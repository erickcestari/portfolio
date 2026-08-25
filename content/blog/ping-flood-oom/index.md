---
title: crashing a lightning node with a flood of pings
date: 2026-08-25
description: Core Lightning answered every ping and gossip query even when the peer refused to read the replies. One connection could grow the outgoing queue until the node ran out of memory. Here's the OOM, and the backpressure fix that closed it.
slug: ping-flood-oom
---

## Background

Every Lightning node speaks an encrypted peer-to-peer protocol defined in BOLT 8: messages are framed and encrypted with the Noise protocol, and each frame is at most 65,535 bytes. In Core Lightning (CLN) this transport lives in a dedicated daemon, `connectd`, which multiplexes one TCP connection per peer and shuffles messages between the peer and the per-channel subdaemons.

Some peer messages never reach a subdaemon at all. `connectd` answers them locally, right on the connection:

- **`ping`** (BOLT 1). A `ping` carries a `num_pong_bytes` field. The receiver must reply with a `pong` message padded to exactly that many bytes, up to a maximum of 65,531. It is a liveness probe, and the reply is generated entirely by the receiver.
- **`query_channel_range`** (BOLT 7). A gossip query asking "give me the channels in this block range." The receiver builds and streams back a reply covering `first_blocknum` through `first_blocknum + number_of_blocks`.

Both are handled inside `connectd`, and in both the *sender* picks how large the *reply* is. `query_channel_range` is the worst of them: one small request can name a block range covering the entire chain.

## The Unbounded Output Queue

`connectd` is not supposed to read as fast as a peer can send. The read loop reads **one** message and then parks itself on a wake token, `&peer->peer_in`, instead of immediately reading the next one.

```c
/* Wait for them to wake us */
peer->peer_in_lastmsg = type;
peer->peer_in_lasttime = time_mono();

return io_wait(peer_conn, &peer->peer_in, next_read, peer);
```

It stays asleep until something wakes that token. In the vulnerable code that wake came from the subdaemon side: once `write_to_subd` had drained a subdaemon's queue, it woke the read loop again.

```c
/* Nothing to send? */
if (!msg) {
        ...
        /* Tell them to read again. */
        io_wake(&subd->peer->peer_in);
        ...
}
```

This is textbook backpressure. If a peer stops reading its socket, `connectd`'s writes block, the encrypted queue never empties, `&peer->peer_in` is never woken, and the read side stalls. The node reads no faster than it can send, and memory stays bounded.

The problem was that locally-handled messages skipped the gate entirely. After answering a `ping` or a gossip query, the read loop took a shortcut:

```c
/* If we swallow this, just try again. */
if (handle_message_locally(peer, decrypted))
        return next_read(peer_conn, peer);   /* read the NEXT message immediately */
```

`next_read` reads again right away. It never touches `&peer->peer_in`, so nothing at all limits how fast a peer can make `connectd` generate replies.

The messages where the peer sizes that reply all sit behind this shortcut:

```c
/* We handle pings and gossip messages. */
static bool handle_message_locally(struct peer *peer, const u8 *msg)
{
        ...
        } else if (type == WIRE_PING) {
                handle_ping_in(peer, msg);
                return true;
        ...
        } else if (type == WIRE_QUERY_CHANNEL_RANGE) {
                handle_query_channel_range(peer, msg);
                return true;
        } else if (type == WIRE_QUERY_SHORT_CHANNEL_IDS) {
                handle_query_short_channel_ids(peer, msg);
                return true;
        ...
}
```

And each `ping` produces a reply that the sender sizes, allocated and enqueued on the outgoing queue:

```c
if (num_pong_bytes < 65532) {
        ignored = tal_arrz(ctx, u8, num_pong_bytes);   /* up to 65,531 bytes */
        *pong = towire_pong(ctx, ignored);
        ...
}
```

Put together, the loop against a non-reading peer becomes:

1. Read a `ping` asking for a 65,531-byte `pong`.
2. Build the `pong`, enqueue it on `peer_outq`.
3. `return next_read(...)` — immediately read the next `ping`. **No wait on the write side.**
4. The peer never reads, so the write side never drains `peer_outq`. But the read loop never checks; it keeps looping as fast as it can decrypt.

The outgoing queue grows without bound. `query_channel_range` with `number_of_blocks` set to `U32::MAX` does the same thing and worse, piling a whole chain's worth of gossip replies onto the same queue from one small request.

## Crashing the Node

The exploit needs no funded channel and no valid gossip. It only needs to complete the Noise handshake and then refuse to read:

1. The attacker `M` completes the BOLT 8 handshake with the victim `V`. No channel required.
2. `M` sends a flood of `ping` messages, each with `num_pong_bytes = 65531` (or a flood of `query_channel_range` with `number_of_blocks = U32::MAX`).
3. `M` **never reads** from the socket.
4. `V`'s `connectd` answers every message, appending a large `pong` (or gossip reply) to the per-peer outgoing queue, and immediately reads the next request because local handling skips the read gate.
5. The queue grows until `connectd` exhausts RAM and swap, and the node is killed by the OOM killer.

In testing on a 2-core VM with 2 GB RAM and 2 GB swap, a single connection was enough to take the node down; a hundred simulated peers did it faster. The victim needs no open channel with the attacker, so the attack surface is every reachable node on the network.

## The Fix

The fix has two parts. The first routes locally handled messages back through the gate: instead of reading the next message immediately, `connectd` nudges the write side and then parks on `&peer->peer_in`, exactly like a subdaemon-bound message.

```c
/* If we swallow this, just try again. */
if (handle_message_locally(peer, decrypted)) {
        /* Make sure to update peer->peer_in_lastmsg so we blame correct msg! */
        io_wake(peer->peer_outq);
        goto out;
}
...
/* Wait for them to wake us */
peer->peer_in_lastmsg = type;
out:
peer->peer_in_lasttime = time_mono();

return io_wait(peer_conn, &peer->peer_in, next_read, peer);
```

That alone would deadlock the connection. The only thing that ever woke `&peer->peer_in` was `write_to_subd`, and a locally handled message never reaches a subdaemon, so the read loop would park and never be woken again. The second part gives the gate a socket-side waker:

```c
if (!msg) {
        /* Tell them to read again, */
        io_wake(&peer->subds);
        io_wake(&peer->peer_in);

        /* Wait for them to wake us */
        return msg_queue_wait(peer_conn, peer->peer_outq, write_to_peer, peer);
}
```

Now the read loop sleeps after queuing a reply and does not read again until the writer has drained `peer_outq` and woken it. Against a peer that never reads, the writer never drains, so reading stalls after a single queued reply. `peer_outq` can no longer grow past roughly one message, and the flood can no longer drive the node to OOM.

It landed as [PR #8525](https://github.com/ElementsProject/lightning/pull/8525).


## Discovery

I was learning BOLT 8 by implementing it, writing my own library for the Noise handshake and transport. Once it could talk to a real node, the obvious next step was to point it at one and see how the P2P layer held up under traffic no well-behaved peer would ever send. Running a CLN node in regtest on a small VM, I scripted 100 peers that completed the handshake and then spammed `ping` messages with `num_pong_bytes = 65531` while deliberately reading nothing back. The node consumed all RAM and swap and was OOM-killed. The same crash reproduced with `query_channel_range` set to the maximum block range, and even with a single peer, which pointed at the real cause: the outgoing per-peer queue was never being bounded when the peer refused to drain it.

## Lessons Learned

The interesting part is that CLN already had backpressure. The bug was that the locally handled messages bypassed it. The shortcut looked harmless because no subdaemon was involved and there was nothing to route anywhere, but it also meant the read side wasn't waiting for the write side anymore.

After finding this, I went through the other messages `handle_message_locally` answers and looked for the same pattern: can the peer make us generate a large response, and do we wait for that response to leave the socket before reading again? `ping` and `query_channel_range` were the two where the sender picks the size, and both took the shortcut.

The other assumption that broke is about the peer. The write path assumes the peer eventually drains its socket. A peer that finishes the handshake and then stops reading never does, so every reply we generate stays on our queue. No channel, no funds, no valid gossip: finishing a Noise handshake is enough.

It also matters how this was found. I was writing my own BOLT 8 implementation to learn the protocol, not to hunt for bugs, but what came out of it was a client with no interest in behaving well: it could put any value the wire format allows in a field and then decline to read the replies. Testing with an existing implementation would not have gotten there, since both sides would already agree on what a reasonable peer does.

## Timeline

- **2025-08-25:** Vulnerability reported privately to Rusty Russell.
- **2025-09-02:** Fix merged as [PR #8525](https://github.com/ElementsProject/lightning/pull/8525) and released as the last change in Core Lightning `v25.09`.
- **2026-08-25:** Public disclosure.
