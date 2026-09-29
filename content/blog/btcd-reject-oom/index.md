---
title: a rejection too large for btcd to survive
date: 2026-09-29
description: btcd gave each P2P message type its own size limit, but alert, cfcheckpt, and reject fell back to the global 32 MiB maximum, and the node allocated a buffer of the declared length for each one. Enough peers sending maximum-size messages exhausted RAM and swap until the node was OOM-killed. Here's the oversized-message OOM, and the fix that closed it.
slug: btcd-reject-oom
---

[btcd](https://github.com/btcsuite/btcd), the Go full node from btcsuite, accepted `alert`, `cfcheckpt`, and `reject` messages of up to 32 MiB each and allocated a receive buffer of the full declared length for every one. Any peer that completes the version handshake can send them. With btcd's default of 125 peer slots, enough connections streaming maximum-size messages push the node past its RAM and swap until it is killed for running out of memory.

I found the size gap through differential fuzzing with [bitcoinfuzz](https://github.com/bitcoinfuzz/bitcoinfuzz) and reproduced the crash in a small VM, first with `alert` and later with `reject`.

## Background

Every message in the Bitcoin v1 P2P protocol starts with a 24-byte header: a 4-byte network magic, a 12-byte command, a 4-byte payload length, and a 4-byte checksum. The receiver learns how large the payload claims to be before any of it arrives, so the standard defense is to cap that length before allocating anything.

Bitcoin Core learned this the hard way. Until 2015 it accepted any message up to its 32 MiB serialization bound, and an attacker could force a node to allocate that much per connection. [PR #5843](https://github.com/bitcoin/bitcoin/pull/5843) introduced a separate network limit, `MAX_PROTOCOL_MESSAGE_LENGTH`, at 2 MiB, later raised to 4 MB for segwit. The bug was [publicly disclosed](https://bitcoincore.org/en/2024/07/03/disclose_receive_buffer_oom/) as CVE-2015-3641 in July 2024. Today Core caps protocol messages at 4,000,000 bytes and rust-bitcoin at 5,000,000.

btcd goes further than a single cap. Every message type implements `MaxPayloadLength` from the `wire.Message` interface, so the reader can reject a header whose length exceeds what that type could ever need:

```go
type Message interface {
	BtcDecode(io.Reader, uint32, MessageEncoding) error
	BtcEncode(io.Writer, uint32, MessageEncoding) error
	Command() string
	MaxPayloadLength(uint32) uint32
}
```

A `ping` is capped at 8 bytes and a `block` at 4,000,000. Per-type limits are the defense this bug defeats.

## Three Messages Without a Real Limit

The reader in `wire/message.go` checks the global maximum, then the per-type maximum, and then allocates the whole payload at once:

```go
// Check for maximum length based on the message type as a malicious client
// could otherwise create a well-formed header and set the length to max
// numbers in order to exhaust the machine's memory.
mpl := msg.MaxPayloadLength(pver)
if hdr.length > mpl {
	...
}

// Read payload.
payload := make([]byte, hdr.length)
n, err := io.ReadFull(r, payload)
```

The comment names this exact attack, and the check stops it as long as each type's bound is tight. Three were not. The `alert` message returned the global maximum:

```go
func (msg *MsgAlert) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}
```

So did `cfcheckpt`, the BIP157 compact filter checkpoint message:

```go
func (msg *MsgCFCheckpt) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}
```

And so did `reject`, because its free-form reason string has no protocol limit:

```go
func (msg *MsgReject) MaxPayloadLength(pver uint32) uint32 {
	plen := uint32(0)
	// The reject message did not exist before protocol version
	// RejectVersion.
	if pver >= RejectVersion {
		// Unfortunately the bitcoin protocol does not enforce a sane
		// limit on the length of the reason, so the max payload is the
		// overall maximum message payload.
		plen = MaxMessagePayload
	}

	return plen
}
```

That global maximum was the same 32 MiB Core had used before 2015:

```go
const MaxMessagePayload = (1024 * 1024 * 32) // 32MiB
```

For these three types the per-type check compared the header against the same number as the global check, so neither one stopped a 32 MiB payload. Two of the three were also dead weight: Bitcoin Core [retired the alert system](https://bitcoin.org/en/alert/2016-11-01-alert-retirement) in 2016 and [removed `reject`](https://github.com/bitcoin/bitcoin/pull/15437) in 2019, but btcd still parsed both.

## Exhausting Memory

The loop needs nothing beyond a normal inbound connection:

1. The attacker connects to btcd and completes the `version`/`verack` handshake.
2. It sends a `reject` (or `alert`, or `cfcheckpt`) whose header declares a payload just under 32 MiB, followed by that payload.
3. btcd passes both length checks, allocates a buffer of the declared size, and reads the payload into it.
4. The attacker does the same on every connection it can open, up to btcd's default of 125 peers.

One maximum-size buffer per connection across 125 connections is about 4 GB, which is the full RAM plus swap of the test machine.

## Crashing the Node

On a VM running Ubuntu Server 24 with 2 CPU cores, 2 GB of RAM, and 2 GB of swap, 125 simulated peers completed the handshake and sent 32 MiB `alert` messages. btcd consumed all of the RAM and all of the swap and was killed by the OOM killer. The follow-up test with `reject` messages on the same setup ended the same way.

Nothing is persisted, so a restart brings the node back, but nothing stops the same peers from reconnecting and doing it again. Any reachable btcd node that accepts inbound connections was exposed.

## The Fix

The root cause was one constant doing two jobs: `MaxMessagePayload` was both the serialization bound for internal decoding and the network limit for untrusted peers, and three message types fell back to it.

The fix landed in stages. `alert` was removed outright in [PR #2396](https://github.com/btcsuite/btcd/pull/2396). [PR #2398](https://github.com/btcsuite/btcd/pull/2398) gave `cfcheckpt` a precise bound derived from the most filter headers the decoder will accept:

```go
// Calculation: 1 byte (filter type) + 32 bytes (stop hash) +
// 5 bytes (max varint) + (maxCFHeadersLen * 32 bytes per hash)
maxCFCheckptPayload = 1 + 32 + 5 + (maxCFHeadersLen * 32)
```

With `maxCFHeadersLen = 100000` that is about 3.2 MB. Both changes shipped in btcd `v0.25.0`, but `reject` still accepted 32 MiB there, which prompted the second report.

The general fix, which I upstreamed, first went in as a commit in [PR #2479](https://github.com/btcsuite/btcd/pull/2479) that lowered `MaxMessagePayload` itself to 4 MB. Review pointed out ([issue #2503](https://github.com/btcsuite/btcd/issues/2503)) that the same constant also bounds non-network deserialization, such as transactions read back from the database, so [PR #2504](https://github.com/btcsuite/btcd/pull/2504) split it the way Core had in 2015. `MaxMessagePayload` went back to 32 MiB as the serialization bound, and a new network limit took over on the wire:

```go
// MaxProtocolMessageLength is the maximum length of an incoming/outgoing p2p
// protocol message. This is separate from MaxMessagePayload which is used as a
// general serialization bound. No current valid p2p message exceeds 4MB.
// This mirrors Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH introduced in
// bitcoin/bitcoin#5843.
const MaxProtocolMessageLength = (4 * 1000 * 1000) // ~4MB
```

It is enforced on all four network read and write paths, including the BIP324 v2 read path, which previously had no overall size check. [PR #2518](https://github.com/btcsuite/btcd/pull/2518) then lowered `reject`'s `MaxPayloadLength` to `MaxProtocolMessageLength` so the per-type bound and the network limit agree. With the cap in place, 125 peers can pin at most about 500 MB, the same bound Core accepts. The fix shipped in btcd [`v0.26.0`](https://github.com/btcsuite/btcd/releases/tag/v0.26.0).

## Discovery

I was running differential fuzzing on Bitcoin P2P message parsing with [bitcoinfuzz](https://github.com/bitcoinfuzz/bitcoinfuzz), comparing rust-bitcoin against btcd, when the two disagreed on the maximum message length: rust-bitcoin stops at 5 MB, Bitcoin Core at 4 MB, and btcd accepted about 33 MB (32 MiB). btcd's per-type limits meant the global number alone did not prove anything, so I went through each message's `MaxPayloadLength` and found `alert` and `cfcheckpt` returning the global maximum, then built the 125-peer reproduction in a VM to confirm the crash. After those two were fixed I went back over the same list and found that `reject` did the same thing.

## Lessons Learned

A per-message limit is only as tight as the default it falls back to. btcd sized almost every message precisely, but the types that were hard to size deferred to `MaxMessagePayload`, and that constant was a serialization bound, not a network limit. Core had separated the two after CVE-2015-3641, and it took three implementations disagreeing on one number to show that btcd never had.

## Timeline

- **2025-07-03:** `alert` and `cfcheckpt` reported privately to Lightning Labs.
- **2025-07-11:** `alert` removed in [PR #2396](https://github.com/btcsuite/btcd/pull/2396).
- **2025-07-16:** `cfcheckpt` bounded in [PR #2398](https://github.com/btcsuite/btcd/pull/2398).
- **2025-11-04:** Both released in btcd [`v0.25.0`](https://github.com/btcsuite/btcd/releases/tag/v0.25.0).
- **2026-02-04:** `reject` reported privately to Lightning Labs.
- **2026-03-10:** `MaxMessagePayload` lowered to 4 MB in [PR #2479](https://github.com/btcsuite/btcd/pull/2479).
- **2026-04-08:** `MaxProtocolMessageLength` introduced in [PR #2504](https://github.com/btcsuite/btcd/pull/2504) and applied to `reject` in [PR #2518](https://github.com/btcsuite/btcd/pull/2518).
- **2026-06-18:** Released in btcd [`v0.26.0`](https://github.com/btcsuite/btcd/releases/tag/v0.26.0).
- **2026-09-29:** Public disclosure.

*Acknowledgments: Thanks to [Bruno Garcia](https://github.com/brunoerg) for helping me along the way.*
