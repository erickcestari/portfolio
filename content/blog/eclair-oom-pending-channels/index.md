---
title: crashing an eclair node with unfunded channels
date: 2026-09-30
description: eclair opened a channel for any peer as fundee, derived its id from a funding transaction the peer named but never had to broadcast, and wrote it to disk. Two id-tracking bugs let one connection bury an unbounded number of these never-funded channels past the rate limiter until the node ran out of memory, then crash-looped on every restart. Here's the free-channel flood, and the fix that closed it.
slug: eclair-oom-pending-channels
---

As fundee, [eclair](https://github.com/ACINQ/eclair) opens a channel for any peer, derives the channel id from a funding transaction the peer only names but never has to broadcast, and persists it. Two id-tracking bugs let one connection bury an unbounded number of these never-funded channels past the rate limiter until the node runs out of memory. Because every channel is written to the database, restarting reloads the fake channels and crashes again, so the node is stuck in a crash loop until someone raises the heap or clears the rows by hand.

The attacker spends nothing on-chain: no UTXO, no broadcast, no confirmation, just protocol messages and cheap signatures. I found it with an AI harness I built for vulnerability hunting, then confirmed the impact with a proof of concept against eclair v0.14.0 (commit `ec8c63b`) on regtest.

## Background

Opening a single-funded channel is a short exchange defined in [BOLT 2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md). The opener sends `open_channel`, the fundee replies `accept_channel`, the opener sends `funding_created` carrying the funding transaction id and output index plus a signature for the fundee's first commitment, and the fundee replies `funding_signed`. From that point both sides know the channel and wait for the funding transaction to confirm on-chain.

The channel's permanent id is the funding outpoint itself. Before `funding_created` arrives the fundee only has a random `temporary_channel_id`; afterwards the channel is re-keyed under the real id derived from the outpoint the opener supplied.

Opening a channel is cheap for the fundee and it is the opener who pays for the funding transaction, so a fundee can be asked to hold many half-open channels for peers who never follow through. eclair defends against that with a `PendingChannelsRateLimiter`: it counts pending (not-yet-confirmed) channels per peer and in total, and rejects new opens once a peer passes `maxPendingChannelsPerPeer` (3) or the network passes `maxTotalPendingChannelsPrivateNodes` (99). That limiter is the whole defense against a peer flooding the node with pending channels. The bug is that it can be walked straight past.

## A Channel That Costs the Opener Nothing

As fundee, eclair takes the channel id verbatim from the outpoint in `funding_created`:

```scala
val channelId = toLongId(fundingTxId, fundingOutputIndex)
```

Nothing checks that `fundingTxId` refers to a transaction that exists. On `funding_created` the fundee's only validation is the commitment signature, and the attacker holds the channel keys on its own side, so producing a valid signature is free. Having accepted it, the fundee persists the channel with `storing()`, sets a watch on the funding output, and sends `funding_signed`. The channel is now a live `WAIT_FOR_FUNDING_CONFIRMED` actor on disk.

Since the funding transaction never confirms, eclair keeps that channel until `FUNDING_TIMEOUT_FUNDEE = 2016` blocks, about two weeks. So one message exchange with no on-chain cost buys the attacker a fully persisted pending channel that the victim will hold for two weeks.

The one guard that could stop a second channel from the same peer, `checkNoExistingChannel`, does not fire here: for a plain single-funded open with no `requestFunding` TLV and no open-channel plugin, the default path spawns the channel directly.

## Slipping Past the Rate Limiter

If every open counted, the limiter would stop the third channel. It does not, because two pieces of id tracking disagree about identity once a channel is assigned its final id.

The first is the `Peer` duplicate guard. It only looks in the `TemporaryChannelId` keyspace:

```scala
d.channels.get(TemporaryChannelId(open.temporaryChannelId))
```

But once a channel gets its final id it is re-keyed under `FinalChannelId(C)`, a different map key, and the temporary id is dropped. So a new `open_channel` whose `temporary_channel_id` happens to equal a previous channel's *final* id finds nothing in the temporary keyspace and is accepted.

The second is the limiter's bookkeeping. It stores a flat `Seq` of ids and lets `filterNot` collapse duplicates. Adds are un-deduplicated:

```scala
temporaryChannelId +: peerChannels
```

and when a channel is assigned its final id, `replaceChannel` rewrites the list:

```scala
channels.filterNot(_ == temporaryChannelId) :+ channelId
```

If the tracked list is `[C, C]`, `filterNot(_ == C)` removes *both* entries and then appends one, so the count drops from 2 back to 1 while both channels are still alive.

## Burying Channels

Chain the ids so each new open reuses the previous channel's final id. On a single connection:

1. Send `open_channel` with a fresh `temporary_channel_id` T1. The limiter tracks `[T1]`.
2. Receive `accept_channel`; send `funding_created` with any `funding_txid` (never broadcast) and a valid commitment signature. The fundee assigns `C1 = toLongId(...)`, persists the channel, and replies `funding_signed`. The limiter collapses to `[C1]`, count 1.
3. Send a new `open_channel` with `temporary_channel_id = C1`, the previous *final* id. The `Peer` guard misses it (C1 lives under `FinalChannelId`, not `TemporaryChannelId`), so it is accepted. The limiter tracks `[C1, C1]`, count 2.
4. Drive channel 2 to `funding_created`. On the assignment `C1 -> C2`, `replaceChannel`'s `filterNot(_ == C1)` deletes both `C1` entries and appends `C2`, leaving `[C2]`, count 1. Channels 1 and 2 are both alive.

Repeat with `temporary_channel_id` set to the last channel's final id each round. Every iteration buries one more live pending channel while the limiter's counter just oscillates between 1 and 2, never reaching 3 or 99.

The attacker still pays nothing on-chain. Each buried channel costs the victim a live `Channel` actor, a persisted database row, and an on-chain funding watch, held for about 2016 blocks.

## Amplification

Each buried channel is small on its own, around 875 bytes, but the attacker controls its size. eclair persists the peer's raw init features in every channel:

```scala
RemoteChannelParams.initFeatures = remoteInit.features
```

serialized as the raw feature bitvector (`featuresCodec`). eclair accepts unknown *odd* (optional) feature bits without disconnecting, since "we only need to check even feature bits (it's ok to be odd)". Setting a single high odd bit inflates the stored feature vector to roughly 65 KB, bounded only by the 65535-byte message limit.

So each buried channel grows from about 875 bytes to about 65 KB, and every channel stores its own copy. That turns the slow crawl toward OOM into a fast one, and makes the reload after a restart far heavier.

## Crashing the Node

eclair runs on Akka, and `akka.jvm-exit-on-fatal-error` turns an `OutOfMemoryError` into a JVM shutdown. Enough buried channels and the node dies.

The damage is durable. On boot eclair reloads and respawns every persisted channel (`spawnChannel` + `INPUT_RESTORED`), re-registering each funding watch and timer. With the heap already too small for the fake channels, it OOMs again during startup: a crash loop. The node cannot recover on its own; someone has to raise the heap or purge the fake channels from the database.

eclair sets no `-Xmx`, so it uses the JVM default heap of about 25% of available RAM and is container and host aware. On a node with 16 GB RAM, so about a 4 GB heap, it took about 47m43s to crash, with 217,623 rows in `local_channels`.

```
Uncaught error from thread [eclair-node-scheduler-1]: Java heap space, Uncaught error from thread [eclair-node-akka.io.pinned-dispatcher-12]:
Java heap space, shutting down JVM since 'akka.jvm-exit-on-fatal-error' is enabled forshutting down JVM since 'akka.jvm-exit-on-fatal-error'
is enabled for ActorSystem[eclair-node]
```

The attack needs no channel, no funds, and no prior relationship with the victim, so every reachable eclair node is in scope.

## The Fix

The root cause is that identity tracking collapses two distinct live channels that happen to share an id, so a channel can exist without ever counting toward the limit. The fix, [PR #3324](https://github.com/ACINQ/eclair/pull/3324), closes both bugs: the `Peer` duplicate guard now rejects an incoming `temporary_channel_id` that already exists under either keyspace, temporary or final, so a new open can no longer reuse a live channel's final id; and the rate limiter tracks channels by a stable identity, so `replaceChannel` and `removeChannel` can no longer delete two distinct live channels when they share an id. With both in place the counter reflects the real number of pending channels again, and the flood hits the limit as intended. It shipped in eclair [`v0.14.1`](https://github.com/ACINQ/eclair/releases/tag/v0.14.1).

The same PR also closed a separate bug in the same fundee flow: a race between the duplicate check and the channel insertion that could orphan channel actors and leak memory, found by Matt Morehouse with `smite`, and disclosed as LNF-2026-0003.

## Discovery

The harness clones the repository, runs a reconnaissance agent that maps the entry points and the invariants each is meant to hold, then turns hunter agents loose to break them, using the BOLTs as the spec reference. It surfaced the channel-id collision; my part was to confirm the finding was real and build the proof of concept that drove it to OOM. It is not push-button yet: "find vulnerabilities in eclair" on its own still returns noise, and the real work is the recon and spec-diff scaffolding around the hunt.

For a similar multi-agent approach, see Cloudflare's [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/).

## Lessons Learned

A rate limit is only as good as its notion of identity. eclair had the counter and the counter worked, but "the same channel" meant one thing in the temporary keyspace, another after id assignment, and a third inside the limiter's flat list. Where those disagree, a channel can be alive and uncounted at the same time. The cheapest half of the attack was the design decision underneath it: deriving a persisted, watched, two-week channel id from a transaction the peer never has to prove exists.

## Timeline

- **2026-07-04:** Vulnerability reported privately to ACINQ.
- **2026-07-07:** Reproduced and confirmed by ACINQ.
- **2026-07-17:** Fix merged as [PR #3324](https://github.com/ACINQ/eclair/pull/3324), released in eclair [`v0.14.1`](https://github.com/ACINQ/eclair/releases/tag/v0.14.1).
- **2026-09-30:** Public disclosure.
