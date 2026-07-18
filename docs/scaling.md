# Scaling notes

Both known bottlenecks are consequences of single-writer Durable Objects owning shared state.
One is now mitigated in code (audit chain sharding); the other is documented here for when
measurement shows it is needed.

## Audit chain: sharded by (org, UTC day) — implemented

`AuditChainDO` is one DO per (org, period); the active segment is `org:YYYY-MM-DD` and the
pre-sharding DO (addressed by org alone) is served in place as the read-only "legacy" segment.
Chain continuity across segments is anchored in the predecessor: a segment's first append seals
its predecessor (atomic in the predecessor's single writer — every later append there is
rejected) and only then chains from the returned head. Sequence numbers stay globally monotonic,
the entry-hash format is unchanged, and `services/audit.ts` routes appends (clock-derived name,
no directory read on the hot path) and fans reads/proofs/checkpoints/verification out across
segments via the per-org `AuditDirectoryDO`.

This bounds a single DO's write load to one org-day. If one org-day is still too hot, the same
seal-and-chain protocol supports finer periods (hour) without format changes — the period string
is opaque to the protocol.

## Budget hot nodes: sub-counter sharding — designed, not built

The `reserved` running-total counter (see `BudgetDO`) removed the O(in-flight reservations) list
scan from every reserve/getState. What remains is fundamental: one DO serialises all
reservations under a hot node.

When a single node's request rate becomes the limit:

1. Split the node into N sub-counters `{ref}#0..N-1`, each owning a fixed share of the limit
   (`limit/N` initially).
2. Route each reservation to `hash(tid) mod N`; on `insufficient_budget`, optionally probe one
   sibling shard before failing.
3. Rebalance by cron: a shard's share may be lowered no further than its current
   `spent + reserved`, and the freed headroom granted to a starved shard — so the sum of shares
   never exceeds the node's limit at any instant, preserving the hard cap.
4. `getState` aggregates shards; the reconciliation cron sums shards against the audit-derived
   total exactly as today.

The cost is exactness at the margin — a request can be refused while another shard still has
headroom (bounded by the rebalance interval). That is the accepted trade for N× throughput, and
why this is opt-in per measured hot node rather than the default topology.
