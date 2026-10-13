# Experimental opt-in connection pool

This draft adds `client.NewReconnectableClientPool(configFunc, connectedFunc, lazy, size)` to the Go core API. Existing constructors and the standard CLI configuration are unchanged. The CLI configuration/API shape and the congestion-control policy still need maintainer agreement in [#1431](https://github.com/HyNetworks/hysteria/issues/1431).

- Size 1 delegates to the existing reconnectable client. Sizes 2 through 8 create independent reconnectable QUIC connections; the upper bound is a resource guard, not a recommendation.
- New TCP streams and Hysteria UDP sessions are assigned round-robin. Existing streams/sessions remain on their selected connection. A failed open is returned to the caller; there is no transparent replay, migration, packet striping or single-stream speedup.
- Lazy mode opens each connection on its first selected flow. Eager initialization fails as a whole and closes already initialized members if a later member cannot initialize.
- Config evaluation and success callbacks are serialized within the pool. The success callback receives the connected member and a pool-wide count of successful handshakes, including initial connections and reconnects. A custom connection factory must provide independent packet connections and support concurrent members.
- Nonzero client bandwidth targets are split statically and evenly. Remainders are assigned in bytes/s so the member targets sum to the configured target. Zero targets remain zero. Idle members' allocations are not redistributed. This does not implement a shared limiter or guarantee the aggregate wire rate; loss compensation and server-side per-connection limits still apply.
- `Close` closes all members, aggregates errors, waits for concurrent closes and is idempotent. Established flow ownership remains with each underlying reconnectable client.

## Scope and unresolved questions

No GRO, receive recycling, diagnostic packet logging, quic-go dependency changes, OpenWrt configuration or CPU-overclock code is included. The public pool API is provisional, and the bound of eight members is a conservative implementation choice for review. Only two/three members have prior router throughput measurements; eight is covered by unit-level distribution tests, not router performance validation.

The inherited reconnectable client's terminal-error transport cleanup issue remains under review in [#1696](https://github.com/HyNetworks/hysteria/pull/1696). This draft does not bundle that unrelated fix or claim complete reconnect/leak validation. The pool must not be promoted to a finished production feature until that lifecycle issue and pool reconnect regressions have been addressed.

The paired prototype results in [#1431](https://github.com/HyNetworks/hysteria/issues/1431#issuecomment-6146553555) showed approximately 35% higher aggregate download throughput at the same fixed CPU clock and aggregate bandwidth targets. Both benchmark sides included additional custom receive-path changes; those are motivation for this draft, **not benchmarks of this clean pool-only branch**. Throughput, memory and latency should be measured again against unmodified upstream quic-go before proposing a default or recommending production deployment.
