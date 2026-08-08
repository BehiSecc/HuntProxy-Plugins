# Racer

Racer models limit-overrun, multi-endpoint, object-state, partial-construction,
time-sensitive, and deferred race tests. Each job first runs an equivalent
sequential control, then at least two synchronized attempts. One request shape
is repeated; multiple `exchange_ids` are released together for multi-endpoint
tests. All state-changing execution requires `allow_state_changes=true`.

The required `race_group` host contract is documented in
`RACE_GROUP_CONTRACT.md`. Parallel and HTTP/1 last-byte synchronization are not
called single-packet attacks. `h2_single_packet` must release the final HTTP/2
DATA fragments in one real TCP packet or fail with `protocol_incompatible`.

The plugin is enabled for sequential controls, bounded parallel dispatch, and
real HTTP/1 last-byte synchronization. HuntProxy does not yet implement true
HTTP/2 single-packet release, so that requested technique returns an explicit
`protocol_incompatible` observation and never falls back. Its other techniques
remain usable.
