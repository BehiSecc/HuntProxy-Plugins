# Racer

Racer runs bounded same-request and multi-endpoint tests for limit overruns,
object-state collisions, partial construction, time-sensitive flows, and
deferred processing. Every state-changing job requires
`allow_state_changes=true`.

Requests can inherit a saved exchange or be supplied as an unsent inline
template. Each shape has its own copy count and optional semantic success
predicate. Predicates can match status codes, headers, body text or regexes,
JSON pointers, and redirect locations. Prefer them over `success_statuses`:
many applications return HTTP 200 for both accepted and rejected operations.

For one-shot transitions, use `control_mode: "none"`. `single_each` runs one
copy of each distinct shape as a low-impact benchmark, while `full_group`
preserves the older full sequential comparison. Optional `setup_requests` run
before the control and every attempt; `validation_requests` run afterward and
must all match for an attempt to qualify. These requests are intentionally
static and bounded; workflows requiring tokens extracted dynamically between
steps should prepare the state separately.

Techniques are `sequential`, ordinary `parallel`, and exact HTTP/1
`last_byte_sync`. Parallel and last-byte synchronization are not described as
single-packet attacks. HuntProxy does not currently implement true HTTP/2
single-packet release, so `h2_single_packet` returns an explicit
`protocol_incompatible` observation and never falls back.

See `RACE_GROUP_CONTRACT.md` for the host operation format.
