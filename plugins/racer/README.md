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
bounded. The literal `{attempt}` is replaced in URL values, `body_text`, and
header values for race, setup, and validation requests. This supports unique
usernames, emails, idempotency keys, and similar per-attempt state without raw
byte-offset scripting. It is deliberately rejected in `body_base64`.

CSRF or state tokens that must be freshly extracted between attempts remain an
explicit limitation. HuntProxy's semantic HTTP workflow can prepare such state
before a Racer job, but its extracted values are currently private to that
workflow and cannot be passed into a later race group. Prepare those tokens
separately or use a target/session where one scoped token remains valid.

Techniques are `sequential`, ordinary `parallel`, exact HTTP/1
`last_byte_sync`, and `h2_single_packet`. The HTTP/2 technique negotiates ALPN
`h2`, opens one stream per request, withholds the final DATA fragment from every
stream, then releases all final fragments in one TLS write. It requires a
shared HTTPS origin; empty-body streams are ended by zero-length DATA frames in
that same release write. An incompatible target returns
`protocol_incompatible`; HuntProxy never falls back to ordinary parallel
dispatch.

See `RACE_GROUP_CONTRACT.md` for the host operation format.
