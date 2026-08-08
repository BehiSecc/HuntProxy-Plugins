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

Setup requests can privately extract a bounded body-regex, header, or JSON
value and bind it into later race and validation URL, `body_text`, or header
values with `{{extract:name}}`. Values are unique per attempt, never returned
in plugin results, and required-extract failures stop the remaining plan.
Extraction from a race response, chaining within one setup group, arbitrary
scripts, and `body_base64` substitution remain unsupported.

Techniques are `sequential`, ordinary `parallel`, exact HTTP/1
`last_byte_sync`, and `h2_single_packet`. The HTTP/2 technique negotiates ALPN
`h2`, opens one stream per request, withholds the final DATA fragment from every
stream, then releases all final fragments in one TLS write. It requires a
shared HTTPS origin; empty-body streams are ended by zero-length DATA frames in
that same release write. An incompatible target returns
`protocol_incompatible`; HuntProxy never falls back to ordinary parallel
dispatch.

See `RACE_GROUP_CONTRACT.md` for the host operation format.
