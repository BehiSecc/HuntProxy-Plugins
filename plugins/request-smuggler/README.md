# Request Smuggler

`scan` is a bounded HTTP/1 desynchronization scanner. It measures the normal
target and a harmless marker path, then alternates an independent clean control,
an ambiguous pipeline, a victim request, and a recovery request. This catches
both same-client-socket effects and contamination that emerges through a pooled
backend connection after the front end closes the original client connection.
CL.TE, TE.CL, TE.TE permutations, and CL.0 use a marker oracle. CL.0 leaves
the smuggled header block incomplete so the next request completes it, matching
real single-connection behavior. The 0.CL family pairs an early-response
request containing `Content-Length : 1` and no body with an independent `XGET`
victim; a normal victim response that is impossible without the hidden length
interpretation confirms the discrepancy.

`connection_state` compares a Host-bearing request directly and as the second
request on one established connection. Set `connection_state_host` and
`connection_state_path` to the authorized values you need to test. The default
uses a unique subdomain of the target and the probe path.

The default five-cycle gate requires at least three marker confirmations and
zero contaminated controls before producing a firm finding. Repeated timeouts
without marker contamination are reported only as tentative parser-discrepancy
candidates. Requests run sequentially and every exchange is tagged with its
operation ID.

Use a unique marker, an idempotent `probe_path`, and `confirm_intrusive=true`.
Authentication is excluded by default; set `include_auth=true` only when the
authorized target requires it. A custom `canary_path` should be harmless and
have a response distinguishable from the probe path.

The HTTP/2 families use HuntProxy's ordered raw HPACK fields without semantic
normalization. They cover H2.CL, H2.TE, CRLF header-value injection, CRLF
request splitting, header-name tunnelling, and pseudo-path tunnelling. The host
requires HTTPS with ALPN `h2`, preserves duplicate and malformed field order,
and never falls back to HTTP/1. H2 probes use the same independent
control/probe/victim/recovery oracle as HTTP/1. Tunnelling is only firm when a
nested HTTP/1 response is repeatedly visible in the HTTP/2 response body.

The default scan is intentionally thorough: five cycles across every framing
variant can schedule up to 508 requests. Use `families`, `max_techniques`, and
`repeats` to reduce volume on fragile targets. Browser-proven client-side
desync remains out of scope. Pause-based coverage requires the separate
read-before-continuation workflow and is not claimed by these probes.
