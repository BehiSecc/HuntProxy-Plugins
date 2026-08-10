# Request Smuggler

`scan` is a bounded HTTP/1 desynchronization scanner. It measures the normal
target and a harmless marker path, establishes every selected technique's clean
controls before sending any ambiguous request, then uses dedicated post-probe
observers. This catches
both same-client-socket effects and contamination that emerges through a pooled
backend connection after the front end closes the original client connection.
CL.TE, TE.CL, TE.TE permutations, and CL.0 use a marker oracle. CL.0 leaves
the smuggled header block incomplete so the next request completes it, matching
real single-connection behavior. The 0.CL family dispatches an early-response
request with no body and an independent valid chopped-prefix/revealed-canary
request over two separate connections behind one start barrier. The same
second request is sent alone as a control and resolves to the normal path; a
canary response only in the grouped case confirms that the hidden length
consumed its prefix. A bounded `zero_cl_offsets` sweep accounts for headers
inserted during front-end rewriting. It also covers whitespace/tab,
folded-name/value, hop-by-hop, duplicate, underscore, and bare LF/CR
header-hiding variants. The second connection pauses after its first byte for
the bounded `zero_cl_delay_ms` interval, giving the early-response request a
deterministic lead without serializing the pair. Each retains repeated quorum
and bounded post-pair observers. All standalone controls run before any pair,
so a delayed queued response cannot corrupt the baseline. `zero_cl_observers`
controls how many later requests sample each pair. Repeated non-canary
divergence is retained in structured diagnostics; only exact reproducible
canary revelation becomes a finding. Targeted pool-dependent confirmation can use up to nine
repeats; broad scans remain bounded by the package request limit.

`connection_state` compares a Host-bearing request directly and as the second
request on one established connection. Set `connection_state_host` and
`connection_state_path` to the authorized values you need to test. The default
uses a unique subdomain of the target and the probe path.

The default five-cycle gate requires at least three exact marker confirmations
and every front-loaded control to remain clean before producing a firm finding.
Timeouts, protocol rejection, and response divergence without marker
contamination remain diagnostics rather than findings. Requests run
sequentially and every exchange is tagged with its
operation ID.

Use a unique marker, an idempotent `probe_path`, and `confirm_intrusive=true`.
Authentication is excluded by default; set `include_auth=true` only when the
authorized target requires it. A custom `canary_path` should be harmless and
have a response distinguishable from the probe path.

The HTTP/2 families use HuntProxy's ordered raw HPACK fields without semantic
normalization. They cover H2.CL, H2.TE, CRLF header-value injection, CRLF
request splitting, header-name tunnelling, and pseudo-path tunnelling. The host
requires HTTPS with ALPN `h2`, preserves duplicate and malformed field order,
and never falls back to HTTP/1. H2 probes use the same front-loaded control and
dedicated post-probe observer oracle as HTTP/1. Tunnelling is only firm when a
nested HTTP/1 response is repeatedly visible in the HTTP/2 response body.
`tunnel_path` selects the harmless inner response and `tunnel_outer_path`
selects a shorter outer response (default `/login`). A separate header-name
Host-injection probe remains diagnostic-only unless a future workflow supplies
a direct, authorized routing oracle; a changed response alone does not prove
that the injected Host reached an HTTP/1 origin. Nested-response confirmation
requires a complete Content-Length-framed inner response whose body matches the
direct canary response.

Response comparison is semantic: status, normalized response body, and relevant
routing headers are compared while volatile CDN trace headers are ignored.
Canary confirmation requires the exact normalized canary body or a non-empty
Location oracle; matching only the canary status code is insufficient. HTTP/2
reset, GOAWAY, incomplete, and truncated streams are classified as rejection or
inconclusive evidence and never as downstream responses.

The default scan is intentionally thorough: five cycles across every selected
framing variant can schedule hundreds of requests. Use `families`,
`max_techniques`, and
`repeats` to reduce volume on fragile targets. Browser-proven client-side
desync remains out of scope. Pause-based coverage requires the separate
opt-in `pause` family because its default three-or-more 61-second cycles are
slow. It sends the same CL.0 carrier twice on one connection and splits the
wire write immediately after the first header block. `pause_await_response`
uses response-gated continuation for servers where that is the relevant
primitive; the default fixed pause matches vectors that require the entire
delay even if an early response is already available.
