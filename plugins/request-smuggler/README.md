# Request Smuggler

`scan` is a bounded HTTP/1 desynchronization scanner. It measures the normal
target and a harmless marker path, then alternates a clean two-request pipeline
with each ambiguous pipeline. CL.TE, TE.CL, TE.TE permutations, and CL.0 use a
same-connection marker oracle. 0.CL and malformed length probes are diagnostic.

The default five-cycle gate requires at least three marker confirmations and
zero contaminated controls before producing a firm finding. Repeated timeouts
without marker contamination are reported only as tentative parser-discrepancy
candidates. Requests run sequentially and every exchange is tagged with its
operation ID.

Use a unique marker, an idempotent `probe_path`, and `confirm_intrusive=true`.
Authentication is excluded by default; set `include_auth=true` only when the
authorized target requires it. A custom `canary_path` should be harmless and
have a response distinguishable from the probe path.

The current host preserves exact HTTP/1 bytes, duplicate headers, and response
transcripts. It does not yet expose malformed HTTP/2 frames or a read-before-
write same-socket primitive. Accordingly this plugin does not claim H2
downgrade/tunneling, pause-based, or browser-proven client-side desync coverage.
