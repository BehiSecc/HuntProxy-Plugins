# AuthAnalyzer

Use `scan` only with two non-empty, distinct identity sets. It compares those
identities and can optionally add an anonymous control.

An identity can use inline `cookie`/`headers`, a project-scoped named cookie
identity such as `{"profile":"sco"}`, or `{"cookie_file":"/private/sco.json"}`.
Create a named identity with the HuntProxy `cookies` tool by supplying
`profile_name`; named identities are not applied to ordinary project traffic.
Profile and file cookie values are resolved by the host and never enter plugin
output.

Use `anonymous_audit` when a saved request is already known to represent a
protected resource. It requires `confirm_expected_protected=true` and sends
only anonymous requests, so its labels never imply identities that were not
actually supplied. If the target issues a guest-session or affinity cookie,
pass it as `anonymous_context`; base credentials are still removed.

For applications that report a protected handler outcome with a non-2xx
status, provide `success_markers` and optional `failure_markers`. Markers must
match across both repeats before that response is treated as allowed.

Authorization outcome and body stability are reported separately. Two
allowed-status repeats are classified as `allowed` even when volatile response
fields prevent a stable body match; mixed, failed, or missing repeats are
`inconclusive`, not denied. Every classification includes the generated probe
exchange IDs, including unstable controls and non-findings.
