# Request Smuggler

The `scan` action sends two clean single-request controls, two valid pipeline
controls, and two copies of each selected probe. It covers bounded HTTP/1
CL.TE, TE.CL, TE.TE obfuscation, CL.0, 0.CL, duplicate/signed length parser
discrepancies, keep-alive connection state, client-side readiness, and
pause-before-body/terminal-chunk behavior.

The action requires a unique marker and `confirm_intrusive=true`. Concurrency is
fixed at one to reduce cross-probe interference. Findings require stable
controls plus a repeated probe-only timeout or response-boundary difference.

HuntProxy's current raw transport is HTTP/1 only. This extension does **not**
claim malformed HTTP/2, H2 downgrade, H2 tunneling, or browser-proven
client-side desync support.
