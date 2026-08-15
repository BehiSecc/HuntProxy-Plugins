# AuthAnalyzer

AuthAnalyzer replays selected saved requests for a target using two different identities. It helps reveal authorization differences between users, cross-user access to the same resources, and vertical or horizontal access-control gaps.

It does not decide which user should have access. Instead, it gives the agent repeated response evidence that can be reviewed against the application's intended roles and ownership rules.

## Start With Two Identities and Saved Requests

Choose saved requests that exercise meaningful user or role boundaries. AuthAnalyzer needs one base exchange to start and can include related History exchange IDs in the same run. For a broader review, ask the agent to gather the target's saved requests from History first.

The primary and secondary identities must be different. Each can come from one of these sources:

- inline cookies and headers;
- a named cookie profile stored in the HuntProxy project; or
- a local cookie file on the HuntProxy machine.

You must also provide the exact domains or wildcard subdomains that should be included. `example.com` and `*.example.com` are separate patterns.

## Example Prompt

```text
Find the saved GET requests for api.example.com, then run AuthAnalyzer on them
with cookie profiles user-a and user-b. Show reproduced access differences.
```

## How It Compares Identities

For every selected request, AuthAnalyzer sends two attempts as the primary identity and two as the secondary identity. An optional logged-out control can help show whether the resource requires authentication at all.

Before applying an identity, AuthAnalyzer removes Cookie, Authorization, and Proxy-Authorization from the captured request and suppresses the project cookie jar. This prevents credentials from the saved exchange from leaking into another identity or the anonymous control.

GET, HEAD, and OPTIONS requests are included by default. Other methods are skipped unless `allow_state_changes` is enabled.

## How Results Are Classified

Every identity and request pair is sent twice. By default, a repeated 2xx or 3xx response counts as allowed. Success markers can recognize an allowed outcome at another status, while failure markers can reject login and denial responses.

Missing, mixed, failed, or skipped attempts remain inconclusive; they are never treated as denied. Body instability alone does not change two allowed attempts into an inconclusive outcome. The plugin also separates authorization outcome from body similarity, so a clear 200-versus-403 difference can still be useful when the response content is volatile.

For equality checks, AuthAnalyzer normalizes common CSRF tokens, nonces, timestamps, UUIDs, log IDs, and signed-URL noise before comparing response bodies. Target-specific `ignore_patterns` can remove additional changing values.

Every classification keeps the generated History exchange IDs, including inconclusive and negative results.

For a focused logged-out check, use `anonymous_audit` when you already know how the selected requests behave for a signed-in identity and want to test them as a logged-out user. It requires `confirm_expected_protected: true`.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `primary` / `secondary` | Required | Supply two distinct inline, named-profile, or cookie-file identities. |
| `domains` | Required | Select exact hosts or `*.` subdomain patterns for the comparison. |
| `exchange_ids` | Empty | Add related saved request shapes to the same run. |
| `include_anonymous` | `true` | Add a logged-out comparison and strengthen protected-resource interpretation. |
| `allow_state_changes` | `false` | Include methods other than GET, HEAD, and OPTIONS. |
| `max_requests` | `100` | Limit request shapes from 1 to 500. A normal comparison can send six network requests per shape. |
| `similarity_threshold` | `0.92` | Set how closely normalized response bodies must match. |
| `ignore_patterns` | Empty | Remove target-specific volatile body values before comparison. |
| `success_markers` / `failure_markers` | Empty | Define allowed and denied outcomes using response-body text. |

## Current Limits

- It replays existing request shapes; it does not discover endpoints, enumerate object IDs, log users in, or create identities.
- It cannot infer the intended access policy or which supplied user is lower privileged.
- Body equality does not compare response headers or redirect destinations, and markers cannot match `Location` or other headers.
- Volatile, unavailable, or compacted response bodies can prevent equality findings.
