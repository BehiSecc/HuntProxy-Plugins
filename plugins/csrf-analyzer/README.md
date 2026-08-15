# CSRFAnalyzer

CSRFAnalyzer starts from a captured state-changing request and checks whether the application still accepts it after CSRF tokens, Origin and Referer checks, methods, content types, or session/token pairings are changed.

It uses repeated baselines and negative controls to separate accepted requests from rejected-token behavior. A normal scan proves reproducible request acceptance; an optional state read-back is what turns that evidence into confirmed server-side change.

## Start With a Working Action

Choose a saved authenticated request that changes application state and succeeds reproducibly. Set `allow_state_change: true`, then describe how the agent should recognize success and rejection when the status code alone is ambiguous.

CSRFAnalyzer recognizes these token names by default: `csrf`, `csrf_token`, `_csrf`, `xsrf`, `_token`, `authenticity_token`, `x-csrf-token`, and `x-xsrf-token`. Add the application's custom name when needed.

Use `fresh_token` when every submission needs a newly acquired token, `per_request_values` when another field must be unique, and `readback` when a separate GET can confirm the final state.

## Example Prompt

```text
Use HuntProxy MCP. Run CSRFAnalyzer on exchange 42 with allow_state_change
enabled. Treat “Profile updated” as success and “Invalid CSRF token” as
failure. Test the normal semantic workflow first, then explain which results
show request acceptance and what state read-back would confirm the change.
```

## What It Checks

| Group | Coverage |
| --- | --- |
| **Token handling** | Token removal and invalid values in query, header, form, and nested JSON fields; duplicate ordering for query, header, and form tokens. |
| **Origin and Referer** | Origin removal, `null`, and cross-site values; Referer removal and cross-site values; and combined Origin/Referer variations. |
| **Methods** | Conversion to GET, moving form fields into the query when possible, plus `X-HTTP-Method-Override: GET`. |
| **Content types** | Missing Content-Type and `text/plain` substitutions where applicable. |
| **Session binding** | The original token under a second identity and explicit cookie/token pairs. |
| **Real browser delivery** | Token-removed top-level GET or cross-site form POST using an isolated Chromium session. |

When a token exists, isolated Origin, Referer, method-override, and content-type results remain diagnostic. Finding-producing combinations also remove the detected tokens and compare them with a rejected invalid-token control.

## How It Confirms a Result

The plugin sends the successful baseline twice and every selected mutation twice. It compares status, normalized body content, and canonicalized redirect destinations.

A candidate must remain reproducibly successful, resemble the accepted baseline, and differ from its linked negative control. `success_markers` and `failure_markers` can inspect response bodies and decoded headers, including `Location`; a structured `success_predicate` can match status, headers, redirects, body text or regular expressions, and JSON fields.

Without a read-back, findings remain tentative because they prove acceptance rather than durable state. With a repeated same-origin GET whose predicate confirms the expected state after each submission, findings become firm and include the read-back exchanges as evidence.

## Fresh Tokens and State Read-Back

`fresh_token` performs a GET, extracts a token with a regular expression, and injects it into the configured query, header, or body field before requests that should retain a valid token. Token-removal and invalid-token tests deliberately do not restore it.

`readback` performs a same-origin GET after every baseline and mutation. Its predicate can check status, headers, redirect location, body content, or JSON, and may use `{counter}` when every submission has a unique value.

## Browser Mode

The separate `browser_scan` action uses a named HuntProxy cookie profile in fresh Chromium. It sends two token-removed top-level GETs or form POSTs from an isolated cross-site document so real browser cookie rules apply.

Browser mode returns an acceptance candidate when both runs complete and a matching managed-profile cookie was delivered. It does not create a finding by itself because cookie delivery does not prove authentication or state change.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `allow_state_change` | Required | Must be `true` before either action plans repeated submissions. |
| `token_names` | Common eight-name set | Add nonstandard query, header, form, or JSON token names. |
| `success_predicate` | Empty | Define a precise accepted response using status, headers, redirects, body, or JSON. |
| `success_markers` / `failure_markers` | Empty | Match simpler accepted and rejected text across bodies and decoded headers. |
| `fresh_token` | Empty | Acquire and inject a fresh one-time token before appropriate replays. |
| `per_request_values` | Empty | Give non-token body, query, or header fields a unique `{counter}` value. |
| `readback` | Empty | Confirm the final state with a same-origin GET and predicate. |
| `secondary_identity` | Empty | Test whether the original token is bound to a second inline cookie/header identity. |
| `paired_cookie_tests` | Empty | Test explicit cookie/session and matching-token pairs. |
| `max_mutations` | `50` | Limit the selected variations from 1 to 80; each is sent twice. |

## Current Limits

- The normal scan sends semantic request mutations; it does not prove that a real cross-site browser can deliver them.
- Multipart token fields are not changed automatically, and duplicate-token ordering is not tested for JSON.
- Browser mode supports captured GET and form-urlencoded POST only; it does not cover JSON, multipart, sibling-domain, client-side redirect, or WebSocket delivery flows.
- Browser mode has no read-back input and reports delivery candidates rather than findings.
- The plugin does not discover a state-check endpoint, infer the desired final state, reset changes, or acquire a login.
