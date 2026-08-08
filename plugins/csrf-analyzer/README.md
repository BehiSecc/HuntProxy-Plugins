# CSRFAnalyzer

CSRFAnalyzer requires `allow_state_change=true` because it repeats the captured
request. It independently tests token removal/mutation/duplication across form,
query, header, and nested JSON locations; Origin and Referer absence/cross-site behavior;
method and content-type controls; and optional cross-session token binding with
a second identity.

When a token is present, isolated Origin, Referer, content-type, and override
responses are diagnostic only. Findings require a combined token-removal probe
plus a stable rejected invalid-token control, avoiding claims based on requests
that still carry a valid token.

For one-time tokens, provide `fresh_token` with an in-scope acquisition URL,
a body regex whose first capture is the token, and its typed request location.
Each replay becomes a host-owned GET → POST workflow. Extracted values remain
internal and a missing token aborts before the state-changing request.

Provide `success_markers` and `failure_markers` when HTTP status alone cannot
prove the state change. The analyzer normalizes common volatile response fields
and requires repeated agreement. It does not emulate browser SameSite behavior
or automatically mutate multipart tokens; use a real browser flow for those cases.

`paired_cookie_tests` always use the explicit identity and token pair supplied by
the caller; the primary identity's `fresh_token` workflow does not replace it.
