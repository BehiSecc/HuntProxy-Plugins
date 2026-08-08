# CSRFAnalyzer

CSRFAnalyzer requires `allow_state_change=true` because it repeats the captured
request. It independently tests token removal/mutation/duplication across form,
query, and header locations; Origin and Referer absence/cross-site behavior;
method and content-type controls; and optional cross-session token binding with
a second identity.

Provide `success_markers` and `failure_markers` when HTTP status alone cannot
prove the state change. The analyzer normalizes common volatile response fields
and requires repeated agreement. It does not emulate browser SameSite behavior
or automatically mutate nested JSON/multipart tokens; use a real browser flow
for those cases.

