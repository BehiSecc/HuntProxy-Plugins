# 403Bypasser

`scan` tests bounded path normalization, forwarding-header, method override,
and safe-method variants. Every candidate is sent twice and is reported only
when a 401/403 control becomes a reproducible 2xx response. A 404 can be
included explicitly with `include_not_found=true` and produces lower-severity
results. Replaying an
unsafe base method or adding unsafe method variants requires
`allow_state_changes=true`.

Forwarding headers sent through `/` are compared with two header-free benign
carrier controls, preventing an ordinary public home page from being mistaken
for the protected resource. Path-only 2xx results remain tentative unless a
caller-supplied `success_markers` value proves protected content was reached;
`failure_markers` can exclude login and denial templates.
