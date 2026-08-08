# 403Bypasser

`scan` tests bounded path normalization, forwarding-header, method override,
and safe-method variants. Every candidate is sent twice and is reported only
when a 401/403 control becomes a reproducible 2xx response. A 404 can be
included explicitly with `include_not_found=true` and produces lower-severity
results. Replaying an
unsafe base method or adding unsafe method variants requires
`allow_state_changes=true`.
