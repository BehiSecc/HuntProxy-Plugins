# UploadAnalyzer

UploadAnalyzer mutates the first file part of a captured multipart request after
`allow_uploads=true`. All generated content is inert. It establishes an allowed
control and a direct prohibited-extension control, then tests mixed case,
trailing dot/space, double extensions, semicolons, encoded/double-encoded dots,
encoded null/slash forms, Windows ADS, and declared-MIME/content mismatches.

Filename bypasses are reported only when the allowed control succeeds, the
direct prohibited control fails, and a variant reproducibly behaves like the
allowed upload. Controls preserve the captured part's MIME type; declared-image
tests reuse a captured image MIME when possible. Add success/failure markers
for endpoints that return 200 on both acceptance and rejection.

The plugin does not upload executable content, retrieve uploaded paths, or
claim code execution. Public retrieval, storage renaming, asynchronous scanning,
and execution require a separate explicitly authorized validation step.

