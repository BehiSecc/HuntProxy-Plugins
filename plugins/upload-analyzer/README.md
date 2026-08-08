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

All ordinary controls use inert marker text. Consequently, a structurally valid
image-only endpoint may reject the allowed control even when the captured upload
was valid; magic-signature outcomes remain diagnostic unless an accepted allowed
control establishes a reliable comparison. Reflected parent-directory paths are
tentative until a separate safe read-back proves the resolved storage location.

The plugin does not upload executable content, retrieve uploaded paths, or
claim code execution by default. An explicit `allow_server_config_uploads=true`
plus an in-scope `safe_readback_url` enables a sequential `.htaccess` → inert
alternate-extension → read-back chain. It proves configuration application with
a unique harmless MIME type and marker; it never uploads executable syntax.
The opted-in chain leaves its `.htaccess` and inert marker file on the target;
the caller is responsible for authorized cleanup. Storage renaming, asynchronous
scanning, and execution require separate validation.
