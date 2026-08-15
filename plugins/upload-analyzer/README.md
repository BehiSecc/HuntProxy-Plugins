# UploadAnalyzer

UploadAnalyzer turns one captured multipart upload into a repeatable filtering experiment. It replaces the first file with inert marker content, compares an allowed extension with a prohibited extension, and then tests filename normalization and declared-content variations twice each.

Other multipart fields and the captured request context are preserved.

## Start With a Working Upload

Choose a saved, complete `multipart/form-data` request containing a `filename=` or UTF-8 `filename*=` file part. Set `allow_uploads: true`, then identify one extension the application should allow and one it should block.

Add success and failure markers when accepted and rejected uploads return the same status code. The normal full matrix contains 21 variations and sends each twice, producing 42 upload requests.

## Example Prompt

```text
Use HuntProxy MCP. Run UploadAnalyzer on exchange 42. The application should
allow .jpg and block .php. Treat “Upload complete” as success and “File type
not allowed” as failure. Show me the planned request count, then run the inert
filename and content checks and summarize reproducible differences.
```

## What It Checks

| Group | Examples |
| --- | --- |
| **Controls** | One allowed extension and one directly prohibited extension. |
| **Filename normalization** | Mixed case, trailing dot or space, double extension, semicolon, encoded dots, null suffixes, encoded slash, and Windows ADS. |
| **Path handling** | Plain and encoded parent-directory filenames. |
| **Declared content** | Image and octet-stream MIME mismatches plus PNG, GIF, and PDF signature prefixes. |

All ordinary matrix payloads contain inert marker data. The declared-image checks reuse the captured image MIME type when one is available.

## How It Confirms a Result

A filename bypass requires the allowed control to be accepted, the direct prohibited control to be reproducibly rejected, and the variation to behave like the allowed upload twice. Strong response similarity produces a firm result; weaker but marker-backed acceptance remains tentative.

If the prohibited extension is accepted directly, the plugin reports ineffective extension filtering rather than a bypass. Content-validation findings are created only when `expect_content_validation: true` is set.

A parent-directory filename is always tentative because response reflection does not prove where the server stored the file.

## Optional Server-Configuration Chain

`allow_server_config_uploads: true` adds an Apache-specific `.htaccess` workflow. The plugin uploads `.htaccess` twice, uploads an inert alternate-extension marker twice, and fetches its known URL twice.

A firm result requires both uploads to succeed and the read-back to return the marker with the configured `application/x-huntproxy-inert` MIME type. The workflow requires `safe_readback_url`, supports `{filename}` substitution, and leaves both uploaded files for later cleanup.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `allow_uploads` | Required | Must be `true` before the plugin plans repeated uploads. |
| `allowed_extension` | `txt` | Name an extension the application should accept. |
| `prohibited_extension` | `php` | Name an extension the application should reject. |
| `marker` | `huntproxy-upload` | Give every uploaded file recognizable inert content and filenames. |
| `success_markers` / `failure_markers` | Empty | Distinguish accepted and rejected responses with similar status codes. |
| `expect_content_validation` | `false` | Report accepted MIME and signature mismatches as findings. |
| `max_files` | `21` | Select the first 2–21 ordered cases, including the two controls. Each case is uploaded twice; `2` runs controls only. |
| `allow_server_config_uploads` | `false` | Add the `.htaccess` and inert read-back workflow. |
| `server_config_extension` | `l33t` | Choose the alternate extension mapped by the `.htaccess` test. |
| `safe_readback_url` | Empty | Supply the known URL for the inert marker file, optionally using `{filename}`. |

## Current Limits

- It only changes the first file in a multipart request and does not discover where uploaded files are stored.
- Accepted uploads do not prove public retrievability or code execution. Ordinary mode performs no read-back and never uploads executable code.
- Storage renaming, delayed scanning, and later file transformations need a separate read-back workflow.
- Image-only endpoints can reject the allowed control because the ordinary matrix uses inert text rather than a structurally complete image.
- The server-configuration chain is specific to Apache `.htaccess` and requires a caller-known read-back URL.
