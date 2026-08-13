# HuntProxy plugin API v1

This is the compact contract reference. Start with
[Write a HuntProxy plugin](writing-plugins.md) and the
[minimal example](../examples/minimal-plugin/) if you are building your first
plugin.

## Package contract

The manifest shape is defined in
[`schemas/plugin-manifest-v1.json`](../schemas/plugin-manifest-v1.json). The
generic checker also verifies files, UTF-8, digests, host-compatible byte
limits, exports, and safe path resolution:

```bash
node scripts/validate-plugin.mjs path/to/plugin
```

The public schema intentionally uses simple IDs and explicit limits even where
the host accepts a broader defaulted form.

| Manifest field | Contract |
|---|---|
| `schema_version` | `1` |
| `id` | 2–63 lowercase letters, digits, or hyphens; begins alphanumeric |
| `name` | Nonblank, 1–80 characters, at most 128 UTF-8 bytes |
| `version` | `MAJOR.MINOR.PATCH` |
| `description` | 1–300 characters |
| `enabled` | Boolean; disabled packages cannot run |
| `entrypoint` | Safe relative `.js` path, UTF-8, at most 4 MiB |
| `entrypoint_sha256` | Lowercase SHA-256 of the exact file bytes |
| `resources` | Named safe relative UTF-8 files, each at most 1 MiB and 4 MiB total |
| `capabilities` | Unique values from the table below |
| `limits` | Explicit conservative ceilings |
| `actions` | Unique names, descriptions, input schemas, capability hints, and optional saved-exchange requirements |

`input_schema` is shown to agents for discovery. The host does not currently
validate action input against it before calling `plan()`. Validate required,
bounded, and safety-sensitive values inside `plan()` too.

Set an action's `requires_base_exchange` to `true` when planning or evidence
always depends on a saved request. HuntProxy exposes the requirement through
`extension_describe` and rejects preview/run calls without `base_exchange_id`
before starting the JavaScript runtime. It defaults to `false` for existing
packages.

## Capabilities

| Capability | Permits |
|---|---|
| `http.semantic` | `http_request` and `http_workflow` |
| `browser.csrf` | Isolated real-browser CSRF delivery probes |
| `http.raw` | `raw_http1`, `raw_http1_group`, and `raw_http2`; also exposes bounded raw base-request context |
| `page.discover` | Bounded static endpoint/URL discovery from the stored base response |
| `http.race` | `race_group` |
| `identity.use` | Bounded unredacted base request headers/body for identity-aware comparisons |
| `aws.api_gateway` | Specialized host-managed IpRotate Gateway operations |

`browser.csrf` plans a bounded `browser_csrf` operation using a captured GET or
form-urlencoded POST plus an explicit named cookie-profile identity. HuntProxy
clones managed cookies into a fresh non-persistent Chromium context, submits from
an opaque cross-site document, captures the exchanges, reports only whether a
matching managed cookie was delivered, and discards the context. Custom attacker
origins, arbitrary scripts or headers, non-form bodies, sibling origins, and
WebSocket flows are intentionally unsupported.

Capabilities are granted to the whole manifest. An action's
`required_capabilities` must be a subset, but it is discovery metadata rather
than an action-level security boundary. HuntProxy still checks every planned
operation against the manifest capabilities.

## Effective limits

| Limit | Default | Accepted/effective range |
|---|---:|---:|
| Job timeout | 120,000 ms | 1,000–900,000 ms |
| Planned requests | 100 | 1–10,000 |
| Request concurrency | 4 | 1–100, then reduced to the project limit |
| QuickJS memory | 16 MiB | 4–64 MiB |
| Each `plan`/`analyze` stage | 2,000 ms legacy fallback; 60,000 ms first-party | 250–120,000 ms |
| Entrypoint | — | 4 MiB |
| Plugin input | — | 2 MiB |
| Final result | — | 8 MiB |
| Body exposed to JavaScript | — | 256 KiB, then marked truncated |

`max_operations` counts actual requests, not only top-level operation objects:
workflow steps, raw-group members, HTTP/2 streams, race requests, and AWS
regions all count. `max_concurrency` is also reduced to the project's request
concurrency limit. At most four plugin jobs run at once across the host.
`extension_describe` also returns host-resolved `effective_limits`, making an
omitted or clamped value visible before execution. `extension_preview` runs the
real planner without network traffic and reports stage-scoped request,
candidate, runtime, and mode estimates. If execution completed but aggregation
timed out, `job_resume_analysis` retries the retained analysis without replaying
any probes.

## JavaScript lifecycle

The UTF-8 entrypoint assigns:

```js
globalThis.HuntProxyPlugin = {
  plan: function (input, context) { return planObject; },
  analyze: function (input, observations, context) { return analysisObject; }
};
```

Both functions are synchronous, JSON-only, and run in separate QuickJS
contexts. Async functions and Promise returns are unsupported because HuntProxy
does not await them. Filesystem/process APIs, sockets, `fetch`, Node modules,
and npm packages are unavailable.

### Context

Every call receives:

```json
{
  "api_version": 1,
  "plugin_id": "example",
  "plugin_version": "1.0.0",
  "action": "scan",
  "project_id": 7,
  "base_exchange": null,
  "related_exchanges": [],
  "resources": {}
}
```

When supplied, `base_exchange` contains presented request metadata:

```text
exchange_id, method, url, headers, request_length,
request_body_hash, request_preview
```

With `identity.use`, it also contains `identity.request_headers` as base64
values and a bounded `identity.request_body_base64`. With `http.raw`, it gains
`raw_request_base64` plus `raw_request_reconstructed`, or
`raw_request_omitted: true` when unavailable.
With `page.discover`, it also contains `page_discovery` with the saved source
URL and a bounded `targets` list of host-resolved, same-origin passive resource
URLs extracted from the decoded stored response, plus total/truncation fields.
Emails, flat application routes, cross-origin references, userinfo, fragments,
and sensitive signed-query candidates are excluded. Discovery is passive;
plugins must still deliberately request each candidate.

`identity.use` also permits semantic HTTP operations to declare an opaque
`identity` selector containing exactly one of `profile` or `cookie_file`.
HuntProxy resolves selectors host-side once per job, applies cookie
domain/path/expiry rules to each request URL, and suppresses the active project
cookie jar. Cookie bytes are not exposed to plugin JavaScript or job output;
the caller-supplied file path is used only as an opaque selector. Named profiles are project-scoped and managed through the `cookies`
tool with `profile_name`.

If `input.exchange_ids` is an integer array, the host loads bounded
`related_exchanges` containing `exchange_id`, `method`, `url`, and
`status_code`. Verified manifest resources appear as UTF-8 strings under their
manifest names.

### Plan result

```json
{
  "execution": "parallel",
  "stop_on_error": false,
  "operations": [],
  "result": {}
}
```

All fields are optional. Execution defaults to `parallel`; use `sequential`
when top-level operations depend on order. Workflow steps are internally
sequential. `stop_on_error: true` requires sequential execution. `result` is
returned later as `plan_result`; it is not passed to `analyze()`.

Operation IDs must be nonempty, unique, stable, and safe to expose in History
as `plugin-op:<id>` labels.

## Operations

### Semantic request

```json
{
  "id": "replay",
  "type": "http_request",
  "base_exchange_id": 42,
  "method": "GET",
  "protocol": "auto",
  "headers": [{"name": "X-Check", "value": "one"}],
  "header_tombstones": ["Authorization"],
  "query_params": [{"name": "debug", "value": "1"}]
}
```

Supply `base_exchange_id`, or an inline `url` and usually `method`. Optional
fields include `delay_before_ms` (0–30,000), `body_text`, `body_base64`, and
typed `query_params`, `cookie_params`, and `body_params`. A typed parameter
with `value: null` removes it. Protocol is `auto`, `h1`, or `h2`.
`cookie_params` and `body_params` require `base_exchange_id`; body parameters
only mutate saved form-urlencoded bodies or top-level JSON objects.

### Private workflow

```json
{
  "id": "fresh-token-submit",
  "type": "http_workflow",
  "steps": [
    {
      "id": "acquire",
      "request": {"id": "get-form", "url": "https://example.test/form", "method": "GET"},
      "extract": [{"from": "body_regex", "name": "csrf", "pattern": "name=csrf value=([^ >]+)", "group": 1, "encoding": "url"}]
    },
    {
      "id": "submit",
      "request": {"id": "post-form", "url": "https://example.test/form", "method": "POST", "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}], "body_text": "csrf={{extract:csrf}}"}
    }
  ]
}
```

A workflow has 1–64 ordered steps. Each step may extract at most 16 values
from `body_regex`, `header`, or `json`; extracts are at most 8 KiB each and
64 KiB total. Encodings are `raw`, `url`, `json`, or `base64`; extracts are
required by default. `{{extract:name}}` works in method, URL, UTF-8 header
values, `body_text`, and typed parameter values—not `body_base64`. Extracted
values remain host-private and are removed from observations and results.

### Raw HTTP/1

```json
{
  "id": "raw-probe",
  "type": "raw_http1",
  "target_url": "https://example.test/",
  "request_utf8": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
  "use_project_cookies": false,
  "options": {"response_mode": "auto", "read_timeout_ms": 60000, "idle_timeout_ms": 1000}
}
```

Use exactly one of `request_utf8` or `request_base64`. Advanced options support
bounded split writes, response-gated continuation, half-close, and response
modes `auto`, `until_idle`, or `until_close`.

### Barriered raw HTTP/1 group

```json
{
  "id": "two-sockets",
  "type": "raw_http1_group",
  "target_url": "https://example.test/",
  "members": [
    {"id": "a", "request_utf8": "GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n"},
    {"id": "b", "request_utf8": "GET /b HTTP/1.1\r\nHost: example.test\r\n\r\n"}
  ]
}
```

Groups require 2–32 members. HuntProxy opens every connection before releasing
the requests through one barrier. Each member accepts the raw HTTP/1 fields
above and produces its own saved exchange.

### Raw HTTP/2

```json
{
  "id": "h2-probe",
  "type": "raw_http2",
  "target_url": "https://example.test/",
  "streams": [{
    "id": "stream-a",
    "headers": [
      {"name": ":method", "value": "GET"},
      {"name": ":scheme", "value": "https"},
      {"name": ":authority", "value": "example.test"},
      {"name": ":path", "value": "/"}
    ]
  }],
  "options": {"timeout_ms": 60000, "final_data_together": false}
}
```

Raw HTTP/2 requires HTTPS with ALPN `h2`. Header order is preserved, including
pseudo-headers. Streams may supply an odd `stream_id` and one of `body_text`
or `body_base64`. `final_data_together` releases final DATA frames in one
write; unsupported protocol negotiation is an error rather than a fallback.

### Race group

```json
{
  "id": "attempt-0",
  "type": "race_group",
  "technique": "parallel",
  "attempt": 0,
  "requests": [
    {"id": "one", "base_exchange_id": 42, "success": {"status_codes": [200, 302]}},
    {"id": "two", "base_exchange_id": 42, "success": {"status_codes": [200, 302]}}
  ],
  "options": {"timeout_ms": 60000}
}
```

Techniques are `sequential_control`, `parallel`, `last_byte_sync`, and
`h2_single_packet`. Requests accept semantic URL/method/header/body overrides,
project-cookie opt-in, and bounded success predicates for status, headers,
body, JSON, and redirects. Private extraction/binding requires a sequential,
stop-on-error plan. See Racer's
[`RACE_GROUP_CONTRACT.md`](../plugins/racer/RACE_GROUP_CONTRACT.md) for the
advanced synchronization and private-validation contract.

### AWS API Gateway

```json
{
  "id": "rotation-status",
  "type": "aws_api_gateway",
  "action": "status"
}
```

This is a specialized IpRotate host capability, not a general AWS SDK. Actions
are `status`, `enable` (`target_url`, `regions`, `stage_name`), and `disable`
(`target_url`). Credentials stay in the local IpRotate credential file and are
never passed into JavaScript.

## Observations

`analyze()` receives one observation per top-level operation. Sequential plans
preserve order; parallel plans use completion order. Always correlate by `id`.

An ordinary semantic response contains:

```text
id, exchange_id, status_code, duration_ms, response_length,
response_body_hash, response_preview, response_headers,
response_body_base64, response_body_truncated
```

Response header values and bodies are base64. Bodies are decoded when safe and
bounded to 256 KiB. A semantic request may add
`observe: {body_bytes, body_contains}`. `body_bytes` is capped at 256 KiB and
defaults to zero when `observe` is present; up to 32 exact strings can be
searched case-insensitively across the decoded saved body, returning
`response_body_contains` without copying that body into JavaScript.
`response_body_search_complete` is false when an unsupported or oversized
encoded body could not be searched completely; plugins must treat that as
inconclusive rather than as a negative match. The host
also enforces a bounded aggregate analysis payload. If legacy captures exceed
it, bodies/transcripts are omitted with an `*_omitted_reason` while hashes,
previews, headers, evidence IDs, and host-side search results remain available.
Operation-specific wrappers are:

| Operation | Observation |
|---|---|
| `http_workflow` | `{id, steps, terminal, extracted, error?}` |
| `raw_http1` | `{id, raw}` with a bounded `response_transcript_base64` |
| `raw_http1_group` | `{id, dispatch, members}` |
| `raw_http2` | `{id, protocol, single_write_release, streams, ...}` |
| `race_group` | `{id, technique, attempt, synchronized, responses, error?}` |
| `aws_api_gateway` | `{id, ip_rotation, error?}` |

A normal operation failure becomes:

```json
{"id": "probe", "error": {"code": "...", "message": "..."}}
```

After a sequential stop-on-error failure, remaining observations contain
`{"id":"...","skipped":{"reason":"previous operation failed"}}`.
Cancellation and stage exceptions fail the whole job.

Jobs retain `execution.evidence_exchange_ids` for all saved probe exchanges
before analysis starts, so the IDs remain available if analysis fails.
Generated exchanges also receive a `plugin-job:<uuid>` label for recovery after
the in-memory job record expires.

## Analysis and findings

Return JSON such as:

```json
{
  "findings": [],
  "result": {"tested": 1}
}
```

At most 1,000 findings may be returned. A persisted finding requires `title`
and a nonempty `evidence_exchange_ids` array referencing exchanges saved in
the same project. Recommended fields are `severity`, `confidence`,
`explanation`, and bounded non-secret `metadata`.

HuntProxy redacts known base-request secrets and sensitive output keys, but a
plugin must still avoid copying secrets or private extracts into any output.
Extra finding metadata remains in the job analysis; the persisted finding
record stores its title, description, and first evidence link.
Every generated exchange is labeled with `plugin`, the plugin name,
`plugin:<id>`, and `plugin-op:<operation-id>`.
