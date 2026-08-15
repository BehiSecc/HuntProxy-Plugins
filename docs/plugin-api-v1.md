# HuntProxy Plugin API v1

This is the contract reference for HuntProxy plugin authors. If you are building your first plugin, start with [Create a HuntProxy Plugin](writing-plugins.md) and the [minimal working example](../examples/minimal-plugin/).

```text
plan(input, context) → HuntProxy executes bounded operations → analyze(input, observations, context)
```

The plugin chooses what to test and interprets the observations. HuntProxy validates the plan, performs the network work, saves every exchange, and persists evidence-backed findings.

## Contents

- [Package Contract](#package-contract)
- [Capabilities](#capabilities)
- [Effective Limits](#effective-limits)
- [JavaScript Lifecycle](#javascript-lifecycle)
- [Context](#context)
- [Plan Result](#plan-result)
- [Operations](#operations)
  - [Semantic HTTP Request](#semantic-http-request)
  - [Private HTTP Workflow](#private-http-workflow)
  - [Raw HTTP/1](#raw-http1)
  - [Barriered HTTP/1 Group](#barriered-http1-group)
  - [Raw HTTP/2](#raw-http2)
  - [Race Group](#race-group)
  - [Browser CSRF](#browser-csrf)
  - [AWS API Gateway](#aws-api-gateway)
- [Observations](#observations)
- [Analysis and Findings](#analysis-and-findings)
- [Agent and Job Flow](#agent-and-job-flow)

## Package Contract

A plugin is an immediate child of HuntProxy's configured `plugin_dir`:

```text
my-plugin/
├── plugin.json
├── index.js
├── README.md       optional, recommended
└── resources/      optional UTF-8 files
```

The public manifest shape is defined by [`schemas/plugin-manifest-v1.json`](../schemas/plugin-manifest-v1.json). Validate a package from the HuntProxy-Plugins repository root with:

```bash
node scripts/validate-plugin.mjs path/to/my-plugin
```

| Manifest Field | Contract |
| --- | --- |
| `schema_version` | Must be `1`. |
| `id` | 2–63 lowercase letters, digits, or hyphens; begins with a letter or digit. |
| `name` | Nonblank, 1–80 characters and at most 128 UTF-8 bytes. |
| `version` | `MAJOR.MINOR.PATCH`. |
| `description` | 1–300 characters. |
| `enabled` | Boolean. A disabled package cannot run. |
| `entrypoint` | Safe relative `.js` path; UTF-8 and at most 4 MiB. |
| `entrypoint_sha256` | Lowercase SHA-256 of the exact entrypoint bytes. |
| `resources` | Named safe relative UTF-8 files, each at most 1 MiB and 4 MiB total, with exact SHA-256 digests. |
| `capabilities` | Unique host capabilities from the table below. |
| `limits` | Explicit ceilings for the job and JavaScript runtime. |
| `actions` | Unique agent-visible actions, descriptions, input schemas, capability hints, and optional base-exchange requirements. |

An action has this general shape:

```json
{
  "name": "scan",
  "description": "Test one captured request for a focused behavior.",
  "required_capabilities": ["http.semantic"],
  "requires_base_exchange": true,
  "input_schema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {}
  }
}
```

Action names match `^[a-z][a-z0-9_]{1,63}$` and must be unique inside the manifest.

`input_schema` is discovery metadata shown to the agent. HuntProxy does not currently apply schema validation or defaults before calling `plan()`. The plugin must validate types, required fields, bounds, unknown fields, and explicit opt-ins itself.

`requires_base_exchange: true` makes HuntProxy advertise the dependency and reject preview or run calls without `base_exchange_id` before JavaScript starts.

## Capabilities

| Capability | What It Permits |
| --- | --- |
| `http.semantic` | `http_request` and `http_workflow`. |
| `http.raw` | `raw_http1`, `raw_http1_group`, and `raw_http2`; also bounded raw base-request context. |
| `http.race` | `race_group`. |
| `identity.use` | Bounded identity-aware context and host-resolved profile or cookie-file selectors. |
| `page.discover` | Bounded passive same-origin resource candidates from the saved base response. |
| `browser.csrf` | Isolated Chromium delivery through `browser_csrf`. |
| `aws.api_gateway` | IpRotate's specialized `aws_api_gateway` lifecycle operation. |

Capabilities belong to the whole manifest. `actions[].required_capabilities` must be a subset of that list, but it is discovery metadata rather than a separate action-level boundary. HuntProxy checks every planned operation against the manifest capabilities.

## Effective Limits

| Limit | Host Default | Accepted Range |
| --- | ---: | ---: |
| Job timeout | 120,000 ms | 1,000–900,000 ms |
| Planned network operations | 100 | 1–10,000 |
| Request concurrency | 4 | 1–100, then reduced to the project limit |
| QuickJS memory | 16 MiB | 4–128 MiB |
| Each `plan` or `analyze` stage | 2,000 ms | 250–120,000 ms |
| Manifest | — | 256 KiB |
| Entrypoint | — | 4 MiB |
| Plugin input | — | 2 MiB |
| Final result | — | 8 MiB |
| Response body exposed to JavaScript | — | 256 KiB before truncation or omission |

The public schema requires `timeout_ms`, `max_operations`, `max_concurrency`, and `memory_mb`. `js_stage_timeout_ms` is optional.

`max_operations` counts actual network work, not top-level objects. Workflow steps, raw-group members, HTTP/2 streams, race requests, and AWS regions all count. HuntProxy exposes the resolved values as `effective_limits` through `extension_describe`.

At most four plugin jobs run concurrently across the host. Candidate lists, repeats, response processing, and output should remain bounded even when the manifest ceiling is high.

## JavaScript Lifecycle

The UTF-8 entrypoint assigns two synchronous functions:

```js
globalThis.HuntProxyPlugin = {
  plan: function (input, context) {
    return {operations: [], result: {}};
  },
  analyze: function (input, observations, context) {
    return {findings: [], result: {}};
  }
};
```

Both functions must return plain JSON. Async functions, generators, and Promise results are unsupported. The runtime provides no `fetch`, sockets, filesystem or process APIs, Node.js modules, or npm packages.

Planning and analysis run in separate QuickJS contexts. Globals do not carry between them, and `plan.result` becomes `plan_result` in the final job output rather than an input to `analyze()`.

## Context

Both stages receive a context shaped like:

```json
{
  "api_version": 1,
  "execution_nonce": "0123456789abcdef0123456789abcdef",
  "plugin_id": "example",
  "plugin_version": "1.0.0",
  "action": "scan",
  "project_id": 7,
  "base_exchange": null,
  "related_exchanges": [],
  "resources": {}
}
```

When supplied, `base_exchange` contains a presented request summary:

```text
exchange_id, method, url, headers, request_length,
request_body_hash, request_preview
```

Capabilities add bounded context:

- `identity.use` adds base64 request identity headers and up to 256 KiB of request body under `base_exchange.identity`. This context may contain credentials and is available only for semantic saved exchanges; a raw-wire base exchange is rejected.
- `http.raw` adds up to 2 MiB of exact or reconstructed raw request data through `raw_request_base64`, plus `raw_request_reconstructed`; otherwise it sets `raw_request_omitted: true`.
- `page.discover` adds up to 64 passive same-origin resource candidates and total/truncation metadata under `base_exchange.page_discovery`. It is omitted when the action input already supplies `target_url`.

When `input.exchange_ids` is an integer array, HuntProxy loads bounded `related_exchanges` containing `exchange_id`, `method`, `url`, and `status_code`. Verified resource files appear as strings under their manifest names in `context.resources`.

Identity selectors contain exactly one nonempty `profile` or `cookie_file`. The same selector object must appear in the caller's action input before a plugin may use it in an operation. HuntProxy resolves it host-side, suppresses the active project cookie jar for that operation, applies the selected cookies by domain/path/expiry rules, and keeps their bytes out of JavaScript and job output. A plugin operation using selectors also requires `identity.use`.

## Plan Result

`plan()` returns:

```json
{
  "execution": "parallel",
  "stop_on_error": false,
  "operations": [],
  "result": {},
  "preview": {
    "stage": "confirm",
    "candidate_count": 10,
    "candidate_unit": "variants"
  }
}
```

All fields are optional. Top-level execution defaults to `parallel`; use `sequential` when operations depend on order. `stop_on_error: true` requires sequential execution. Workflow steps remain internally ordered.

Operation IDs must be nonempty, unique, and stable. HuntProxy uses them in observations and History labels.

`preview` is optional bounded metadata for `extension_preview`. Supported fields include stage, scope, follow-up expectation, candidate count and unit, candidate breakdown, selected/supported/recommended modes, and a recommendation.

`scope` is `current_stage` or `complete_action`. Preview identifiers are short slugs, candidate breakdown and supported modes are limited to 16 entries, and the recommendation is limited to 512 characters.

Every operation URL is checked against project scope when it executes. Without explicit host patterns, a base-exchange job is pinned to that exchange's host; a job without a base exchange is pinned to the project's target host. Preview sends no requests, so successful planning does not guarantee that every URL will pass execution-time scope checks.

## Operations

| Operation | Capability | Purpose |
| --- | --- | --- |
| `http_request` | `http.semantic` | Replay or modify one semantic HTTP request. |
| `http_workflow` | `http.semantic` | Run ordered requests with private extraction and substitution. |
| `raw_http1` | `http.raw` | Send one byte-oriented HTTP/1 request. |
| `raw_http1_group` | `http.raw` | Release 2–32 HTTP/1 connections through one barrier. |
| `raw_http2` | `http.raw` | Send ordered HTTP/2 headers and streams. |
| `race_group` | `http.race` | Run sequential controls, parallel requests, or synchronized races. |
| `browser_csrf` | `browser.csrf` + `identity.use` | Test supported cross-site delivery in isolated Chromium. |
| `aws_api_gateway` | `aws.api_gateway` | Manage IpRotate's bounded API Gateway profiles. |

### Semantic HTTP Request

```json
{
  "id": "probe",
  "type": "http_request",
  "base_exchange_id": 42,
  "method": "GET",
  "protocol": "auto",
  "headers": [{"name": "X-Check", "value": "one"}],
  "header_tombstones": ["X-Remove-Me"],
  "query_params": [{"name": "debug", "value": "1"}],
  "observe": {
    "body_bytes": 4096,
    "body_contains": ["expected marker"]
  }
}
```

Provide `base_exchange_id`, or an inline `url` and usually `method`. Common optional fields are:

- `delay_before_ms`, from 0 to 30,000;
- `body_text` or `body_base64`;
- `headers` and `header_tombstones`;
- typed `query_params`, `cookie_params`, and `body_params`; and
- `protocol`: `auto`, `h1`, or `h2`.

A parameter with `value: null` removes it. `cookie_params` and `body_params` require a saved exchange; body parameters modify saved form-urlencoded bodies or top-level JSON objects.

`credential_mode` defaults to `with_project_credentials`; use `without_project_credentials` to suppress the project cookie jar. An opaque `identity` selector can apply a named profile or local cookie file when `identity.use` is declared.

`identity_comparison` optionally groups requests that use the same base exchange. HuntProxy rejects the group when supposedly different selectors resolve to identical cookie credentials.

`observe.body_contains` searches up to 32 exact strings case-insensitively on the host without copying the complete body into JavaScript. If `response_body_search_complete` is false, a missing match is inconclusive.

Each search string is limited to 200 bytes. When `observe` is present, `body_bytes` defaults to zero; request only the response bytes the analysis actually needs.

See the [minimal plugin](../examples/minimal-plugin/) for a basic replay and [ParamFinder](../plugins/param-finder/README.md) for a staged semantic workflow.

### Private HTTP Workflow

```json
{
  "id": "fresh-token-submit",
  "type": "http_workflow",
  "steps": [
    {
      "id": "acquire",
      "request": {
        "id": "get-form",
        "url": "https://example.test/form",
        "method": "GET"
      },
      "extract": [{
        "from": "body_regex",
        "name": "csrf",
        "pattern": "name=csrf value=([^ >]+)",
        "group": 1,
        "encoding": "url"
      }]
    },
    {
      "id": "submit",
      "request": {
        "id": "post-form",
        "url": "https://example.test/form",
        "method": "POST",
        "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
        "body_text": "csrf={{extract:csrf}}"
      }
    }
  ]
}
```

A workflow contains 1–64 ordered steps. Each step may extract up to 16 values from `body_regex`, `header`, or `json`; extracts are limited to 8 KiB each and 64 KiB total. Encodings are `raw`, `url`, `json`, and `base64`.

Extracts are required by default. An optional missing extract produces no value, but a later placeholder still fails if that value is unavailable. `{{extract:name}}` works in method, URL, UTF-8 header values, `body_text`, and typed parameter values, but not `body_base64`. Observation metadata exposes extracted names only; values remain host-private.

See [CSRFAnalyzer](../plugins/csrf-analyzer/README.md) for a maintained private-workflow example.

### Raw HTTP/1

```json
{
  "id": "raw-probe",
  "type": "raw_http1",
  "target_url": "https://example.test/",
  "request_utf8": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
  "use_project_cookies": false,
  "options": {
    "response_mode": "auto",
    "read_timeout_ms": 60000,
    "idle_timeout_ms": 1000
  }
}
```

Supply exactly one of `request_utf8` or `request_base64`. `target_url` selects the connection destination rather than rewriting the raw bytes. Raw options support an upstream proxy, bounded split writes, response-gated continuation, half-close, and response modes `auto`, `until_idle`, and `until_close`.

`pause_at_byte` and `pause_ms` must be supplied together, with the offset strictly between the first and last request byte. `await_response_before_continue` requires those split options. Split pauses range from 1–120,000 ms, read timeouts from 1–120,000 ms, and idle timeouts from 1–10,000 ms. Managed cookie injection cannot be combined with split-byte writes.

### Barriered HTTP/1 Group

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

Groups require 2–32 uniquely named members and must fit the project's request-concurrency limit. HuntProxy opens every connection before releasing the requests through one local barrier. Each successful member produces its own saved exchange, and the aggregate response allowance is capped at 64 MiB.

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

Raw HTTP/2 requires HTTPS with ALPN `h2`; unsupported negotiation is an error rather than an HTTP/1 fallback. A request contains 1–100 uniquely named streams with 1–256 ordered header fields each. Streams may set a unique odd 31-bit `stream_id` and one of `body_text` or `body_base64`; total outbound bodies are capped at 65,535 bytes. `final_data_together` requires at least two streams and releases final DATA fragments in one TLS write.

See [Request Smuggler](../plugins/request-smuggler/README.md) for maintained raw HTTP examples.

### Race Group

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

Groups contain 1–1,000 requests. Techniques are `sequential_control`, `parallel`, `last_byte_sync`, and `h2_single_packet`. Requests accept semantic URL, method, header, and body overrides plus bounded success predicates for status, headers, body, JSON, and redirects. A body-dependent predicate that cannot inspect the full body is indeterminate rather than false.

`last_byte_sync` must fit the project's request-concurrency limit. `h2_single_packet` supports at most 100 requests, requires one HTTPS origin with ALPN `h2`, and does not fall back to HTTP/1.

HTTP/1 last-byte mode reconstructs a semantic HTTP/1 request; it is not byte-for-byte inherited raw replay. Current split writes cannot inject the managed project cookie jar, so use credentials already captured in the saved request with `use_project_cookies: false`.

Extraction is allowed only from `sequential_control` groups, with at most 16 extracts per group and 256 per plan. Any private extraction or binding requires a sequential, stop-on-error plan; placeholders are unsupported in `body_base64` and regular-expression predicates. Start with the [Racer guide](../plugins/racer/README.md), then use [`RACE_GROUP_CONTRACT.md`](../plugins/racer/RACE_GROUP_CONTRACT.md) for the low-level synchronization and private-validation contract.

### Browser CSRF

```json
{
  "id": "browser-check",
  "type": "browser_csrf",
  "base_exchange_id": 42,
  "mode": "cross_site_form_post",
  "body_params": [{"name": "csrf", "value": null}],
  "identity": {"profile": "user-a"},
  "timeout_ms": 15000
}
```

Modes are `top_level_get` and `cross_site_form_post`, and must match the captured GET or POST method. POST requires a saved `application/x-www-form-urlencoded` body. The operation uses a named managed-cookie profile in fresh, non-persistent Chromium and reports whether a matching cookie was delivered.

Timeout is 1,000–30,000 ms. Materialized forms are limited to 128 fields, with names up to 1,024 bytes and values up to 64 KiB. Custom attacker origins, header tombstones, arbitrary scripts, JSON/multipart bodies, sibling-origin flows, and WebSockets are unsupported. The operation needs both `browser.csrf` and `identity.use` for its required profile selector.

An unavailable browser runtime returns a `not_tested` observation with a reason. Matching-cookie delivery proves browser delivery only, not authentication or server-side state change.

### AWS API Gateway

```json
{"id": "rotation-status", "type": "aws_api_gateway", "action": "status"}
```

This is IpRotate's specialized host operation, not a general AWS SDK. Actions are:

- `enable`: `target_url`, `regions`, and `stage_name`;
- `status`; and
- `disable`: `target_url`.

AWS credentials remain in IpRotate's local credential file and never enter JavaScript context or job output.

See [IpRotate](../plugins/ip-rotate/README.md) for its setup and lifecycle.

## Observations

`analyze()` receives one observation per top-level operation. Parallel observations arrive in completion order; always correlate them by `id`.

A normal semantic response can contain:

```json
{
  "id": "probe",
  "exchange_id": 43,
  "status_code": 200,
  "duration_ms": 84,
  "response_length": 512,
  "response_body_hash": "...",
  "response_preview": {"text": "..."},
  "response_headers": [{"name": "Content-Type", "value_base64": "..."}],
  "response_body_base64": "...",
  "response_body_truncated": false,
  "response_body_contains": {"expected marker": true},
  "response_body_search_complete": true
}
```

Raw response header values (`value_base64`) and the optional `response_body_base64` are base64; `response_preview.text` is readable text. Bodies are bounded to 256 KiB before truncation. The aggregate observation payload is limited to 24 MiB; bodies or transcripts may be removed with an `*_omitted_reason`, or oversized legacy observations may be replaced by evidence-only error metadata while keeping recoverable exchange IDs.

Operation wrappers are:

| Operation | Observation Shape |
| --- | --- |
| `http_workflow` | `{id, steps, terminal, extracted, error?}`; `extracted` contains names only. |
| `raw_http1` | `{id, raw}` with a bounded response transcript. |
| `raw_http1_group` | `{id, dispatch, members}`. |
| `raw_http2` | `{id, protocol, single_write_release, streams, ...}`. |
| `race_group` | `{id, technique, attempt, synchronized, responses, error?}`. |
| `browser_csrf` | Delivery status, cookie-delivery evidence, exchanges, and reason when not tested. |
| `aws_api_gateway` | `{id, ip_rotation, error?}`. |

A normal operation failure becomes:

```json
{"id": "probe", "error": {"code": "...", "message": "..."}}
```

After a sequential stop-on-error failure, remaining observations contain a `skipped.reason`. Cancellation or a JavaScript stage exception fails the whole job.

HuntProxy collects `execution.evidence_exchange_ids` for saved probe exchanges before analysis starts. Generated exchanges receive `plugin`, the manifest plugin name, `plugin:<id>`, `plugin-op:<normalized-id>`, and `plugin-job:<uuid>` labels.

## Analysis and Findings

`analyze()` returns JSON such as:

```json
{
  "findings": [{
    "title": "Confirmed example issue",
    "severity": "medium",
    "confidence": "firm",
    "explanation": "The positive behavior was reproduced against its control.",
    "evidence_exchange_ids": [43],
    "metadata": {"variant": "example"}
  }],
  "result": {"tested": 1}
}
```

A plugin may return at most 1,000 findings. Every persisted finding needs a title and at least one evidence exchange from the same project. Negative, failed, or ambiguous checks belong in `result`, not `findings`.

An optional `description` becomes the persisted description. Without it, HuntProxy builds one from severity, confidence, explanation, and evidence IDs.

Do not copy cookies, tokens, passwords, raw authenticated requests, or private workflow extracts into results, errors, metadata, or findings. Host redaction is a backstop, not a substitute for keeping secrets out of plugin-authored output.

The completed job result has this outer shape:

```json
{
  "plan_result": {},
  "execution": {"evidence_exchange_ids": [43]},
  "analysis": {"findings": [], "result": {}},
  "persisted_findings": []
}
```

Keys named `remediation` are removed recursively before plugin output is returned or persisted. Extra finding metadata remains in job analysis; the persisted finding stores its title, description, and first evidence link.

Keep `analysis.result.follow_up` compact. The summary view preserves it directly only when it is at most 64 KiB; use the full result view for larger analysis output.

## Agent and Job Flow

| MCP Tool | Purpose |
| --- | --- |
| `extension_list` | List loaded plugins and rejected-package issues. |
| `extension_describe` | Show actions, input schemas, capabilities, and effective limits. |
| `extension_preview` | Run the real planner without network traffic. |
| `extension_run` | Start a plugin job. |
| `job_status` | Poll progress using the returned recommended interval. |
| `job_results` | Read `summary`, `findings`, or `full` result views. |
| `job_cancel` | Cancel queued or running work. |
| `job_resume_analysis` | Retry retained analysis after an aggregation timeout without replaying probes. |

Analysis checkpoints are bounded and memory-only. Resume them before HuntProxy restarts or the retained job is evicted from the 256-job in-memory window.

## Related Documentation

- [Create a HuntProxy Plugin](writing-plugins.md) is the first-plugin walkthrough.
- [How HuntProxy Plugins Work](architecture.md) explains the host/plugin boundary and job lifecycle.
- [Plugin manifest schema](../schemas/plugin-manifest-v1.json) is the machine-readable package contract.
