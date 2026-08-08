# `race_group` host contract

A group may mix saved exchanges, inline requests, and saved requests with
overrides:

```json
{
  "type": "race_group",
  "id": "race-0",
  "technique": "sequential_control | parallel | last_byte_sync | h2_single_packet",
  "attempt": 0,
  "requests": [
    {
      "id": "apply-copy-0",
      "method": "POST",
      "url": "https://example.test/apply",
      "headers": [{ "name": "Content-Type", "value": "application/json" }],
      "body_text": "{\"code\":\"ONE\"}",
      "protocol": "h1",
      "use_project_cookies": true,
      "success": {
        "status_codes": [200],
        "json": [{ "pointer": "/applied", "equals": true }]
      }
    },
    {
      "id": "confirm-copy-0",
      "base_exchange_id": 42,
      "url": "https://example.test/confirm",
      "header_tombstones": ["If-Match"],
      "success": { "redirect_location": { "contains": "/complete" } }
    }
  ],
  "options": { "timeout_ms": 30000, "hold_timeout_ms": 5000 }
}
```

Exactly one of `body_text` and `body_base64` is allowed. A request needs either
`base_exchange_id` or an inline `url`. When both are present, the inline fields
override the saved request through the normal Reply materialization path.
`use_project_cookies` defaults to true so inline last-byte requests can use the
host-managed cookie jar without placing session values in plugin input.

A `sequential_control` setup request may declare up to 16 response `extract`
rules (`body_regex`, `header`, or `json`). Sequential plans with
`stop_on_error: true` can reference them later as `{{extract:name}}` in typed
URL, `body_text`, and header values. Names are unique across the plan, values
are capped at 8 KiB each/64 KiB total, and only names—not values—reach plugin
analysis. A plan may contain at most 256 extracts.

Responses include the host-evaluated semantic predicate without returning the
matched body:

```json
{
  "id": "apply-copy-0",
  "exchange_id": 100,
  "status_code": 200,
  "response_length": 42,
  "response_body_hash": "hex",
  "success": {
    "matched": true,
    "checks": [{ "type": "json", "pointer": "/applied", "matched": true }],
    "body_truncated": false,
    "indeterminate": false
  },
  "error": null
}
```

Body-dependent predicates inspect at most 256 KiB. A failed body check on a
truncated response is marked `indeterminate` and is not counted as success.

`last_byte_sync` materializes each request as HTTP/1, opens every connection,
withholds the final byte, and releases it through one barrier. It rejects an
explicit HTTP/2 request. `h2_single_packet` requires HTTPS, one shared origin,
and supports both empty and non-empty bodies. The host negotiates ALPN `h2`,
opens one stream per request, withholds each final DATA fragment (including a
zero-length terminal DATA frame for an empty body), and releases the final
fragments in one TLS write. It returns `synchronized: true` only when that
single write occurred. Protocol-incompatible targets return an explicit error
and are never retried through ordinary parallel dispatch. Every resulting
exchange is stored and tagged by the host.
