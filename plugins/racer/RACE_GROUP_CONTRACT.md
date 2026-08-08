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
explicit HTTP/2 request. `h2_single_packet` remains unsupported until the host
can release final HTTP/2 DATA fragments in one real TCP packet; it must return
`protocol_incompatible`, never ordinary parallel dispatch. Every resulting
exchange is stored and tagged by the host.
