# `race_group` host contract

Input operation:

```json
{
  "type": "race_group",
  "id": "race-0",
  "technique": "sequential_control | parallel | last_byte_sync | h2_single_packet",
  "attempt": 0,
  "requests": [{ "id": "shape-0-copy-0", "base_exchange_id": 42 }],
  "options": { "timeout_ms": 30000, "hold_timeout_ms": 5000 }
}
```

Observation:

```json
{
  "id": "race-0",
  "technique": "last_byte_sync",
  "attempt": 0,
  "synchronized": true,
  "release_skew_ms": 0.4,
  "responses": [{
    "id": "shape-0-copy-0",
    "exchange_id": 100,
    "status_code": 200,
    "response_length": 42,
    "response_body_hash": "hex",
    "duration_ms": 25,
    "error": null
  }]
}
```

`last_byte_sync` withholds each exact HTTP/1 request's final byte until all
connections are ready. `h2_single_packet` withholds final DATA fragments and
writes them in one TCP packet. Neither may silently fall back to parallel
dispatch. Every resulting exchange is stored and tagged by the host.
