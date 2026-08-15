# 403Bypasser

403Bypasser checks whether a denied endpoint becomes accessible when the request is changed in ways that reverse proxies, frameworks, and access-control layers may interpret differently.

It works from one request already saved in HuntProxy History and keeps every control and test result attached to that project.

## Start With a Denied Request

Choose a stable request that returns `401` or `403`. A `404` can also be investigated when you explicitly enable it, but any resulting finding is kept at medium severity.

Prefer a GET, HEAD, or OPTIONS request. If the saved method is not one of these, or you want to add POST, PUT, and PATCH variations, the plugin requires `allow_state_changes: true`. Remember that even a GET endpoint can have side effects on a poorly designed application.

When possible, give the agent text that proves it reached the protected resource, along with text commonly found on login or denial pages. These markers help distinguish a real bypass from a generic `200 OK` response.

## Example Prompt

```text
Use HuntProxy MCP. Run 403Bypasser against the latest 403 response for /admin
in project 1. Do not enable state-changing variants. Treat “Admin panel” as a
success marker and “Access denied” or “Sign in” as failure markers. Show only
reproducible results and their History exchange IDs.
```

## What It Checks

| Group | Examples |
| --- | --- |
| **Path handling** | Repeated slashes, dot segments, encoded characters, path parameters, extensions, wildcards, and suffixes. |
| **Original-route headers** | `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Uri`, and `X-Original-Uri`. |
| **Proxy and host trust** | Forwarded IP and host headers, loopback values, `Host: localhost`, and related combinations. |
| **Navigation trust** | Trusted `Referer` values supplied by the user. |
| **Methods** | GET, HEAD, OPTIONS, method override, and optional POST, PUT, or PATCH variations. |

## How It Confirms a Result

403Bypasser sends the denied request twice, sends an ordinary root-page carrier control twice, and then sends every selected variation twice.

A candidate is considered only when both responses agree and either return 2xx or match a supplied success marker. Any failure marker disqualifies it. Header variations routed through `/` must also differ from the ordinary root response, which prevents a public homepage from looking like protected content.

Path-only 2xx results remain tentative unless a supplied success marker proves that the protected resource was reached. Findings retain the two denied baseline exchanges and both candidate exchanges as evidence.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `success_markers` | Empty | Provide text that appears only in the protected response. Strongly recommended for path variations and soft-error applications. |
| `failure_markers` | Empty | Exclude login, denial, or generic error pages that return an allowed-looking status. |
| `referer_values` | Empty | Test pages the application may trust as navigation sources. |
| `include_not_found` | `false` | Include a known `404` response; any resulting finding is capped at medium severity. |
| `allow_state_changes` | `false` | Replay an unsafe base request or include POST, PUT, and PATCH variations. |
| `max_variants` | `50` | Raise or lower the number of variations, from 1 to 100. Each variation is sent twice. |

## Current Limits

- It tests one known endpoint and one saved request context at a time; it does not crawl for denied routes or compare different users.
- Success and failure markers are matched against response bodies only; they cannot match `Location` or other response headers.
- Highly volatile responses may not repeat closely enough to confirm, while generic success pages need good markers to avoid misleading results.
