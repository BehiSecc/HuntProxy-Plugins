# Request Smuggler

Request Smuggler helps an AI agent find HTTP request desynchronization by sending bounded HTTP/1 and HTTP/2 probe sequences, then checking whether a harmless canary response leaks into later traffic.

It is built for confirmation, not guesswork. Most findings require a canary to be reproduced against clean controls; connection-state checks instead compare the same Host-bearing request directly and as the second request on one connection.

## Start With a Stable Request

Choose a harmless request from HuntProxy History. The plugin needs its exact raw bytes and uses the saved origin, path, and ordinary headers to build each probe.

Use an idempotent `probe_path` and a harmless canary path whose response is easy to distinguish from the normal page. Cookies and authorization are excluded by default; include them only when the target cannot be tested without authentication.

## Example Prompt

```text
Use HuntProxy MCP. Run Request Smuggler against exchange 42. Generate a unique
marker, set confirm_intrusive to true, keep authentication excluded, start with
three repeats, and report firm findings, tentative signals, and diagnostics
separately.
```

For a fragile target, ask the agent to test one or two families first, then expand only when the controls remain stable.

## What It Checks

| Group | Coverage |
| --- | --- |
| **HTTP/1 framing** | CL.TE, TE.CL, TE.TE variations, and CL.0 marker pipelines. |
| **0.CL** | Early-response connection pairs, header-hiding variations, and front-end rewrite offsets. |
| **Connection state** | Whether a Host-bearing request behaves differently when sent second on an established HTTP/1 connection. |
| **HTTP/2 downgrade** | H2.CL, H2.TE, and response-queue behavior using ordered HTTP/2 fields. |
| **HTTP/2 injection** | CRLF header-value injection and request splitting. |
| **HTTP/2 tunnelling** | Header-name and pseudo-path tunnelling with nested-response confirmation. |
| **Parser diagnostics** | Conflicting duplicate Content-Length, signed Content-Length, and HTTP/2 header-name Host injection. These signals are diagnostic-only. |
| **Pause-based CL.0** | An optional family that delays the remainder of a CL.0 request pipeline. |

## How It Confirms a Result

Before sending any ambiguous request, the plugin records the normal endpoint and canary twice and prepares clean controls for every selected technique. It then repeats each probe and sends fresh observer requests afterward, so contaminated traffic cannot become a later baseline.

Most firm findings require stable controls and reproducible downstream canary contamination. With the default five repeats, the canary must appear in at least three attempts while every standalone control stays clean. The connection-state family instead confirms that the same Host-bearing request changes only when it is sent second on an established connection.

With stable, distinct baselines and clean controls, exact canary contamination below that threshold is kept as tentative evidence. Timeouts, parser rejection, protocol errors, and response divergence without the canary remain diagnostics rather than vulnerabilities.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `marker` | Required | Generate a unique 8–32 character alphanumeric value for every run. |
| `confirm_intrusive` | Required | Must be `true` before the plugin plans the scan. |
| `families` | Broad scan | Limit testing to selected technique groups. The slow pause family is not included by default. |
| `repeats` | `5` | Choose 3–9 repetitions. More repeats improve confirmation but increase traffic. |
| `max_techniques` | `30` | Bound the selected framing variations. The default broad scan can schedule up to 633 requests. |
| `probe_path` | Saved path | Use a harmless, idempotent endpoint for the outer and observer requests. |
| `canary_path` | Unique missing path | Use a harmless path with a response clearly different from the probe response. |
| `include_auth` | `false` | Copy the saved Cookie and Authorization headers into raw probes. |
| `zero_cl_*` | Built-in bounds | Tune the 0.CL offset sweep, pair delay, and post-pair observers. |
| `pause_ms` | `61000` | Change the delay used only by the opt-in pause family. |

## Current Limits

- HTTP/2 checks require HTTPS with ALPN `h2`; they never silently fall back to HTTP/1.
- Browser-powered client-side desynchronization is not covered.
- The default 30-technique scan includes only part of the built-in 0.CL matrix. Run the `0_cl` family separately to cover all 26 built-in variants.
- Parser discrepancies alone are diagnostic. The plugin confirms a desynchronization primitive, not a victim-impact exploit chain.
- The plugin uses bounded built-in probe families; it does not accept arbitrary raw probe templates or cover every target-specific desynchronization technique.
