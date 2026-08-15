# Racer

Racer turns a race-condition hypothesis into a repeatable experiment. Give it the requests, define what success means, and it runs synchronized attempts while HuntProxy saves every response as evidence.

It is useful for duplicate-use and limit-overrun bugs, conflicting actions such as confirm versus cancel, object-state collisions, partial construction, and time-sensitive workflows.

Racer does not discover race candidates or infer the application's business rules. The agent needs a clear hypothesis and a way to recognize success.

## Define the Experiment

Before running Racer, decide:

- which request or requests should arrive together;
- how many copies of each request to send;
- what a successful action looks like;
- how many successes should normally be possible; and
- whether the application needs a reset before each attempt or a read-back afterward.

You need a HuntProxy project, saved exchanges or inline request shapes, and application state that can be consumed or reset.

Prefer semantic success checks over status codes alone. Many applications return `200 OK` for both accepted and rejected actions. Racer can match response headers, body text or regular expressions, JSON fields, and redirect locations.

## Example Prompt

```text
Use HuntProxy MCP. Run Racer on exchange 42 to test whether this coupon can be
applied twice. Race two copies with HTTP/1 last-byte synchronization for three
attempts. Treat “Coupon applied” as success and expect at most one success.
Run one sequential control first. Tell me the expected request volume before
running and wait for confirmation. Then show me the saved evidence for any
reproducible overrun.
```

For a multi-endpoint race, give the agent both saved exchanges—for example, confirm and cancel—and add a safe request that checks the final object state after every attempt.

## How a Run Works

```text
optional reset → sequential control
repeat: optional reset → synchronized requests → optional state check
compare attempts → save finding and evidence
```

The default control sends one copy of each distinct request sequentially. Each race attempt can then reuse saved exchanges or use inline request templates. Setup requests can reset state or acquire a fresh token, while validation requests can confirm the final result.

Use `{attempt}` in URLs, text bodies, or headers when each attempt needs a unique value. Setup and validation requests can also extract a bounded value from a body, header, or JSON response and reuse it privately later in the workflow.

## Synchronization Techniques

| Technique | How It Sends the Requests |
| --- | --- |
| `sequential` | Sends requests one after another for a baseline or diagnostic run. It does not produce a race finding. |
| `parallel` | Sends ordinary concurrent requests. Useful as a first pass, without packet-level synchronization. |
| `last_byte_sync` | Opens separate HTTP/1 connections, holds the final byte of each request, then releases them through one local barrier. This is the default. |
| `h2_single_packet` | Opens one HTTP/2 stream per request and releases every final DATA fragment in one TLS write. It requires one HTTPS origin with ALPN `h2` and never falls back to ordinary parallel requests. |

These techniques narrow the release window, but neither guarantees that every request reaches the application at exactly the same moment.

## How It Confirms a Result

Racer counts responses that match the declared semantic success conditions. When no predicate is provided, it falls back to `success_statuses` and then to any 2xx response, so explicit checks are strongly recommended.

An attempt qualifies only when its setup and validation checks pass and the run is non-sequential. HTTP/1 last-byte and HTTP/2 modes must also report a successful synchronized release.

If more responses succeed than `expected_max_successes`, one qualifying attempt produces a tentative result. Two or more qualifying attempts produce a firm finding. A response state that appears only during synchronized attempts remains tentative until the final application state is validated.

For strong evidence, add a read-back request that checks the resulting balance, object state, redemption count, or other business invariant after every attempt.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `technique` | `last_byte_sync` | Choose sequential, parallel, HTTP/1 last-byte, or HTTP/2 synchronized release. |
| `attempts` | `3` | Repeat the experiment from 1 to 20 times. Reproducible results receive higher confidence. |
| `control_mode` | `single_each` | Use `none` for one-shot actions or `full_group` when the complete race volume is safe to run sequentially. |
| `expected_max_successes` | `1` | Set the maximum number of successful actions the application should allow. |
| `requests[].copies` | `1` | Set the number of copies for each request shape. Always choose this explicitly on fragile endpoints. |
| `setup_requests` | Empty | Reset state or acquire per-attempt values before the synchronized group. |
| `validation_requests` | Empty | Read the final state after each attempt and strengthen the proof. |
| `timeout_ms` | `30000` | Bound the synchronized HTTP/1 or HTTP/2 request group. |

When using the legacy top-level `exchange_ids` form with only one saved exchange, the default is 20 copies rather than one. Always set the copy count explicitly, especially on fragile endpoints.

## Good to Know

- HTTP/1 last-byte mode reconstructs the saved request for synchronized delivery. For authenticated tests, start from an exchange that already contains the credentials and set `use_project_cookies: false` so split-write delivery does not try to inject managed cookies.
- Last-byte mode needs one connection per expanded request and cannot exceed the project's concurrency limit, which is 32 by default.
- HTTP/2 mode guarantees one TLS write for the final fragments, not one physical network packet.
- `time_sensitive` uniquely requires a private extract-and-compare validation chain. The other pattern names are labels and do not generate specialized probes automatically.

For the low-level host operation, see [RACE_GROUP_CONTRACT.md](RACE_GROUP_CONTRACT.md).
