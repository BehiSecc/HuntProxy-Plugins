# ParamFinder

ParamFinder helps an AI agent discover hidden parameters and likely unkeyed cache parameters without sending one request for every word in a large list.

It screens names in batches, confirms interesting candidates individually, and carries the work across bounded follow-up jobs.

## Choose a Target

Use either:

- a saved exchange when the original method, body, cookies, authorization, or exact request shape matters; or
- an explicit `url` for an anonymous GET scan of query and header parameters.

Do not provide both. URL mode cannot test body or cookie parameters and removes sensitive headers such as Cookie, Authorization, Proxy-Authorization, and Host from its candidates.

## Example Prompt

```text
Use HuntProxy MCP. Run ParamFinder against exchange 42 for query and header
parameters. Include names harvested from this project's JavaScript, keep the
default cache-key checks enabled, and run every returned follow_up until the
workflow is complete. Show confirmed hidden parameters separately from likely
unkeyed cache parameters.
```

For a focused endpoint, ask the agent to prioritize a short supplied word list or lower `max_words` before expanding to the bundled resources.

## How the Workflow Progresses

| Stage | What Happens |
| --- | --- |
| **Screen** | Sends two baselines, tests names in buckets, and narrows changed groups. Query and header buckets also receive an isolated poison/clean cache check by default. |
| **Confirm** | Retests every narrowed name twice. Query and header names also receive two independent poison/clean cache-key trials. |
| **Resume** | Returns to remaining screen groups when confirmation interrupted a paginated scan. |

Run `result.follow_up` unchanged until it becomes `null` or `workflow_complete` is true. The continuation contains a target guard, candidate signature, namespace, and cursor; editing them can invalidate the chain.

## What It Covers

| Location | Support |
| --- | --- |
| **Query** | Saved exchanges and anonymous URL mode, with differential and cache-key checks. |
| **Header** | Saved exchanges and anonymous URL mode, with differential and cache-key checks. |
| **Body** | Saved exchanges only; top-level form and JSON parameters. |
| **Cookie** | Saved exchanges only; HuntProxy mutates candidate cookie parameters without exposing captured values to plugin output. |

Candidate names are prioritized from harvested words, caller-supplied words, high-signal defaults, and bundled Param Miner resources. Query and header are the default locations.

## How It Confirms a Result

A hidden-parameter finding requires the candidate to produce the same response change in two individual confirmation requests relative to two baselines. Stable baselines produce firm informational findings. When the baseline is unstable, body-only differences are suppressed and only a repeatable status change may remain tentative.

For a likely unkeyed query or header parameter, each of two trials receives a different isolated cache-buster key. For each key, the exact marker must appear in the poison response and then persist into its paired clean response.

Screening alone never creates findings.

## Useful Options

| Option | Default | What It Controls |
| --- | ---: | --- |
| `locations` | Query + header | Choose query, header, body, and/or cookie parameters. |
| `bucket_size` | `64` | Set how many names are screened together, from 2 to 64. |
| `max_words` | `100000` | Cap candidates per location after all word sources are combined. |
| `max_requests` | `500` | Set the per-job request budget. Only complete test groups are admitted. |
| `cache_bust` | `true` | Add a unique keyed query value so existing cache entries do not hide origin behavior. |
| `cache_key_tests` | `true` | Add poison/clean checks for query and header candidates. |
| `similarity_threshold` | `0.96` | Control normalized response-body comparison. |
| `ignore_patterns` | Empty | Remove target-specific volatile response text before comparison. |
| `words` / `harvested_words` | Empty | Add target-specific names ahead of defaults and bundled resources. |

## Current Limits

- URL mode is anonymous GET and supports query and header locations only.
- Body discovery is limited to top-level form and JSON fields; nested JSON and multipart fields are not mined automatically.
- A confirmed response change proves that a parameter affects the response, not that it is exploitable.
- The unkeyed signal proves repeated marker persistence but does not require explicit HIT headers or CacheAnalyzer's stronger cache-profile gates.
- Large word sources can require many follow-up jobs; coverage is complete only when the whole chain finishes.
