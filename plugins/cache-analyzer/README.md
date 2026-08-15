# CacheAnalyzer

CacheAnalyzer helps an AI agent find web cache poisoning, cache-key mistakes, and web cache deception without treating every changed response as a vulnerability.

It profiles the cache, narrows broad candidate lists, and keeps testing until a unique marker or private response is reproduced through clean cache hits.

## Start With a Useful Request

Choose a saved GET or HEAD exchange. For poisoning, use a stable endpoint that exposes cache behavior. For deception, use a request whose authenticated response is meaningfully different from its logged-out response.

Every run needs a unique 8–40 character alphanumeric `marker` and `allow_cache_side_effects: true`. If the saved page loaded same-origin scripts or styles, discovery can profile those resources and move testing to a cacheable target. You can also provide a same-origin `target_url` directly.

## Example Prompt

```text
Use HuntProxy MCP. Run CacheAnalyzer in full mode against exchange 42.
Generate a unique marker, set allow_cache_side_effects to true, keep shared-key
tests disabled, run every returned follow_up, and separate confirmed findings
from incomplete cache evidence.
```

Use `light` instead when you want a smaller high-yield header and deception check.

## How the Workflow Progresses

| Stage | What Happens |
| --- | --- |
| **Discover** | Profiles the saved URL and bounded same-origin resources, then selects one cacheable target in Light or up to three in Full. This stage runs when poisoning is included, no `target_url` is supplied, and extra page-discovered targets are available. |
| **Screen** | Full mode batches header and query candidates and keeps inputs whose unique markers survive a poison/clean pair. Screening never creates a finding. |
| **Confirm** | Retests narrowed headers and query parameters individually with fresh cache profiles and clean confirmation requests. Light mode starts here with a small header set. |
| **Advanced** | Full mode adds header combinations, non-sensitive cookies, full-query behavior, parameter cloaking, fat GET, URL normalization, and cache deception where applicable. |
| **Next target** | Continues the same workflow when discovery selected another cacheable resource. |

Always pass `result.follow_up` back unchanged until it becomes `null`. A large screen can return another screen page before confirmation, and Full continues into advanced analysis.

## What It Checks

- unkeyed headers, header combinations, query parameters, and cookies;
- full-query cache-key behavior;
- parameter cloaking and fat-GET discrepancies;
- URL normalization collisions; and
- web cache deception using static-looking suffixes, delimiters, and normalized paths.

## How It Confirms a Result

For cache poisoning, a firm finding requires the candidate marker in a fresh poison response and in two later clean requests to the exact tested key. Both clean responses must show explicit cache-HIT evidence, and the cache-buster profile must prove that the test key is isolated.

Shared-key probes replace isolation proof only when `allow_shared_cache_key_tests: true` is supplied. A changed response without the exact marker remains diagnostic. Deterministic scheme redirects are the narrow exception and must persist through two clean-HIT trials.

For cache deception, the plugin first proves that authenticated and logged-out baselines differ. It then requires an authenticated MISS at the crafted path followed by two credential-free HIT responses that reproduce the complete private representation. `private`, `no-store`, or `Vary: *` evidence overrides an apparent HIT.

## Useful Options

| Option | Default | What It Controls |
| --- | ---: | --- |
| `scan_mode` | `full` | Use `light` for a smaller high-yield workflow or `full` for wordlists and advanced families. |
| `modes` | Poisoning + deception | Run only one mode when the objective is already known. |
| `target_url` | Saved URL | Test a specific same-origin target and skip automatic discovery. |
| `oracle_families` | Broad set | Restrict poisoning to selected families. |
| `max_discovery_targets` | `12` | Bound same-origin resources profiled in addition to the saved URL. |
| `max_header_candidates` | Full `5000`, Light `40` | Cap candidate headers before staging and operation limits are applied. |
| `max_parameter_candidates` | `1000` | Cap query-parameter candidates used during screening. |
| `max_poison_variants` | `500` | Cap variants selected across the enabled families. |
| `allow_shared_cache_key_tests` | `false` | Enable exact/shared-key checks such as full-query and URL-normalization tests. |
| `poison_attempts` | `1` | Repeat poison requests for short-lived cache entries. |

Sensitive cookie names must be supplied explicitly with `allow_sensitive_cookie_mutation: true`.

## Current Limits

- Only saved GET and HEAD exchanges are accepted, and target overrides must remain on the same origin.
- Confirmed cache findings need recognizable HIT/MISS evidence such as `Age`, `X-Cache`, `CF-Cache-Status`, `X-Cache-Hits`, or `Cache-Status`.
- Discovery selects at most three eligible targets in Full and one in Light.
- Full mode can require several jobs when candidate groups do not fit within the 2,000-operation stage limit.
- Shared-key tests stay disabled until their separate option is enabled.
