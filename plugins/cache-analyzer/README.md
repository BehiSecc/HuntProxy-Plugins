# CacheAnalyzer

CacheAnalyzer profiles cache behavior, screens cache-key inputs, confirms only
candidate-specific persistence, and tests web cache deception. Every scan
requires `allow_cache_side_effects=true`.

## Scan modes and stages

`scan_mode` defaults to `full`.

- `light` directly confirms a short, high-yield set of forwarding, host,
  rewrite, and method headers plus the common forwarded-host/scheme
  combination. It does not load the long-tail header wordlist.
- `full` screens every eligible entry from the
  bundled header and parameter resources in bounded, independently marked
  groups. Copy `result.follow_up` into the next scan. The returned sequence is
  normally `discover -> screen -> confirm -> advanced`.

When the saved response references passive same-origin script or stylesheet
resources, the bounded `discover` phase profiles the saved URL plus up to 12
host-resolved targets. It requires a stable, nonempty 2xx response and an
explicit cache HIT. Two distinct query keys establish isolation; exact-URL fallback is
available only with `allow_shared_cache_key_tests=true`. Full carries at most
three eligible targets through the staged queue, while Light selects one. This
lets an uncacheable HTML shell lead the scan to a cacheable referenced
endpoint without automatically GETting flat application routes such as logout
or admin actions. Cross-origin and sensitive signed URLs are excluded by the
host. Supplying `target_url` explicitly skips automatic discovery. When no
cacheable target is proven, discovery returns `no_cacheable_target_found` and
does not spend the broad probing budget.

A screen page that cannot fit under the 2,000-operation limit returns another
screen follow-up with `screen_cursor` and accumulated candidates. Coverage is
never implied: every result reports generated, tested, deferred, and skipped
counts. Header values are type-aware (hostnames, IP addresses, schemes, ports,
paths, and methods) instead of sending one malformed value everywhere.

The confirm stage sends each attributed header or query parameter separately.
The advanced follow-up covers header combinations, non-sensitive cookies,
fat GET, parameter cloaking, full-query behavior, URL normalization, and
deception. It does not repeat the direct query probes already completed by
confirmation. Automatic cloaking uses bounded confirmed or screen-reflected
parameters as carriers with common or endpoint-derived targets; exact marker
persistence still gates findings. Fat-GET
also tests bounded parameter names that screening observed as reflected,
because a keyed query parameter can still be unkeyed in a GET body.

Full-query and URL-normalization probes can touch a shared cache key and remain
disabled unless `allow_shared_cache_key_tests=true`. The same acknowledgement
is required by `shared_header_cache_key_oracle=true`, which is intended for
strict caches that reject query cache busters. Parameter-cloaking probes also
use the profiled isolated `hp_cache_bust` key in addition to the candidate
carrier, preventing them from warming or colliding with the original public
entry. Their poison requests also request bounded `Cache-Control: no-cache`
revalidation and still reject a pre-existing HIT as proof.
The full-query poison request asks the cache to revalidate with
`Cache-Control: no-cache`; a pre-existing HIT is still rejected as proof.

## Evidence discipline

Each stage starts with credentialed and credential-free baselines plus a
two-key cache profile. The profile primes and repeats two distinct
`hp_cache_bust` values. `isolation_verified=true` requires key A to repeat as
a HIT, the first request for key B not to be a HIT, and key B to repeat as a
HIT. Cache-profile namespaces include the stage and screen cursor, preventing
earlier follow-ups from warming the later stage's profile keys.

A cache-poisoning finding is created only when all applicable checks pass:

1. The poison response contains the candidate-specific marker.
2. The marker-bearing poison response is not itself a cache HIT.
3. Two later clean requests to the exact same tested key contain that marker.
4. At least one clean response has explicit cache-HIT evidence.
5. An isolated probe also has a verified two-key cache profile. Explicitly
   acknowledged shared-key probes use their shared-key proof instead.

Response changes without the exact marker are returned only as bounded
`inconclusive_mutation_only` diagnostics. Marker persistence without cache or
isolation proof is also diagnostic and never becomes a persisted finding.
Marker search covers the complete captured response body and response headers,
not only the preview.
Deception equality uses full captured-body hashes or normalized full bodies;
matching previews alone cannot establish a private-response cache leak.

Cache evidence recognizes positive `Age`, `X-Cache`,
`CF-Cache-Status`, `X-Cache-Hits`, and `Cache-Status` values while
distinguishing misses, bypasses, `private`, `no-store`, and `Vary: *`.
All semantic operations declare either
`with_project_credentials` or `without_project_credentials`; credential-free
requests also tombstone Cookie and authorization headers. These labels express
the requested credential policy, not a claim that credentials were present on
the saved exchange.

Findings with the same endpoint, proof class, and marker-normalized confirmed
response fingerprint are merged. The retained finding includes
`supporting_variants`, `variant_count`, and bounded combined evidence.
The confirm follow-up also carries bounded root-cause identifiers into the
advanced stage, so an equivalent combination or advanced probe is suppressed
instead of being persisted as a second finding.

Coverage counts use `coverage_unit=candidate_inputs`; they are intentionally
different from network operation counts because screen requests batch multiple
candidates. Bounded diagnostic arrays include total and truncation fields.

## Operational notes

Operations execute sequentially because each poison/clean/confirm sequence is
order-sensitive. Network execution is capped at 2,000 operations and 15
minutes. Aggregation has a separate bounded 10-second JavaScript budget for
large captured bodies. Retry scheduling also caps cumulative planned delay at
10 minutes and reduces the selected variant count when necessary. The saved
base exchange must use GET or HEAD; the plugin does not replay state-changing
methods as part of cache discovery.

Use a harmless saved exchange on the same origin and pass `target_url` when
saving the target itself would warm a shared key. Cross-origin overrides are
rejected. Sensitive authentication/session cookie names still require an
explicit name and `allow_sensitive_cookie_mutation=true`.
