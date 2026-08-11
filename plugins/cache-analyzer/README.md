# CacheAnalyzer

`scan` tests common unkeyed headers/query inputs and cache-deception path
variants. It uses a caller-generated marker, cache-busted URLs, clean follow-up
requests, anonymous controls, and repeat confirmation. Operations must execute
sequentially, so this manifest fixes concurrency at one.

Cookie poisoning is opt-in through `cookie_names` or `use_cookie_wordlist`.
Each candidate is poisoned once and then checked twice with a distinct clean
value on the same cache key. Authentication, session, token, and CSRF cookie
names additionally require `allow_sensitive_cookie_mutation=true`.

The action requires `allow_cache_side_effects=true`: even isolated tests can
create cache entries. Cache confidence uses header values rather than header
presence: positive `Age`, `X-Cache`, `CF-Cache-Status`, `X-Cache-Hits`, or
`Cache-Status` evidence can establish a hit, while explicit misses,
`Cache-Control: no-store/private`, and `Vary: *` cannot upgrade a
mutation-only result to firm. Exact marker persistence remains independent
positive evidence.

Broad scans can produce more than a thousand observations. CacheAnalyzer uses
a bounded 10-second JavaScript-stage budget because HuntProxy must parse the
complete observation set before analysis; the global 2-second default is too
short for broad supported scans. Network execution remains bounded by the
separate action timeout and 2,000-operation limit.

The poisoning matrix also tests a bounded `X-Forwarded-Host` plus
`X-Forwarded-Scheme` pair. Supply additional two-to-four-header sets through
`header_combinations`; every set receives its own isolated cache key.
Explicit header templates are evaluated before built-in and bundled candidates,
matching the existing explicit-before-resource order for cookie candidates.
For a fixed `Header~value` template, the exact supplied value becomes the
persistence marker; `%s` templates continue to use the generated run marker.

Advanced request-shape oracles are opt-in. `parameter_cloaking` describes a
carrier, nested target, and delimiter; `fat_get_parameters` sends harmless form
markers in GET bodies. `full_query_oracle` deliberately compares a marked query
with the query-free URL and therefore additionally requires
`allow_shared_cache_key_tests=true`.
Literal cloaking delimiters remain literal on the wire; encoded delimiter
choices remain encoded so callers can test both parser behaviors explicitly.

Use `oracle_families` to run only named poisoning families, such as
`["full-query"]`; omit it to preserve the broad default scan. Confirmed
full-query collisions are persisted with the `full-query` subtype.
Its controls use a distinct path so they cannot pre-fill the shared query-free
cache key before the poison request. Cloaking and fat-GET controls use the same
isolation because cache parsers may ignore ordinary query busters. Full-query, cookie, cloaking, and fat-GET
findings require the unique poison marker to persist; response-difference
fallbacks are limited to header/query probes with comparable control URLs.
Those comparable probes first request a separately cache-busted clean URL,
then require the poison response and two clean requests to reproduce a change
that was absent before poisoning. The pre-poison control never fills the key
under test when the cache keys the buster as intended; if the cache ignores the
buster, the control can prefill the entry and cause a false negative. Whole
probe groups are capped to the manifest's 2,000-operation limit, so a scan is
never truncated in the middle of a confirmation sequence.
When merely saving the target request would fill a shared cache key, save any
harmless request on the same origin and pass the untouched endpoint through
`target_url`; cross-origin overrides are rejected.
For targets that stay warm, opt into bounded `poison_attempts` and
`poison_interval_ms`. Retries run sequentially before clean confirmation, and
the finding cites the retry whose response carries the unique marker. Defaults
remain one attempt and no extra delay.
Strict caches may reject any added query buster. In that case,
`shared_header_cache_key_oracle=true` preserves the exact target URL, isolates
the controls on another path, requires `allow_shared_cache_key_tests=true`, and
accepts only persisted-marker evidence.

Deception mode covers appended static suffixes plus both sides of encoded path
normalization: static-prefix traversal toward the private path, and private
path plus a delimiter/traversal toward a static directory or exact cached
filename. Candidate directories, filenames, and delimiters stay bounded and
caller-configurable.

`url_normalization_oracle` uses raw HTTP/1 to poison two unique paths containing
harmless angle-bracket markers, then requests each browser-encoded equivalent
twice. It requires `allow_shared_cache_key_tests=true` and reports only when
both independent raw/encoded cache-key collisions reproduce exactly.
