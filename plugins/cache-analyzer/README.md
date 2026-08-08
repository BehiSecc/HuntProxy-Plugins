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
create cache entries. Findings without recognizable cache headers are marked
tentative.

The poisoning matrix also tests a bounded `X-Forwarded-Host` plus
`X-Forwarded-Scheme` pair. Supply additional two-to-four-header sets through
`header_combinations`; every set receives its own isolated cache key.

Advanced request-shape oracles are opt-in. `parameter_cloaking` describes a
carrier, nested target, and delimiter; `fat_get_parameters` sends harmless form
markers in GET bodies. `full_query_oracle` deliberately compares a marked query
with the query-free URL and therefore additionally requires
`allow_shared_cache_key_tests=true`.

Use `oracle_families` to run only named poisoning families, such as
`["full-query"]`; omit it to preserve the broad default scan. Confirmed
full-query collisions are persisted with the `full-query` subtype.

Deception mode covers appended static suffixes plus both sides of encoded path
normalization: static-prefix traversal toward the private path, and private
path plus a delimiter/traversal toward a static directory or exact cached
filename. Candidate directories, filenames, and delimiters stay bounded and
caller-configurable.

`url_normalization_oracle` uses raw HTTP/1 to poison two unique paths containing
harmless angle-bracket markers, then requests each browser-encoded equivalent
twice. It requires `allow_shared_cache_key_tests=true` and reports only when
both independent raw/encoded cache-key collisions reproduce exactly.
