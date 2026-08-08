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
