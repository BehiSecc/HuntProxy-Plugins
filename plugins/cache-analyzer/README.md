# CacheAnalyzer

`scan` tests common unkeyed headers/query inputs and cache-deception path
variants. It uses a caller-generated marker, cache-busted URLs, clean follow-up
requests, anonymous controls, and repeat confirmation. Operations must execute
sequentially, so this manifest fixes concurrency at one.

The action requires `allow_cache_side_effects=true`: even isolated tests can
create cache entries. Findings without recognizable cache headers are marked
tentative.
