# JWTAnalyzer

JWTAnalyzer locates a JWT in the captured Cookie or Authorization header,
performs passive claim/header checks, and can send repeated active validation
probes. It covers unsigned, missing/invalid signature, expiry, empty-HMAC, KID
path, bounded weak-HMAC, and explicitly configured algorithm-confusion tests.

Weak HMAC candidates are verified offline; candidate secrets are never returned
in job results. When a key is verified, claim mutations are re-signed correctly.
Set `target_subject` or `claim_overrides` for a meaningful proof. Embedded JWK,
JKU, and X5U tests require a caller-supplied correctly signed `prebuilt_tokens`
value; the plugin does not generate or host attacker keys implicitly.

Acceptance uses normalized decoded response bodies, so rotating CSRF tokens do
not hide an authenticated response. WebSocket JWT traffic is intentionally out
of scope.

