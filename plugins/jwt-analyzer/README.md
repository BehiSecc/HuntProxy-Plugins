# JWTAnalyzer

JWTAnalyzer locates a JWT in the captured Cookie or Authorization header,
performs passive claim/header checks, and can send repeated active validation
probes. It covers unsigned, missing/invalid signature, expiry, empty-HMAC, KID
path, bounded weak-HMAC, and explicitly configured algorithm-confusion tests.

Network probes are off by default. Set `active=true` only after confirming that
replaying the captured request and its JWT variants is safe for the target; an
omitted or false value performs passive/offline analysis without sending requests.

Weak HMAC candidates are verified offline; candidate secrets are never returned
in job results. When a key is verified, claim mutations are re-signed correctly.
Set `target_subject` or `claim_overrides` for a meaningful proof. Embedded JWK
tokens are signed natively with a bundled scanner-only RSA key. JKU uses that
same key when the caller explicitly supplies an in-scope `jku_url` hosting
`resources/rsa-test-jwks.json`; HuntProxy never hosts keys implicitly. X5U and
custom specialist tokens remain available through `prebuilt_tokens`.

Acceptance uses normalized decoded response bodies, so rotating CSRF tokens do
not hide an authenticated response. WebSocket JWT traffic is intentionally out
of scope.
