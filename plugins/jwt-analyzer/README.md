# JWTAnalyzer

JWTAnalyzer finds a compact JWT in a saved request, reviews its header, claim names, and expiration metadata offline, checks HS256 against a bounded weak-secret list, and can replay selected mutations to see whether the application accepts them.

A saved base exchange is always required, even when you provide a token or replay URL manually. It supplies the request shape, session context, and finding evidence.

## Start With Passive Analysis

By default, JWTAnalyzer sends no network requests. It looks for a three-part token in a Bearer Authorization header or Cookie and reports:

- `alg=none` tokens;
- missing or expired `exp` claims;
- remote `jku` or `x5u` key references; and
- HS256 signatures that match the bounded weak-secret list.

These are review signals from the captured token. A weak-secret match is verified cryptographically, while claim and remote-key observations do not by themselves prove that the server accepts an attack.

## Example Prompts

Start with an offline review:

```text
Use HuntProxy MCP. Run JWTAnalyzer passively on exchange 42. Show me the
algorithm, claim names, expiration issues, remote key references, and whether its
HS256 signature matches the bounded weak-secret list. Do not send mutations.
```

Then run a bounded active check when needed:

```text
Actively test the JWT from exchange 42 with the default invalid-token
mutations. Replay every variant twice, compare it with two original-token
controls, and show only stable acceptance results with their exchange IDs.
```

## Passive and Active Coverage

| Mode | What It Checks |
| --- | --- |
| **Passive** | Algorithm, expiration metadata, remote key references, and weak HS256 secrets. No requests are sent. |
| **Default active** | `none`, invalid signature, missing signature, expired claim, missing expiration, weak-HMAC proof, and KID path behavior. |
| **Specialist active** | Empty HMAC, algorithm confusion, embedded JWK, JKU, X5U, and externally prepared proof tokens when explicitly configured. |

The weak-HMAC proof mutation is generated only when an HS256 secret is recovered and `target_subject` or `claim_overrides` changes a claim. Embedded JWK can use the bundled test key. JKU requires you to host the bundled JWKS at `jku_url`; X5U requires a prepared token from an external key workflow.

## How It Confirms a Result

An active run sends the original token twice and every generated variation twice.

Without a custom success oracle, both mutated responses must be stable, return 2xx or 3xx, and match the repeated authenticated baseline after common volatile values are normalized.

With `success`, both mutated responses must match the supplied status, header, body, redirect, or JSON checks while both original-token controls do not. This mode is useful when proving that a modified claim gains a new privilege or outcome rather than merely preserving the old session.

Weak secrets are checked offline and never returned in plugin results.

## Useful Options

| Option | Default | When to Use It |
| --- | ---: | --- |
| `active` | `false` | Send repeated network validation probes. Leave false for offline analysis. |
| `tests` | Common default set | Select active mutation families, including specialist key-selection tests. |
| `max_secrets` | `2000` | Bound caller-supplied and bundled HS256 candidates, up to 5,000. |
| `target_subject` / `claim_overrides` | Empty | Create a meaningful correctly signed weak-HMAC or configured specialist proof token. |
| `server_public_key` | Empty | Supply the exact key bytes for an algorithm-confusion test. |
| `jku_url` | Empty | Point to a caller-hosted copy of the bundled RSA test JWKS. |
| `prebuilt_tokens` | Empty | Supply externally prepared embedded-JWK, JKU, or X5U proof tokens. |
| `target_url` | Saved URL | Replay against another in-scope URL while still using the required base exchange. |
| `success` | Empty | Define a precise specialist-token success oracle. |
| `similarity_threshold` | `0.92` | Set normalized body similarity for baseline comparison. |
| `ignore_patterns` | Empty | Remove target-specific volatile response content before comparison. |

## Current Limits

- Automatic discovery covers compact three-part JWTs in Bearer Authorization and Cookie headers only; it does not cover query/body tokens, JWE, nested JWTs, WebSockets, or non-HTTP flows.
- Weak-key recovery and signing support HS256, not HS384 or HS512.
- Passive analysis does not evaluate `iss`, `aud`, `nbf`, `iat`, token type, or application-specific claim meaning.
- `expired` and `no_exp` are correctly re-signed only after recovering an HS256 weak secret. With an asymmetric or unknown key, they retain the old signature, so acceptance proves a broader validation failure rather than expiry handling specifically.
- An explicit `input.token` is replayed as Bearer Authorization. On a Cookie-JWT base request it does not remove the inherited JWT cookie, so prefer automatic Cookie extraction.
- KID testing uses one path/empty-HMAC variation rather than a broad injection set.
- Remote key references are reported as signals; the plugin does not host a JWKS or prove that an attacker-controlled key is trusted automatically.
