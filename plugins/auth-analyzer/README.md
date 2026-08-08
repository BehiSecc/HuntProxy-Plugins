# AuthAnalyzer

AuthAnalyzer replays the selected saved request shapes with a primary identity,
a secondary identity, and (by default) no identity. It strips the captured
Cookie and Authorization values before applying each supplied identity, so the
tests do not accidentally combine sessions. Domain patterns and explicit
exchange IDs bound the run.

Use read-only requests by default. Set `allow_state_changes=true` only for
authorized workflows whose side effects are understood. Findings distinguish
cross-user response equivalence, anonymous access, and reproducible identity-
dependent denied/allowed transitions. Response comparison normalizes volatile
tokens and supports target-specific `ignore_patterns`.

