# AuthAnalyzer

Use `scan` only with two non-empty, distinct identity sets. It compares those
identities and can optionally add an anonymous control.

Use `anonymous_audit` when a saved request is already known to represent a
protected resource. It requires `confirm_expected_protected=true` and sends
only anonymous requests, so its labels never imply identities that were not
actually supplied. If the target issues a guest-session or affinity cookie,
pass it as `anonymous_context`; base credentials are still removed.
