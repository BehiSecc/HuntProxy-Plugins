# ParamFinder

`scan` starts with two controls and screens candidate names in bounded buckets.
Every result may return a `follow_up`; the calling agent should keep running it
until it becomes `null`. Changed buckets are confirmed before that chain resumes
any remaining screen pages. Only complete test groups are admitted to a page,
so request budgets cannot split a differential repeat or poison-clean pair. It
supports query, header, cookie, and top-level JSON/form body parameters. Cookie
and body changes are applied host-side to the saved request, so authentication
values never enter plugin input or output.

Query and header screening also uses an isolated poison-clean cache-key oracle.
Each bucket receives its own keyed cache buster and unique value; the clean
request reuses only that cache buster. A parameter is reported as unkeyed only
when its exact value persists into clean responses in two independent trials.
This catches cache-key omissions without treating ordinary URL reflection as a
hidden-parameter response differential.

Candidate words combine small safe defaults, caller-provided and harvested
words, and the vendored Param Miner resources exposed by the host. Response
changes are never reported from screening alone; only stable confirmation can
produce a finding.

Supplied and harvested names are ordered first, followed by built-in
high-signal names and the complete bundled resources. Screening defaults to
bounded 64-name buckets. Deterministic cursors continue late wordlist entries
across bounded jobs; candidate signatures reject continuations if detection
settings, candidate order, or host resources changed. Phase-scoped `coverage`,
workflow-level `workflow_complete`, `request_budget_exhausted`, and
`candidate_word_limit_reached` distinguish job pagination from a word cap.
Cache-dependent operations execute sequentially so poison always precedes clean.
Plan results expose counts plus only a small prioritized candidate sample; the
full bundled resources stay host-side and are not duplicated into job output.
