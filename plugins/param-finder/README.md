# ParamFinder

`scan` starts with two controls, screens candidate names in bounded buckets,
then returns a `follow_up` input for individual two-request confirmation. The
calling agent should immediately run that follow-up and present the confirmed
findings, rather than treating bucket hits as findings. It
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
bounded 64-name buckets so late wordlist entries remain covered;
`planned_operation_count` and `truncated` expose any caller request cap.
