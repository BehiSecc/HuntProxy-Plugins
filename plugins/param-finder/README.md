# ParamFinder

`scan` starts with two controls, screens candidate names in bounded buckets,
then returns a `follow_up` input for individual two-request confirmation. The
calling agent should immediately run that follow-up and present the confirmed
findings, rather than treating bucket hits as findings. It
supports query, header, cookie, and top-level JSON/form body parameters. Cookie
and body changes are applied host-side to the saved request, so authentication
values never enter plugin input or output.

Candidate words combine small safe defaults, caller-provided and harvested
words, and the vendored Param Miner resources exposed by the host. Response
changes are never reported from screening alone; only stable confirmation can
produce a finding.
