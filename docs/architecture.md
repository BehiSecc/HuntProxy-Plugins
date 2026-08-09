# Extension pack architecture

## Boundary

An extension decides what to test and how to interpret results. It does not
open sockets, read HuntProxy's database, handle cookies, or write findings
directly. Those operations remain host capabilities so every generated request
is scope-checked, cancellable, rate-limited, and recorded with the tags
`plugin` and the extension ID.

```text
agent -> extension action -> HuntProxy job
                             |-- semantic/raw/race transport
                             |-- bounded host-owned AWS Gateway lifecycle
                             |-- response comparison
                             |-- history + evidence
                             `-- structured findings
```

## Manifest v1

Each `plugin.json` supplies stable discovery metadata, actions with JSON input
schemas, requested host capabilities, and conservative resource ceilings.
`enabled` is part of the installation contract. Disabled entries remain useful
for development and packaging validation, but the host must not execute them.

Disabled manifests still contain a valid entrypoint and its SHA-256 digest so
packaging, integrity checks, and discovery exercise the real host contract.
The classic JavaScript entrypoint assigns `globalThis.HuntProxyPlugin` with
`plan(input, context)` and `analyze(input, observations, context)` methods.
Only the host performs planned operations; the sandbox exposes no direct
filesystem, network, or process access.

## Safety and performance invariants

- Nothing runs merely because a plugin is installed.
- Every active action requires an explicit invocation and remains in project
  scope unless the user provides an authorized override.
- The host enforces per-job request, concurrency, wall-clock, response-body,
  and memory limits; a plugin may request lower limits but not raise them.
- Potentially destructive upload payloads, denial-of-service payloads, and
  unbounded brute force are excluded from the default pack.
- Authentication material may come from the selected saved exchange or from
  transient action input. It is never copied into manifests or findings, and
  the host redacts sensitive result fields and known saved-request secrets.
- Raw desynchronization and race transports are explicit privileged
  capabilities and cannot be synthesized through ordinary semantic HTTP.
- IpRotate's AWS credentials are read by its host capability from the local
  plugin credential file and never enter JavaScript context or job output.
- Cancellation must stop scheduling immediately and close owned connections.
- The host caps simultaneously active jobs and retains only a bounded set of
  completed in-memory results.

## Result contract

Actions ultimately return a job ID. Completed jobs expose progress, errors,
generated exchange IDs, and zero or more findings. A finding should contain a
title, severity, confidence, explanation, remediation, and evidence exchange
IDs. A negative result is not a finding.
