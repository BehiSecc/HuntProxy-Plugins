# How HuntProxy Plugins Work

A HuntProxy plugin turns a focused testing idea into a workflow an AI agent can inspect and run. The plugin decides what to test and how to interpret responses; HuntProxy owns network execution, project storage, scope and limit enforcement, and evidence persistence. Access to credential-bearing context is capability-gated.

Building your first plugin? Start with [Create a HuntProxy Plugin](writing-plugins.md); use [Plugin API v1](plugin-api-v1.md) for exact fields and operation shapes.

```text
AI agent
   │
   ▼
Plugin action
   │
   ├─ plan(input, context)
   │        │
   │        ▼
   │   HuntProxy host
   │   ├─ validates capabilities and limits
   │   ├─ sends the planned requests
   │   ├─ saves generated HTTP exchanges in History
   │   └─ returns bounded observations
   │        │
   └─ analyze(input, observations, context)
            │
            ▼
       Results and evidence-backed findings
```

## The Boundary

| Plugin JavaScript | HuntProxy Host |
| --- | --- |
| Describes agent-visible actions and their inputs. | Loads and verifies plugin packages. |
| Validates action input inside `plan()`. | Builds the project and saved-request context. |
| Returns bounded operations for HuntProxy to perform. | Checks capabilities, scope, limits, and request counts. |
| Correlates observations and decides what they mean. | Executes requests, browser probes, races, and specialized host actions. |
| Returns diagnostics and reproducible findings. | Saves History exchanges and persists valid findings. |

Plugin code does not receive filesystem, process, socket, database, or direct HTTP APIs. It cannot call `fetch()` or load Node.js packages. Verified resource files are passed to it as strings in `context.resources`; identity selectors and private workflow values are resolved by the host.

The AI agent and user choose the project, saved requests, action, and inputs; preview the plan; start or cancel the job; and review the result against the application's intended behavior.

QuickJS is a restricted runtime inside the HuntProxy process, not a separate operating-system sandbox.

This boundary keeps every network action visible, cancellable, bounded, and connected to evidence.

## A Plugin Job From Start to Finish

1. **Discovery** — HuntProxy reads each immediate child of `plugin_dir`, validates `plugin.json`, verifies the entrypoint and resource digests, and records rejected-package issues.
2. **Description** — The agent can inspect the plugin's actions, input schemas, capabilities, and effective limits before running anything.
3. **Preview** — HuntProxy runs the real `plan()` function without executing its operations. The agent sees the planned request count and any plugin-supplied preview metadata. Because no requests are sent, preview does not prove that every planned URL will pass execution-time scope checks.
4. **Planning** — For a real job, HuntProxy builds the context and calls `plan(input, context)` in a fresh QuickJS environment.
5. **Execution** — HuntProxy validates the returned plan, performs its operations, and saves the resulting exchanges.
6. **Analysis** — A separate QuickJS environment calls `analyze(input, observations, context)`.
7. **Persistence** — HuntProxy returns the plugin result and saves findings that contain valid same-project evidence.

`plan()` and `analyze()` are synchronous and JSON-only. They run in separate environments, so globals do not survive between stages and `plan.result` is not passed into `analyze()`. Plugins rebuild analysis state from the original input, context, and stable operation IDs.

## Capabilities, Not Direct Access

A capability permits a specific family of host-owned operations:

| Capability | Host Operations |
| --- | --- |
| `http.semantic` | Normal HTTP requests and ordered private workflows. |
| `http.raw` | Raw HTTP/1, barriered HTTP/1 groups, and ordered HTTP/2 streams. |
| `http.race` | Parallel, last-byte, and HTTP/2 synchronized race groups. |
| `identity.use` | Managed identity selectors and bounded unredacted saved-request context. |
| `page.discover` | Passive, bounded same-origin resource candidates from a saved response. |
| `browser.csrf` | An isolated Chromium flow for supported cross-site GET and form submissions. |
| `aws.api_gateway` | IpRotate's bounded API Gateway lifecycle actions. |

Capabilities belong to the manifest. HuntProxy checks every planned operation against them before execution. An action's `required_capabilities` helps discovery but does not replace the manifest-level boundary.

Every network operation is checked against project scope when it executes. Without explicit host patterns, a base-exchange job is pinned to that exchange's host; a job without a base exchange is pinned to the project's target host. Additional hosts require explicit project scope configuration.

## Requests, Identities, and Private Values

A normal plugin sees a redacted base-exchange summary: method, URL, presented headers, lengths, hashes, and bounded previews. Additional context is exposed only when the manifest declares the matching capability:

- `identity.use` can expose bounded unredacted base-request headers and body, which may contain credentials. It also permits opaque named-profile or cookie-file selectors whose cookie bytes are resolved host-side.
- `http.raw` can provide a bounded raw base request for byte-oriented tests; those bytes may also contain credentials.
- `page.discover` can provide passive same-origin resource candidates extracted from the saved response.

Identity selectors are resolved once by HuntProxy and applied without copying cookie bytes into plugin output. Inline cookies or authorization headers supplied directly in action input are visible to plugin JavaScript; only named-profile and cookie-file selectors keep those values out of the JavaScript context.

Ordered `http_workflow` and supported race validations can extract values host-side and substitute them into later requests. Their values do not enter observations or job results; observations may expose only the extracted names.

Plugin-authored output must still avoid passwords, cookies, tokens, complete authenticated requests, and private extracts. HuntProxy redacts sensitive-shaped output keys and known sensitive header values from the selected base request, but it cannot recognize every transformed or relabeled secret.

## Limits and Cancellation

Each manifest requests ceilings for job time, JavaScript stage time, operations, concurrency, and memory. HuntProxy clamps them to host ceilings and further applies project concurrency and request-rate limits.

`max_operations` counts actual network work, not just top-level plan entries. Workflow steps, raw-group members, HTTP/2 streams, race requests, and AWS regions all count. Parallel execution is the default; dependent top-level operations must request sequential execution.

Response bodies, analysis payloads, results, candidate lists, and retained jobs are bounded. When a body cannot be included completely, the observation keeps proof metadata and marks the body truncated or omitted. Plugins must treat incomplete searches as inconclusive rather than negative.

Cancellation stops further scheduling and signals in-flight host operations to stop. Up to four plugin jobs run concurrently across the host.

## History and Evidence

Generated HTTP exchanges are saved in History and associated with the plugin job. Ordinary semantic, raw, workflow, and race requests also receive plugin and operation labels. HuntProxy collects evidence IDs before analysis begins, so they remain recoverable even when analysis fails.

A finding is accepted only when it has a title and at least one evidence exchange from the same project. Negative, failed, or ambiguous checks belong in the plugin result, not in findings.

Captured exchanges and accepted findings are durable project data. Detailed job results, status, and resumable analysis checkpoints are bounded in-memory state and should be collected before restart.

## Package Integrity and Reloading

Each plugin is an immediate child of the configured [`plugin_dir`](plugin-api-v1.md#package-contract). Its manifest declares an exact SHA-256 digest for `index.js` and every resource. HuntProxy rejects unreadable paths, digest mismatches, invalid manifests, duplicate plugin IDs, and unsupported packages; [`extension_list`](plugin-api-v1.md#agent-and-job-flow) exposes load issues to the agent.

SHA-256 shows that the installed files match the manifest; it does not verify who published them. HuntProxy does not currently provide a publisher-signature trust store.

Disabled plugins may still be validated and inspected as packages, but they cannot run. Plugins are loaded when HuntProxy starts, so manifest, entrypoint, resource, or digest changes require a daemon restart.

## Related Guides

- [Create a HuntProxy Plugin](writing-plugins.md) walks through the first plugin from copy to real job.
- [Plugin API v1](plugin-api-v1.md) is the complete package, runtime, operation, and result reference.
