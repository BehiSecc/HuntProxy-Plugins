# Write a HuntProxy plugin

A plugin decides what to test and how to interpret the responses. HuntProxy
performs the network requests, enforces project scope and limits, saves every
exchange, and persists findings.

```text
plan(input, context) -> HuntProxy executes operations -> analyze(input, observations, context)
```

Plugins are synchronous JavaScript running in QuickJS. They return plain JSON;
they cannot open sockets, read files, start processes, use Node modules, or call
`fetch()` directly.

## Start from the example

First check the untouched example, then copy it and give it a new directory and
ID:

```bash
node scripts/validate-plugin.mjs examples/minimal-plugin
node examples/minimal-plugin/test.mjs
cp -R examples/minimal-plugin examples/my-plugin
```

Edit `plugin.json`, `index.js`, and `test.mjs` for the new behavior, then update
the entrypoint digest:

```bash
sha256sum examples/my-plugin/index.js
```

Paste that digest into `entrypoint_sha256` and check the package:

```bash
node scripts/validate-plugin.mjs examples/my-plugin
node examples/my-plugin/test.mjs
```

The generic checker validates packaging and exports. Each plugin still needs
its own tests for action inputs, planned operations, and analysis behavior.
Node's `vm` preflight is a correctness check, not a security boundary or an
exact QuickJS replacement; only run it on code you have reviewed. A real
HuntProxy load and job remain authoritative.

## Package layout

```text
my-plugin/
  plugin.json       Discovery, capabilities, limits, actions, and digests
  index.js          plan() and analyze()
  README.md         Optional plugin-specific usage and limitations
  resources/        Optional UTF-8 wordlists or templates
```

The important manifest fields are:

| Field | Meaning |
|---|---|
| `id`, `name`, `version` | Stable package identity |
| `enabled` | Installed plugins can only run when this is `true` |
| `entrypoint`, `entrypoint_sha256` | JavaScript file and its exact SHA-256 |
| `capabilities` | Host operations the package may request |
| `limits` | Conservative job, request, concurrency, and memory ceilings |
| `actions` | Agent-visible actions and their input schemas |

Use an action's `input_schema` to help agents form valid calls. HuntProxy does
not currently apply that schema before `plan()`, so `plan()` must also validate
required and safety-sensitive input and throw a short, useful `Error`.

## JavaScript entrypoint

The entrypoint must export two synchronous functions:

```js
globalThis.HuntProxyPlugin = {
  plan: function (input, context) {
    return { operations: [], result: {} };
  },
  analyze: function (input, observations, context) {
    return { findings: [], result: {} };
  }
};
```

`plan()` returns bounded host operations. `analyze()` correlates observations
by their unique `id`; parallel observations are not guaranteed to remain in
plan order. The two stages use separate QuickJS contexts, so globals do not
carry between them. `plan.result` is included in the final job result but is
not passed to `analyze()`.

The minimal example uses one semantic replay:

```js
{
  id: "replay",
  type: "http_request",
  base_exchange_id: context.base_exchange.exchange_id
}
```

See [Plugin API v1](plugin-api-v1.md) for contexts, observations, findings,
capabilities, limits, and advanced operation examples.

## Install and run

Copy the plugin directory directly beneath HuntProxy's configured
`plugin_dir`, or point development configuration at a directory containing the
plugin as an immediate child:

```toml
plugin_dir = "/path/to/HuntProxy-Plugins/examples"
```

Restart HuntProxy after changing a manifest, entrypoint, resource, or digest.
Then use the normal MCP flow:

```text
extension_list
  -> extension_describe("my-plugin")
  -> extension_run(project_id, "my-plugin", action, base_exchange_id, input)
  -> job_status(job_id) / job_results(job_id)
```

Action fields belong inside `input`. A saved `base_exchange_id` supplies the
request shape without copying session secrets into the action input.

## Findings

Return a finding only for a positive, reproducible result. Every finding needs
a title and at least one saved exchange from the same project:

```js
{
  title: "Descriptive issue title",
  severity: "high",
  confidence: "firm",
  explanation: "What was reproduced and why it matters.",
  remediation: "How to fix it.",
  evidence_exchange_ids: [observation.exchange_id],
  metadata: { variant: "example" }
}
```

Never place passwords, cookies, tokens, private workflow extracts, or complete
raw authenticated requests in results, errors, metadata, or findings.

## Before sharing

- Keep operation IDs unique and stable.
- Declare every capability used by a planned operation.
- Use `execution: "sequential"` for dependent operations; parallel is default.
- Check `{ id, error }` observations instead of assuming every request worked.
- Keep generated URLs in project scope and preserve harmless defaults.
- Bound candidate lists, repeats, response processing, and result size.
- Test empty, invalid, error, timeout, and negative-result paths.
- Update every changed entrypoint or resource digest.
- Run the generic validator, the plugin's tests, and one real HuntProxy job.

## Common problems

| Symptom | Check |
|---|---|
| Plugin is missing from `extension_list` | Daemon log, directory depth, JSON, paths, UTF-8, and SHA-256 |
| Plugin is listed but will not run | `enabled`, action name, and declared capabilities |
| Planning fails | Input validation, base exchange, operation shape, or request budget |
| Later operation runs too early | Use sequential execution or `http_workflow` |
| Analysis associates the wrong response | Map observations by operation ID, never array position |
| Response body is unavailable | Check `response_body_truncated` and use bounded previews/hashes |
| A finding is rejected | Supply a title and nonempty same-project evidence exchange IDs |

For complex implementations, use the maintained plugins as focused examples:
ParamFinder for semantic requests, CSRFAnalyzer for private workflows,
Request Smuggler for raw HTTP, Racer for synchronization, and IpRotate for the
specialized AWS capability.
