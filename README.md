# HuntProxy first-party plugins

This repository contains HuntProxy's maintained, agent-oriented security
extensions. Extensions describe a small set of named actions. HuntProxy owns
network I/O, scope enforcement, credentials, rate limits, cancellation,
history, evidence, and findings.

The initial pack is intentionally focused on tests that an agent can invoke
without adding more UI to HuntProxy:

- ParamFinder
- AuthAnalyzer
- Request Smuggler
- Racer
- 403Bypasser
- JWTAnalyzer
- CacheAnalyzer
- CSRFAnalyzer
- UploadAnalyzer
- IpRotate

Enabled manifests have runnable implementations and offline unit coverage.
Disabled manifests, if any, are specifications visible to development tooling
and must not be advertised as runnable. Enable an extension only after its
implementation, isolated tests, local integration tests, safety review, and
resource-limit tests all pass.

## Repository layout

```text
plugins/<id>/plugin.json       Versioned manifest and agent action schemas
plugins/<id>/README.md         Scope, behavior, and completion criteria
schemas/plugin-manifest-v1.json
docs/architecture.md
docs/upstream-audit.md
tests/validate-manifests.mjs
```

Run `npm test` to validate all manifests using only Node.js built-ins.

## Install and run

For a normal installation, copy the immediate children of `plugins/` into
`~/.huntproxy/plugins/` and restart HuntProxy. During development, point
HuntProxy directly at this checkout in `~/.huntproxy/config.toml`:

```toml
plugin_dir = "/home/administrator/HuntProxy-Plugins/plugins"
```

Agents discover and run extensions through HuntProxy's MCP tools:

```text
extension_list
  -> extension_describe(plugin_id)
  -> extension_run(project_id, plugin_id, action, base_exchange_id, input)
  -> job_status(job_id) / job_results(job_id) / job_cancel(job_id)
```

No extension runs automatically. Start from a saved exchange in the intended
project, inspect the selected action's input schema, and supply any explicit
safety acknowledgement it requires. Every generated request is saved in
HuntProxy History with `plugin`, the extension name, and `plugin:<id>` labels.

Packages are integrity-pinned by SHA-256. The current host does not have a
publisher-signature trust store. Request Smuggler intentionally targets the
host's exact HTTP/1 capabilities; malformed HTTP/2 and downgrade/tunneling
families are not claimed. Racer supports semantic parallel dispatch and exact
HTTP/1 final-byte synchronization; true HTTP/2 single-packet release is
reported as unsupported without fallback.
