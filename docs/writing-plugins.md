# Create a HuntProxy Plugin

A HuntProxy plugin gives an AI agent a repeatable way to test one security idea.

Your plugin decides what requests should be sent and what the responses mean. HuntProxy handles the network traffic, project boundaries, limits, History, and evidence.

```text
Agent input → plan() → HuntProxy sends and saves requests → analyze() → Results
```

Plugins are synchronous JavaScript running inside QuickJS. They cannot open sockets, read files, start processes, import Node.js packages, or call `fetch()` directly. Instead, they ask HuntProxy to perform bounded operations.

## Before You Start

You need:

- a working [HuntProxy](https://github.com/BehiSecc/HuntProxy) installation;
- this repository cloned locally; and
- Node.js 18 or newer for validation and tests.

Run the commands below from the root of the HuntProxy-Plugins repository. No `npm install` is needed: the validator and example tests use Node.js built-ins only.

Node.js is only used while developing the plugin. HuntProxy runs the finished plugin with its embedded QuickJS runtime.

## Start From the Working Example

Validate the example before changing it, then make a copy:

```bash
node scripts/validate-plugin.mjs examples/minimal-plugin
node examples/minimal-plugin/test.mjs
cp -R examples/minimal-plugin examples/my-plugin
```

Your plugin directory now contains:

```text
my-plugin/
├── plugin.json    What the plugin exposes and is allowed to do
├── index.js       How it plans requests and analyzes responses
└── test.mjs       Fast tests for the plugin's behavior
```

Update the copied identity in `plugin.json`. Mirror its new `plugin_id` and `plugin_version` in `test.mjs`; if you rename the action, update `action` there too. This prevents the new package from colliding with `minimal-plugin` while its stale test still appears to pass.

Add a `README.md` for usage and current limitations. Plugins may also include a `resources/` directory for UTF-8 wordlists or templates.

## 1. Describe the Plugin

Open `plugin.json` and change the identity, description, action, limits, and capabilities.

The fields you will use most are:

| Field | What It Means |
| --- | --- |
| `id`, `name`, `version` | The plugin's stable identity and release version. |
| `enabled` | Must be `true` before HuntProxy can run the plugin. |
| `capabilities` | The HuntProxy operations the plugin may request. |
| `limits` | Maximum job time, operations, concurrency, and memory. |
| `actions` | The tasks shown to the agent and the input each task accepts. |
| `actions[].requires_base_exchange` | Tells HuntProxy that an action cannot run without a saved request. |
| `entrypoint_sha256` | The SHA-256 digest of the exact `index.js` file. |

Most first plugins need only `http.semantic`, which allows normal HTTP requests and workflows. Add advanced capabilities only when the plugin actually uses them.

Make action descriptions concrete because the agent uses them to decide when and how to call the plugin. The copied `inspect` action already declares that it needs a saved request:

```json
"requires_base_exchange": true
```

Keep this field on any action that cannot run without a captured request.

The action's `input_schema` teaches the agent which fields are accepted, but HuntProxy does not currently validate that schema before JavaScript starts. Validate every required or bounded value again inside `plan()` and return short, useful errors.

See the [manifest schema](../schemas/plugin-manifest-v1.json) for the complete field contract.

## 2. Plan the Test

`plan()` receives the action input and project context, then returns the operations HuntProxy should perform.

```js
function plan(input, context) {
  if (context.action !== "inspect") {
    throw new Error("Unsupported action.");
  }

  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Input must be an object.");
  }

  if (Object.keys(input).length) {
    throw new Error("The inspect action does not accept input fields.");
  }

  if (!context.base_exchange) {
    throw new Error("Choose a saved request first.");
  }

  var method = String(context.base_exchange.method || "GET").toUpperCase();
  if (["GET", "HEAD", "OPTIONS"].indexOf(method) === -1) {
    throw new Error("This action only replays GET, HEAD, or OPTIONS requests.");
  }

  return {
    operations: [{
      id: "replay",
      type: "http_request",
      base_exchange_id: context.base_exchange.exchange_id,
      method: method,
      protocol: "auto"
    }],
    result: {
      source_exchange_id: context.base_exchange.exchange_id
    }
  };
}
```

Every operation needs a unique, stable `id`. HuntProxy uses it to label History entries and lets `analyze()` match a response to the request that produced it.

Operations run in parallel by default. Return `execution: "sequential"` when one top-level operation must finish before the next begins. Use `http_workflow` when later requests need values extracted privately from earlier responses.

## 3. Analyze the Responses

`analyze()` receives the completed observations. Parallel responses may arrive in a different order, so always find them by operation ID.

```js
function analyze(input, observations) {
  var replay = observations.find(function (item) {
    return item.id === "replay";
  }) || {};

  return {
    findings: [],
    result: {
      exchange_id: replay.exchange_id || null,
      status_code: replay.status_code == null ? null : replay.status_code,
      error: replay.error || null
    }
  };
}

globalThis.HuntProxyPlugin = {
  plan: plan,
  analyze: analyze
};
```

`plan()` and `analyze()` run in separate QuickJS contexts. Globals do not carry between them, and `plan.result` is returned to the caller rather than passed into `analyze()`.

Treat missing, failed, or skipped observations and observations with truncated or omitted bodies explicitly. A network error is a diagnostic result, not proof of a vulnerability.

## 4. Return Findings Only When You Have Proof

A positive, reproducible result can become a finding:

```js
{
  title: "Descriptive issue title",
  severity: "high",
  confidence: "firm",
  explanation: "What was reproduced and why it matters.",
  evidence_exchange_ids: [replay.exchange_id],
  metadata: { variant: "example" }
}
```

Every finding needs a title and at least one exchange saved in the same project. Negative or inconclusive results belong in `result`, not `findings`.

Never put cookies, tokens, passwords, private workflow extracts, or complete authenticated requests in results, errors, metadata, or findings.

## 5. Test and Validate

Update `test.mjs` so it covers:

- valid planning;
- missing or invalid input;
- the planned operations and request count;
- successful and failed observations; and
- positive, negative, and inconclusive analysis.

After changing `index.js`, calculate its new digest:

```bash
# Linux
sha256sum examples/my-plugin/index.js

# macOS
shasum -a 256 examples/my-plugin/index.js
```

Copy the digest into `entrypoint_sha256`, then run:

```bash
node scripts/validate-plugin.mjs examples/my-plugin
node examples/my-plugin/test.mjs
```

Resources have their own SHA-256 entries in `plugin.json`; update those after changing a resource file too.

The validator checks the manifest, paths, capabilities, size limits, digests, resources, and exported functions. It does not run your planner, fully enforce the advertised input schema, or exactly reproduce QuickJS. The plugin test checks behavior, and a real HuntProxy job is the final test.

## 6. Load and Try the Plugin

For a normal HuntProxy installation, copy the finished directory into the plugin folder:

```bash
mkdir -p "$HOME/.huntproxy/plugins"
cp -R examples/my-plugin "$HOME/.huntproxy/plugins/"
```

The resulting manifest should be at `~/.huntproxy/plugins/my-plugin/plugin.json`. Plugins must be immediate children of the configured plugin directory.

If you use `HUNTPROXY_DATA_DIR`, install the plugin beneath that directory's `plugins/` folder instead.

During development, you can point `~/.huntproxy/config.toml` at the directory containing your plugin:

```toml
plugin_dir = "/absolute/path/to/HuntProxy-Plugins/examples"
```

Use an absolute path; `~` is not expanded in this setting. Plugins load when the daemon starts. After changing a manifest, entrypoint, resource, or digest, run `HuntProxy stop`, then restart or reconnect your AI client. If you run `HuntProxy serve` manually, stop and relaunch it instead.

For the minimal plugin, create or select a project and capture a GET, HEAD, or OPTIONS request in History. Note its project and exchange IDs, then try the normal agent workflow:

```text
Use HuntProxy MCP. Confirm my-plugin is installed, describe its inspect action,
preview it on exchange 42 in project 1, then run it and show me the result.
```

Previewing runs the real planner without sending network requests, so it is the easiest way to catch unexpected request counts or missing inputs before a job starts.

## Before You Share It

- Keep operation IDs unique and stable.
- Declare every capability used by a planned operation.
- Keep request counts, repeats, candidate lists, and response processing bounded.
- Validate required and safety-sensitive action fields inside `plan()`.
- Match observations by ID, never by array position.
- Handle errors, missing responses, and truncated bodies.
- Require reproducible evidence before creating a finding.
- Update every changed entrypoint or resource digest.
- Run the validator, the plugin tests, and one real HuntProxy job.
- Document what the plugin checks, what it needs, and what it does not cover.

## Common Problems

| Problem | What to Check |
| --- | --- |
| The plugin is missing | Check `extension_list` for load issues, then directory depth, `enabled`, JSON syntax, file paths, UTF-8, digest, and daemon logs. |
| The plugin cannot run | Action name, required input, base exchange, and declared capabilities. |
| Planning exceeds its budget | Candidate count, repeats, workflows, and `max_operations`. |
| Requests run in the wrong order | Use sequential execution or an `http_workflow`. |
| Analysis uses the wrong response | Match every observation by its operation ID. |
| A body is unavailable | Check truncation and omission fields; use bounded previews, hashes, or host-side searches. |
| A finding is rejected | Include a title and at least one same-project evidence exchange ID. |

## Going Further

- [Minimal plugin](../examples/minimal-plugin/) provides the complete working starter.
- [Plugin API v1](plugin-api-v1.md) documents contexts, operations, observations, capabilities, and limits.
- [Architecture](architecture.md) explains the boundary between plugin JavaScript and HuntProxy.
- Maintained plugins provide focused examples: [ParamFinder](../plugins/param-finder/README.md) for semantic requests, [CSRFAnalyzer](../plugins/csrf-analyzer/README.md) for private workflows, [Request Smuggler](../plugins/request-smuggler/README.md) for raw HTTP, [Racer](../plugins/racer/README.md) for synchronized requests, and [IpRotate](../plugins/ip-rotate/README.md) for the AWS Gateway capability.
