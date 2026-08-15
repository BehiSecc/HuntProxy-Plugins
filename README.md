<h1 id="huntproxy-plugins" align="center">HuntProxy Plugins</h1>

## Introduction

[HuntProxy](https://github.com/BehiSecc/HuntProxy) gives AI agents a reliable workbench to structure a hunt, organize traffic, and run repeatable tests.

But some vulnerabilities cannot be tested well with a single broad prompt. Request smuggling is the clearest example: there are many protocol variants, timing rules, controls, and false positives. Asking a model to "test everything" is not enough.

So I rebuilt many of the testing workflows that bug hunters and web security researchers already rely on, then adapted them for HuntProxy. Each plugin gives the agent a focused way to test one vulnerability class while HuntProxy handles the requests, limits, History, and evidence.

These plugins are practical starting points, not complete replacements for specialist judgment. Some may not cover every technique or target-specific edge case. The goal is to give the agent a reliable path through the common tests, then let you review the proof and decide what deserves deeper manual work.

> [!NOTE]
> While building this pack, I used relevant [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs to validate the plugins, and they performed well across those labs.

## 📚 Table of Contents

- [HuntProxy Plugins](#huntproxy-plugins)
  - [ Plugins](#-plugins)
  - [ Install and Use the Plugins](#-install-and-use-the-plugins)
  - [ Create a Plugin](#-create-a-plugin)
  - [ Credits](#-credits)

## 🧩 Plugins

This repository currently includes ten enabled plugins. Some require extra setup or explicit confirmation before they can run. The plugin decides what to test and how to interpret the responses; HuntProxy performs the network requests and keeps the resulting traffic and evidence.

| Plugin | What It Does | What It Doesn't Cover | How It Works |
| --- | --- | --- | --- |
| **403Bypasser** | Tries path, header, method, encoding, and Referer variations against endpoints that return 401 or 403. | It cannot firmly confirm an ambiguous path-only result unless the target provides a reliable success marker. | [Details](plugins/403-bypasser/README.md) |
| **AuthAnalyzer** | Replays the same requests as two different users, and can compare them with a logged-out request. | It does not discover accounts or credentials; the identities must be provided. | [Details](plugins/auth-analyzer/README.md) |
| **CacheAnalyzer** | Looks for cache poisoning, cache-key mistakes, and web cache deception, then checks whether the behavior is reproducible. |  | [Details](plugins/cache-analyzer/README.md) |
| **CSRFAnalyzer** | Checks token, Origin, Referer, method, and content-type defenses, including optional cross-session and browser-based tests. | It does not mutate multipart tokens or cover sibling-domain, client-side redirect, or WebSocket CSRF chains. | [Details](plugins/csrf-analyzer/README.md) |
| **IpRotate** | Rotates matching HuntProxy traffic through AWS API Gateways in selected regions. | It works for one exact target origin at a time and does not rotate raw HTTP operations. | [Details](plugins/ip-rotate/README.md) |
| **JWTAnalyzer** | Finds JWTs in captured requests and checks claims, algorithms, signatures, weak HMAC keys, KID behavior, and configured key-confusion cases. | It only finds tokens in HTTP Cookie or Authorization headers; WebSocket JWTs are not covered. | [Details](plugins/jwt-analyzer/README.md) |
| **ParamFinder** | Finds hidden or unkeyed parameters in queries, headers, cookies, forms, and JSON bodies. | JSON body discovery is limited to top-level fields; nested JSON parameters are not covered. | [Details](plugins/param-finder/README.md) |
| **Racer** | Tests limit overruns, object-state collisions, and multi-step race conditions using parallel, HTTP/1 last-byte, and HTTP/2 single-packet techniques. |  | [Details](plugins/racer/README.md) |
| **Request Smuggler** | Checks HTTP/1 desynchronization and HTTP/2 downgrade, splitting, response-queue, and tunnelling behavior. | Browser-powered client-side desync is not covered. | [Details](plugins/request-smuggler/README.md) |
| **UploadAnalyzer** | Checks filename normalization, extension bypasses, and MIME/content validation using harmless upload files. | It only changes the first file in a multipart request and does not discover where uploaded files are stored. | [Details](plugins/upload-analyzer/README.md) |

## 📥 Install and Use the Plugins

You need a working [HuntProxy](https://github.com/BehiSecc/HuntProxy) installation first.

HuntProxy loads plugins from `~/.huntproxy/plugins` by default:

```bash
git clone https://github.com/BehiSecc/HuntProxy-Plugins.git
mkdir -p "$HOME/.huntproxy/plugins"
cp -R HuntProxy-Plugins/plugins/. "$HOME/.huntproxy/plugins/"
```

If HuntProxy is already running, stop it with `HuntProxy stop`, then restart your AI client so the plugins are loaded.

Most plugins begin with a request already captured in HuntProxy History. Some actions need additional input or an explicit safety acknowledgement; your agent can discover both from the plugin description.

```text
Use HuntProxy MCP. List the installed plugins, describe the best one for this
test, and tell me what it needs before running anything.
```

Then run a focused test:

```text
Use HuntProxy MCP. Run 403Bypasser against the latest 403 response in project 1.
Do not enable state-changing variants. Summarize promising results with their
History exchange IDs.
```

<details>
<summary><strong>Use this checkout directly during development</strong></summary>

Instead of copying the plugins, point HuntProxy at an absolute path in `~/.huntproxy/config.toml`:

```toml
plugin_dir = "/absolute/path/to/HuntProxy-Plugins/plugins"
```

Restart HuntProxy after changing a manifest, entrypoint, resource, or digest. Paths beginning with `~` are not expanded in this setting.

</details>

## 🛠 Create a Plugin

A plugin plans a bounded test and analyzes the result. HuntProxy performs the requests, applies scope and resource limits, and saves the traffic and evidence. Plugin JavaScript runs inside QuickJS and cannot open sockets, read files, launch processes, use Node.js modules, or call `fetch()` directly.

Start with [Write a HuntProxy plugin](docs/writing-plugins.md) and the [minimal working example](examples/minimal-plugin/). Use [Plugin API v1](docs/plugin-api-v1.md) for the complete contract and [Architecture](docs/architecture.md) for the trust boundary.

```bash
node scripts/validate-plugin.mjs examples/minimal-plugin
node examples/minimal-plugin/test.mjs
cp -R examples/minimal-plugin examples/my-plugin
```

Edit `plugin.json`, `index.js`, and the tests, update `entrypoint_sha256`, then validate the new directory. The validator requires Node.js 18 or newer; the plugin code itself runs inside HuntProxy's embedded QuickJS.

## 🙏 Credits

A special thank you to [James Kettle](https://x.com/albinowax). His public research on request smuggling, web caches, race conditions, and hidden attack surfaces was a major source of inspiration for this pack.

Thank you also to the [PortSwigger Web Security Academy](https://portswigger.net/web-security) for making advanced web security techniques practical to learn and test.
