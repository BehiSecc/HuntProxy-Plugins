import { readdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import vm from "node:vm";

const root = new URL("../", import.meta.url);
const pluginsDirectory = new URL("../plugins/", import.meta.url);
const expectedNames = new Set([
  "ParamFinder", "AuthAnalyzer", "Request Smuggler", "Racer",
  "403Bypasser", "JWTAnalyzer", "CacheAnalyzer", "CSRFAnalyzer",
  "UploadAnalyzer", "IpRotate",
]);
const allowedCapabilities = new Set([
  "http.semantic", "http.raw", "http.race", "identity.use", "aws.api_gateway",
]);
const seenIds = new Set();
const seenNames = new Set();

for (const entry of await readdir(pluginsDirectory, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const manifestPath = join(pluginsDirectory.pathname, entry.name, "plugin.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (manifest.schema_version !== 1) throw new Error(`${entry.name}: unsupported schema_version`);
  if (manifest.id !== entry.name) throw new Error(`${entry.name}: id must match its directory`);
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(manifest.id)) throw new Error(`${entry.name}: invalid id`);
  if (!/^\d+\.\d+\.\d+$/.test(manifest.version)) throw new Error(`${entry.name}: invalid version`);
  if (!expectedNames.has(manifest.name)) throw new Error(`${entry.name}: unexpected display name`);
  if (typeof manifest.enabled !== "boolean") throw new Error(`${entry.name}: enabled must be boolean`);
  if (typeof manifest.entrypoint !== "string" || !manifest.entrypoint.endsWith(".js")) throw new Error(`${entry.name}: invalid entrypoint`);
  if (!/^[a-f0-9]{64}$/.test(manifest.entrypoint_sha256)) throw new Error(`${entry.name}: invalid entrypoint digest`);
  const entrypoint = await readFile(join(pluginsDirectory.pathname, entry.name, manifest.entrypoint), "utf8");
  const digest = createHash("sha256").update(entrypoint).digest("hex");
  if (digest !== manifest.entrypoint_sha256) throw new Error(`${entry.name}: entrypoint digest mismatch`);
  const sandbox = { globalThis: {} };
  vm.runInNewContext(entrypoint, sandbox, { timeout: 100 });
  if (typeof sandbox.globalThis.HuntProxyPlugin?.plan !== "function" || typeof sandbox.globalThis.HuntProxyPlugin?.analyze !== "function") {
    throw new Error(`${entry.name}: entrypoint does not expose the host contract`);
  }
  for (const [name, resource] of Object.entries(manifest.resources ?? {})) {
    if (!resource || typeof resource.path !== "string" || !/^[a-f0-9]{64}$/.test(resource.sha256 ?? "")) {
      throw new Error(`${entry.name}: invalid resource ${name}`);
    }
    const bytes = await readFile(join(pluginsDirectory.pathname, entry.name, resource.path));
    const resourceDigest = createHash("sha256").update(bytes).digest("hex");
    if (resourceDigest !== resource.sha256) throw new Error(`${entry.name}: resource digest mismatch for ${name}`);
  }
  if (seenIds.has(manifest.id) || seenNames.has(manifest.name)) throw new Error(`${entry.name}: duplicate identity`);
  seenIds.add(manifest.id); seenNames.add(manifest.name);
  for (const capability of manifest.capabilities ?? []) {
    if (!allowedCapabilities.has(capability)) throw new Error(`${entry.name}: unknown capability ${capability}`);
  }
  if (!Array.isArray(manifest.actions) || manifest.actions.length === 0) throw new Error(`${entry.name}: no actions`);
  const actionNames = new Set();
  for (const action of manifest.actions) {
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(action.name)) throw new Error(`${entry.name}: invalid action name`);
    if (actionNames.has(action.name)) throw new Error(`${entry.name}: duplicate action ${action.name}`);
    actionNames.add(action.name);
    if (action.input_schema?.type !== "object") throw new Error(`${entry.name}: action input must be an object schema`);
  }
}

for (const expected of expectedNames) {
  if (!seenNames.has(expected)) throw new Error(`missing plugin ${expected}`);
}
if (seenNames.size !== expectedNames.size) throw new Error("unexpected plugin count");

await readFile(new URL("schemas/plugin-manifest-v1.json", root), "utf8").then(JSON.parse);
console.log(`Validated ${seenNames.size} HuntProxy plugin manifests.`);
