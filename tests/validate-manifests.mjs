import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { validatePluginDirectory } from "../scripts/validate-plugin.mjs";

const repository = fileURLToPath(new URL("../", import.meta.url));
const pluginsDirectory = fileURLToPath(new URL("../plugins/", import.meta.url));
const expectedIds = new Set([
  "403-bypasser",
  "auth-analyzer",
  "cache-analyzer",
  "csrf-analyzer",
  "ip-rotate",
  "jwt-analyzer",
  "param-finder",
  "racer",
  "request-smuggler",
  "upload-analyzer",
]);
const baseExchangeActions = new Map([
  ["403-bypasser", ["scan"]],
  ["auth-analyzer", ["scan", "anonymous_audit"]],
  ["cache-analyzer", ["scan"]],
  ["csrf-analyzer", ["scan", "browser_scan"]],
  ["jwt-analyzer", ["scan"]],
  ["request-smuggler", ["scan"]],
  ["upload-analyzer", ["scan"]],
]);
const seen = new Set();

for (const entry of await readdir(pluginsDirectory, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const directory = join(pluginsDirectory, entry.name);
  const validated = await validatePluginDirectory(directory);
  assert.equal(validated.id, entry.name, `${entry.name}: first-party directory must match id`);
  assert.ok(!seen.has(validated.id), `${entry.name}: duplicate plugin id`);
  const manifest = JSON.parse(await readFile(join(directory, "plugin.json"), "utf8"));
  for (const actionName of baseExchangeActions.get(validated.id) ?? []) {
    const action = manifest.actions.find((candidate) => candidate.name === actionName);
    assert.equal(action?.requires_base_exchange, true, `${entry.name}.${actionName}: saved exchange requirement must be advertised`);
  }
  seen.add(validated.id);
}

assert.deepEqual(seen, expectedIds, "the maintained first-party plugin set changed unexpectedly");
const schema = JSON.parse(await readFile(join(repository, "schemas/plugin-manifest-v1.json"), "utf8"));
const limitSchema = schema.properties.limits.properties;
assert.equal(limitSchema.timeout_ms.maximum, 900000);
assert.equal(limitSchema.max_operations.maximum, 10000);
assert.equal(limitSchema.memory_mb.maximum, 128);
assert.equal(limitSchema.js_stage_timeout_ms.minimum, 250);
assert.equal(limitSchema.js_stage_timeout_ms.maximum, 120000);
const inputSchema = schema.properties.actions.items.properties.input_schema;
assert.ok(inputSchema.required.includes("type"));
assert.equal(inputSchema.properties.type.const, "object");
assert.equal(schema.properties.actions.items.properties.requires_base_exchange.type, "boolean");
const minimalManifest = JSON.parse(await readFile(join(repository, "examples/minimal-plugin/plugin.json"), "utf8"));
assert.equal(minimalManifest.actions[0].requires_base_exchange, true);
assert.equal(schema.properties.resources.propertyNames.maxLength, 64);
console.log(`Validated ${seen.size} HuntProxy plugin manifests.`);
