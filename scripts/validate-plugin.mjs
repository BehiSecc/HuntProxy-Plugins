import { createHash } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import { basename, isAbsolute, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_SCRIPT_BYTES = 4 * 1024 * 1024;
const MAX_RESOURCE_BYTES = 1024 * 1024;
const MAX_TOTAL_RESOURCE_BYTES = 4 * 1024 * 1024;
const CAPABILITIES = new Set([
  "http.semantic",
  "http.raw",
  "http.race",
  "identity.use",
  "page.discover",
  "aws.api_gateway",
  "browser.csrf",
]);
const TOP_LEVEL_FIELDS = new Set([
  "schema_version",
  "id",
  "name",
  "version",
  "description",
  "enabled",
  "entrypoint",
  "entrypoint_sha256",
  "resources",
  "capabilities",
  "limits",
  "actions",
]);
const REQUIRED_TOP_LEVEL_FIELDS = [
  "schema_version",
  "id",
  "name",
  "version",
  "description",
  "enabled",
  "entrypoint",
  "entrypoint_sha256",
  "capabilities",
  "limits",
  "actions",
];
const ACTION_FIELDS = new Set([
  "name",
  "description",
  "input_schema",
  "required_capabilities",
  "requires_base_exchange",
]);
const LIMIT_FIELDS = new Set([
  "timeout_ms",
  "js_stage_timeout_ms",
  "max_operations",
  "max_concurrency",
  "memory_mb",
]);

function fail(message) {
  throw new Error(message);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function characterLength(value) {
  return [...value].length;
}

function requireObject(value, field) {
  if (!plainObject(value)) fail(`${field} must be an object`);
  return value;
}

function rejectUnknownFields(value, allowed, field) {
  for (const name of Object.keys(value)) {
    if (!allowed.has(name)) fail(`${field} contains unknown field ${name}`);
  }
}

function requireInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} must be an integer from ${minimum} to ${maximum}`);
  }
}

function safeRelativePath(directory, value, field, extension = null) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\\")) {
    fail(`${field} must be a non-empty relative path`);
  }
  const parts = value.split("/");
  if (isAbsolute(value) || parts.some((part) => !part || part === "." || part === "..")) {
    fail(`${field} must not contain absolute, empty, dot, or parent path components`);
  }
  if (!/^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(value)) {
    fail(`${field} must use portable letters, digits, dots, underscores, hyphens, and forward slashes`);
  }
  if (extension && !value.endsWith(extension)) fail(`${field} must end with ${extension}`);
  const path = resolve(directory, value);
  if (path !== directory && !path.startsWith(`${directory}${sep}`)) {
    fail(`${field} escapes the plugin directory`);
  }
  return path;
}

async function boundedFile(path, maximum, field, directory) {
  let actualPath;
  try {
    actualPath = await realpath(path);
  } catch (error) {
    fail(`${field} cannot be read: ${error.message}`);
  }
  if (actualPath !== directory && !actualPath.startsWith(`${directory}${sep}`)) {
    fail(`${field} resolves outside the plugin directory`);
  }
  let metadata;
  try {
    metadata = await stat(actualPath);
  } catch (error) {
    fail(`${field} cannot be read: ${error.message}`);
  }
  if (!metadata.isFile()) fail(`${field} must be a regular file`);
  if (metadata.size > maximum) fail(`${field} exceeds ${maximum} bytes`);
  return readFile(actualPath);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireDigest(value, field) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    fail(`${field} must be a lowercase SHA-256 digest`);
  }
}

function validateCapabilities(values, field) {
  if (!Array.isArray(values)) fail(`${field} must be an array`);
  const seen = new Set();
  for (const capability of values) {
    if (!CAPABILITIES.has(capability)) fail(`${field} contains unknown capability ${capability}`);
    if (seen.has(capability)) fail(`${field} contains duplicate capability ${capability}`);
    seen.add(capability);
  }
  return seen;
}

function validateLimits(value) {
  const limits = requireObject(value, "limits");
  rejectUnknownFields(limits, LIMIT_FIELDS, "limits");
  for (const required of ["timeout_ms", "max_operations", "max_concurrency", "memory_mb"]) {
    if (!(required in limits)) fail(`limits.${required} is required`);
  }
  requireInteger(limits.timeout_ms, "limits.timeout_ms", 1_000, 900_000);
  requireInteger(limits.max_operations, "limits.max_operations", 1, 10_000);
  requireInteger(limits.max_concurrency, "limits.max_concurrency", 1, 100);
  requireInteger(limits.memory_mb, "limits.memory_mb", 4, 128);
  if (limits.js_stage_timeout_ms !== undefined) {
    requireInteger(limits.js_stage_timeout_ms, "limits.js_stage_timeout_ms", 250, 120_000);
  }
}

function validateActions(actions, manifestCapabilities) {
  if (!Array.isArray(actions) || actions.length === 0) fail("actions must be a non-empty array");
  const names = new Set();
  for (const [index, action] of actions.entries()) {
    requireObject(action, `actions[${index}]`);
    rejectUnknownFields(action, ACTION_FIELDS, `actions[${index}]`);
    if (typeof action.name !== "string" || !/^[a-z][a-z0-9_]{1,63}$/.test(action.name)) {
      fail(`actions[${index}].name must match ^[a-z][a-z0-9_]{1,63}$`);
    }
    if (names.has(action.name)) fail(`duplicate action ${action.name}`);
    names.add(action.name);
    if (typeof action.description !== "string" || characterLength(action.description) < 1 || characterLength(action.description) > 300) {
      fail(`actions[${index}].description must contain 1 to 300 characters`);
    }
    const schema = requireObject(action.input_schema, `actions[${index}].input_schema`);
    if (schema.type !== "object") fail(`actions[${index}].input_schema.type must be object`);
    const required = validateCapabilities(action.required_capabilities ?? [], `actions[${index}].required_capabilities`);
    if (action.requires_base_exchange !== undefined && typeof action.requires_base_exchange !== "boolean") {
      fail(`actions[${index}].requires_base_exchange must be a boolean`);
    }
    for (const capability of required) {
      if (!manifestCapabilities.has(capability)) {
        fail(`action ${action.name} requires undeclared capability ${capability}`);
      }
    }
  }
}

function loadEntrypoint(source, field, timeout) {
  const sandbox = {};
  const context = vm.createContext(sandbox);
  try {
    vm.runInContext(source, context, {
      filename: field,
      timeout,
    });
  } catch (error) {
    fail(`${field} could not be evaluated: ${error.message}`);
  }
  let contract;
  try {
    contract = vm.runInContext(`(function () {
      var plugin = globalThis.HuntProxyPlugin;
      return {
        plan_type: plugin && typeof plugin.plan,
        analyze_type: plugin && typeof plugin.analyze,
        plan_constructor: plugin && typeof plugin.plan === "function" ? plugin.plan.constructor.name : null,
        analyze_constructor: plugin && typeof plugin.analyze === "function" ? plugin.analyze.constructor.name : null
      };
    }())`, context, { timeout });
  } catch (error) {
    fail(`${field} exports could not be inspected: ${error.message}`);
  }
  if (contract.plan_type !== "function") {
    fail(`${field} must export globalThis.HuntProxyPlugin.plan`);
  }
  if (contract.analyze_type !== "function") {
    fail(`${field} must export globalThis.HuntProxyPlugin.analyze`);
  }
  for (const [name, constructor] of [["plan", contract.plan_constructor], ["analyze", contract.analyze_constructor]]) {
    if (["AsyncFunction", "GeneratorFunction", "AsyncGeneratorFunction"].includes(constructor)) {
      fail(`${field} must export a synchronous non-generator ${name} function`);
    }
  }
}

export async function validatePluginDirectory(pluginDirectory) {
  let directory;
  try {
    directory = await realpath(resolve(pluginDirectory));
  } catch (error) {
    fail(`plugin directory cannot be read: ${error.message}`);
  }
  if (!(await stat(directory)).isDirectory()) fail("plugin path must be a directory");
  const manifestBytes = await boundedFile(resolve(directory, "plugin.json"), MAX_MANIFEST_BYTES, "plugin.json", directory);
  let manifest;
  try {
    const manifestText = new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes);
    manifest = JSON.parse(manifestText);
  } catch (error) {
    fail(`plugin.json is not valid JSON: ${error.message}`);
  }
  requireObject(manifest, "plugin.json");
  rejectUnknownFields(manifest, TOP_LEVEL_FIELDS, "plugin.json");
  for (const required of REQUIRED_TOP_LEVEL_FIELDS) {
    if (!(required in manifest)) fail(`plugin.json is missing ${required}`);
  }
  if (manifest.schema_version !== 1) fail("schema_version must be 1");
  if (typeof manifest.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(manifest.id)) {
    fail("id must contain 2 to 63 lowercase letters, digits, or hyphens and start with a letter or digit");
  }
  if (typeof manifest.name !== "string" || !manifest.name.trim() || characterLength(manifest.name) > 80 || Buffer.byteLength(manifest.name, "utf8") > 128) {
    fail("name must contain 1 to 80 characters and at most 128 UTF-8 bytes");
  }
  if (typeof manifest.version !== "string" || !/^\d+\.\d+\.\d+$/.test(manifest.version)) {
    fail("version must use MAJOR.MINOR.PATCH");
  }
  if (typeof manifest.description !== "string" || characterLength(manifest.description) < 1 || characterLength(manifest.description) > 300) {
    fail("description must contain 1 to 300 characters");
  }
  if (typeof manifest.enabled !== "boolean") fail("enabled must be true or false");

  const manifestCapabilities = validateCapabilities(manifest.capabilities, "capabilities");
  validateLimits(manifest.limits);
  validateActions(manifest.actions, manifestCapabilities);

  requireDigest(manifest.entrypoint_sha256, "entrypoint_sha256");
  const entrypointPath = safeRelativePath(directory, manifest.entrypoint, "entrypoint", ".js");
  const entrypointBytes = await boundedFile(entrypointPath, MAX_SCRIPT_BYTES, "entrypoint", directory);
  if (sha256(entrypointBytes) !== manifest.entrypoint_sha256) {
    fail(`entrypoint digest mismatch; expected ${sha256(entrypointBytes)}`);
  }
  let entrypoint;
  try {
    entrypoint = new TextDecoder("utf-8", { fatal: true }).decode(entrypointBytes);
  } catch {
    fail("entrypoint must be UTF-8 text");
  }
  const resources = requireObject(manifest.resources ?? {}, "resources");
  let resourceBytes = 0;
  for (const [name, resource] of Object.entries(resources)) {
    if (!name || characterLength(name) > 64 || Buffer.byteLength(name, "utf8") > 64) {
      fail(`resource name ${name || "<empty>"} must contain at most 64 characters and 64 UTF-8 bytes`);
    }
    requireObject(resource, `resources.${name}`);
    rejectUnknownFields(resource, new Set(["path", "sha256"]), `resources.${name}`);
    requireDigest(resource.sha256, `resources.${name}.sha256`);
    const resourcePath = safeRelativePath(directory, resource.path, `resources.${name}.path`);
    const bytes = await boundedFile(resourcePath, MAX_RESOURCE_BYTES, `resource ${name}`, directory);
    resourceBytes += bytes.length;
    if (resourceBytes > MAX_TOTAL_RESOURCE_BYTES) fail("plugin resources exceed 4194304 bytes in total");
    if (sha256(bytes) !== resource.sha256) {
      fail(`resource ${name} digest mismatch; expected ${sha256(bytes)}`);
    }
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      fail(`resource ${name} must be UTF-8 text`);
    }
  }

  loadEntrypoint(entrypoint, manifest.entrypoint, Math.min(manifest.limits.js_stage_timeout_ms ?? 2_000, 2_000));

  return {
    directory,
    id: manifest.id,
    name: manifest.name,
    action_names: manifest.actions.map((action) => action.name),
  };
}

async function main() {
  const directory = process.argv[2];
  if (directory === "--help" || directory === "-h") {
    console.log("Usage: node scripts/validate-plugin.mjs <plugin-directory>");
    return;
  }
  if (!directory || process.argv.length !== 3) {
    console.error("Usage: node scripts/validate-plugin.mjs <plugin-directory>");
    process.exitCode = 2;
    return;
  }
  try {
    const result = await validatePluginDirectory(directory);
    console.log(`Validated ${result.id}: ${result.action_names.join(", ")}`);
  } catch (error) {
    console.error(`Plugin validation failed in ${basename(resolve(directory))}: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
