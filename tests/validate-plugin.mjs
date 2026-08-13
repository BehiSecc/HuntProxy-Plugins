import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { validatePluginDirectory } from "../scripts/validate-plugin.mjs";

const repository = fileURLToPath(new URL("../", import.meta.url));
const example = join(repository, "examples/minimal-plugin");
const checker = join(repository, "scripts/validate-plugin.mjs");
const temporary = await mkdtemp(join(tmpdir(), "huntproxy-plugin-validator-"));

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function fixture(name) {
  const directory = join(temporary, name);
  await cp(example, directory, { recursive: true });
  return directory;
}

async function manifest(directory) {
  return JSON.parse(await readFile(join(directory, "plugin.json"), "utf8"));
}

async function saveManifest(directory, value) {
  await writeFile(join(directory, "plugin.json"), `${JSON.stringify(value, null, 2)}\n`);
}

try {
  const valid = await validatePluginDirectory(example);
  assert.equal(valid.id, "minimal-plugin");
  assert.deepEqual(valid.action_names, ["inspect"]);

  const badDigest = await fixture("bad-digest");
  await writeFile(join(badDigest, "index.js"), "globalThis.changed = true;\n");
  await assert.rejects(() => validatePluginDirectory(badDigest), /entrypoint digest mismatch/);

  const malformed = await fixture("malformed-json");
  await writeFile(join(malformed, "plugin.json"), "{\n");
  await assert.rejects(() => validatePluginDirectory(malformed), /not valid JSON/);

  const traversal = await fixture("traversal");
  const traversalManifest = await manifest(traversal);
  traversalManifest.entrypoint = "../outside.js";
  await saveManifest(traversal, traversalManifest);
  await assert.rejects(() => validatePluginDirectory(traversal), /parent path components/);

  const symlinkEscape = await fixture("symlink-escape");
  const outsideSource = "globalThis.HuntProxyPlugin = { plan: function () { return {}; }, analyze: function () { return {}; } };\n";
  const outsidePath = join(temporary, "outside.js");
  await writeFile(outsidePath, outsideSource);
  await symlink(outsidePath, join(symlinkEscape, "linked.js"));
  const symlinkManifest = await manifest(symlinkEscape);
  symlinkManifest.entrypoint = "linked.js";
  symlinkManifest.entrypoint_sha256 = digest(outsideSource);
  await saveManifest(symlinkEscape, symlinkManifest);
  await assert.rejects(() => validatePluginDirectory(symlinkEscape), /resolves outside/);

  const undeclared = await fixture("undeclared-capability");
  const undeclaredManifest = await manifest(undeclared);
  undeclaredManifest.actions[0].required_capabilities = ["http.raw"];
  await saveManifest(undeclared, undeclaredManifest);
  await assert.rejects(() => validatePluginDirectory(undeclared), /requires undeclared capability/);

  const baseRequired = await fixture("base-exchange-required");
  const baseRequiredManifest = await manifest(baseRequired);
  baseRequiredManifest.actions[0].requires_base_exchange = true;
  await saveManifest(baseRequired, baseRequiredManifest);
  await validatePluginDirectory(baseRequired);

  const invalidBaseRequired = await fixture("invalid-base-exchange-required");
  const invalidBaseRequiredManifest = await manifest(invalidBaseRequired);
  invalidBaseRequiredManifest.actions[0].requires_base_exchange = "yes";
  await saveManifest(invalidBaseRequired, invalidBaseRequiredManifest);
  await assert.rejects(() => validatePluginDirectory(invalidBaseRequired), /requires_base_exchange must be a boolean/);

  const invalidLimit = await fixture("invalid-limit");
  const limitManifest = await manifest(invalidLimit);
  limitManifest.limits.timeout_ms = 900001;
  await saveManifest(invalidLimit, limitManifest);
  await assert.rejects(() => validatePluginDirectory(invalidLimit), /limits.timeout_ms/);

  const blankName = await fixture("blank-name");
  const blankManifest = await manifest(blankName);
  blankManifest.name = "   ";
  await saveManifest(blankName, blankManifest);
  await assert.rejects(() => validatePluginDirectory(blankName), /name must contain/);

  const multibyteName = await fixture("multibyte-name");
  const multibyteManifest = await manifest(multibyteName);
  multibyteManifest.name = "😀".repeat(40);
  await saveManifest(multibyteName, multibyteManifest);
  await assert.rejects(() => validatePluginDirectory(multibyteName), /128 UTF-8 bytes/);

  const unicodeDescription = await fixture("unicode-description");
  const unicodeDescriptionManifest = await manifest(unicodeDescription);
  unicodeDescriptionManifest.description = "😀".repeat(200);
  await saveManifest(unicodeDescription, unicodeDescriptionManifest);
  await validatePluginDirectory(unicodeDescription);

  const missingSchemaType = await fixture("missing-schema-type");
  const missingSchemaManifest = await manifest(missingSchemaType);
  missingSchemaManifest.actions[0].input_schema = {};
  await saveManifest(missingSchemaType, missingSchemaManifest);
  await assert.rejects(() => validatePluginDirectory(missingSchemaType), /input_schema.type must be object/);

  const badResource = await fixture("bad-resource");
  await writeFile(join(badResource, "words.txt"), "one\ntwo\n");
  const resourceManifest = await manifest(badResource);
  resourceManifest.resources = { words: { path: "words.txt", sha256: "0".repeat(64) } };
  await saveManifest(badResource, resourceManifest);
  await assert.rejects(() => validatePluginDirectory(badResource), /resource words digest mismatch/);

  const resourceBeforeCode = await fixture("resource-before-code");
  const throwingSource = "throw new Error('entrypoint ran before resources were checked');\n";
  await writeFile(join(resourceBeforeCode, "index.js"), throwingSource);
  await writeFile(join(resourceBeforeCode, "words.txt"), "one\n");
  const resourceBeforeCodeManifest = await manifest(resourceBeforeCode);
  resourceBeforeCodeManifest.entrypoint_sha256 = digest(throwingSource);
  resourceBeforeCodeManifest.resources = {
    words: { path: "words.txt", sha256: "0".repeat(64) }
  };
  await saveManifest(resourceBeforeCode, resourceBeforeCodeManifest);
  await assert.rejects(() => validatePluginDirectory(resourceBeforeCode), /resource words digest mismatch/);

  const multibyteResourceName = await fixture("multibyte-resource-name");
  await writeFile(join(multibyteResourceName, "words.txt"), "one\n");
  const multibyteResourceManifest = await manifest(multibyteResourceName);
  multibyteResourceManifest.resources = {
    ["😀".repeat(17)]: { path: "words.txt", sha256: digest("one\n") }
  };
  await saveManifest(multibyteResourceName, multibyteResourceManifest);
  await assert.rejects(() => validatePluginDirectory(multibyteResourceName), /64 UTF-8 bytes/);

  const invalidEntrypointUtf8 = await fixture("invalid-entrypoint-utf8");
  const invalidEntrypointBytes = Buffer.from([0xff]);
  await writeFile(join(invalidEntrypointUtf8, "index.js"), invalidEntrypointBytes);
  const invalidEntrypointManifest = await manifest(invalidEntrypointUtf8);
  invalidEntrypointManifest.entrypoint_sha256 = digest(invalidEntrypointBytes);
  await saveManifest(invalidEntrypointUtf8, invalidEntrypointManifest);
  await assert.rejects(() => validatePluginDirectory(invalidEntrypointUtf8), /entrypoint must be UTF-8/);

  const invalidResourceUtf8 = await fixture("invalid-resource-utf8");
  const invalidResourceBytes = Buffer.from([0xff]);
  await writeFile(join(invalidResourceUtf8, "words.txt"), invalidResourceBytes);
  const invalidResourceManifest = await manifest(invalidResourceUtf8);
  invalidResourceManifest.resources = {
    words: { path: "words.txt", sha256: digest(invalidResourceBytes) }
  };
  await saveManifest(invalidResourceUtf8, invalidResourceManifest);
  await assert.rejects(() => validatePluginDirectory(invalidResourceUtf8), /resource words must be UTF-8/);

  const missingExport = await fixture("missing-export");
  const missingSource = "globalThis.HuntProxyPlugin = { plan: function () { return {}; } };\n";
  await writeFile(join(missingExport, "index.js"), missingSource);
  const missingManifest = await manifest(missingExport);
  missingManifest.entrypoint_sha256 = digest(missingSource);
  await saveManifest(missingExport, missingManifest);
  await assert.rejects(() => validatePluginDirectory(missingExport), /must export.*analyze/);

  const asyncExport = await fixture("async-export");
  const asyncSource = "globalThis.HuntProxyPlugin = { plan: async function () { return {}; }, analyze: function () { return {}; } };\n";
  await writeFile(join(asyncExport, "index.js"), asyncSource);
  const asyncManifest = await manifest(asyncExport);
  asyncManifest.entrypoint_sha256 = digest(asyncSource);
  await saveManifest(asyncExport, asyncManifest);
  await assert.rejects(() => validatePluginDirectory(asyncExport), /synchronous non-generator plan/);

  const standardGlobal = await fixture("standard-global");
  const standardGlobalSource = "var encoded = globalThis.JSON.stringify({ ok: true }); globalThis.HuntProxyPlugin = { plan: function () { return { result: encoded }; }, analyze: function () { return {}; } };\n";
  await writeFile(join(standardGlobal, "index.js"), standardGlobalSource);
  const standardGlobalManifest = await manifest(standardGlobal);
  standardGlobalManifest.entrypoint_sha256 = digest(standardGlobalSource);
  await saveManifest(standardGlobal, standardGlobalManifest);
  await validatePluginDirectory(standardGlobal);

  const initializationTimeout = await fixture("initialization-timeout");
  const timeoutSource = "while (true) {}\n";
  await writeFile(join(initializationTimeout, "index.js"), timeoutSource);
  const timeoutManifest = await manifest(initializationTimeout);
  timeoutManifest.entrypoint_sha256 = digest(timeoutSource);
  timeoutManifest.limits.js_stage_timeout_ms = 250;
  await saveManifest(initializationTimeout, timeoutManifest);
  await assert.rejects(() => validatePluginDirectory(initializationTimeout), /could not be evaluated/);

  const oversizedManifest = await fixture("oversized-manifest");
  await writeFile(join(oversizedManifest, "plugin.json"), Buffer.alloc(256 * 1024 + 1, 0x20));
  await assert.rejects(() => validatePluginDirectory(oversizedManifest), /plugin.json exceeds/);

  const oversizedEntrypoint = await fixture("oversized-entrypoint");
  await writeFile(join(oversizedEntrypoint, "index.js"), Buffer.alloc(4 * 1024 * 1024 + 1, 0x20));
  await assert.rejects(() => validatePluginDirectory(oversizedEntrypoint), /entrypoint exceeds/);

  const oversizedResource = await fixture("oversized-resource");
  const oversizedResourceBytes = Buffer.alloc(1024 * 1024 + 1, 0x61);
  await writeFile(join(oversizedResource, "words.txt"), oversizedResourceBytes);
  const oversizedResourceManifest = await manifest(oversizedResource);
  oversizedResourceManifest.resources = {
    words: { path: "words.txt", sha256: digest(oversizedResourceBytes) }
  };
  await saveManifest(oversizedResource, oversizedResourceManifest);
  await assert.rejects(() => validatePluginDirectory(oversizedResource), /resource words exceeds/);

  const oversizedResourceTotal = await fixture("oversized-resource-total");
  const totalManifest = await manifest(oversizedResourceTotal);
  totalManifest.resources = {};
  for (let index = 0; index < 5; index += 1) {
    const name = `part${index}`;
    const contents = Buffer.alloc(900 * 1024, 0x61 + index);
    const path = `${name}.txt`;
    await writeFile(join(oversizedResourceTotal, path), contents);
    totalManifest.resources[name] = { path, sha256: digest(contents) };
  }
  await saveManifest(oversizedResourceTotal, totalManifest);
  await assert.rejects(() => validatePluginDirectory(oversizedResourceTotal), /resources exceed 4194304 bytes in total/);

  const success = spawnSync(process.execPath, [checker, example], { encoding: "utf8" });
  assert.equal(success.status, 0, success.stderr);
  assert.match(success.stdout, /Validated minimal-plugin: inspect/);
  const failure = spawnSync(process.execPath, [checker, badDigest], { encoding: "utf8" });
  assert.equal(failure.status, 1);
  assert.match(failure.stderr, /Plugin validation failed/);
  assert.doesNotMatch(failure.stderr, /\n\s+at /, "CLI errors should not include a stack trace");
  const help = spawnSync(process.execPath, [checker, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Usage:/);
  const missingArgument = spawnSync(process.execPath, [checker], { encoding: "utf8" });
  assert.equal(missingArgument.status, 2);
  assert.match(missingArgument.stderr, /Usage:/);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log("Generic plugin validator passed.");
