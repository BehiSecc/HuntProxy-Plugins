import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const pluginsDirectory = fileURLToPath(new URL("../plugins/", import.meta.url));
const offenders = [];

for (const entry of await readdir(pluginsDirectory, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const source = await readFile(join(pluginsDirectory, entry.name, "index.js"), "utf8");
  if (/\bremediation\s*:/.test(source)) offenders.push(entry.name);
}

assert.deepEqual(
  offenders,
  [],
  `official plugin findings must not include remediation fields: ${offenders.join(", ")}`,
);

console.log("Validated that official plugin findings omit remediation fields.");
