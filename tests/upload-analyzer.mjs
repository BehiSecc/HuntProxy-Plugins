import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const root = new URL("../plugins/", import.meta.url);
const source = await readFile(new URL("upload-analyzer/index.js", root), "utf8");
const sandbox = { globalThis: {} };
vm.runInNewContext(source, sandbox, { timeout: 500 });
const plugin = sandbox.globalThis.HuntProxyPlugin;
const boundary = "huntproxy-boundary";
const body = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="original.txt"\r\nContent-Type: text/plain\r\n\r\noriginal\r\n--${boundary}--\r\n`;
const context = { api_version: 1, action: "scan", resources: {}, related_exchanges: [], base_exchange: {
  exchange_id: 42, method: "POST", url: "https://example.test/upload",
  identity: {
    request_headers: [{ name: "Content-Type", value_base64: Buffer.from(`multipart/form-data; boundary=${boundary}`).toString("base64") }],
    request_body_base64: Buffer.from(body, "binary").toString("base64"), request_body_truncated: false,
  },
} };
function observation(operation, { status = 201, hash = "accepted", text = "upload stored" } = {}) {
  return { id: operation.id, exchange_id: 2000 + Math.floor(Math.random() * 100000), status_code: status, response_length: text.length, response_body_hash: hash, response_preview: { text }, response_headers: [] };
}

assert.throws(() => plugin.plan({}, context), /allow_uploads/);
const input = { allow_uploads: true, marker: "hp-upload", allowed_extension: "txt", prohibited_extension: "php", max_files: 17, success_markers: ["stored"] };
const plan = plugin.plan(input, context);
assert.equal(plan.operations.length, 34);
assert.equal(plan.result.executable_payloads, false);
assert.equal(plan.result.retrieval_performed, false);
const variants = Array.from(plan.result.variants);
assert.equal(variants[0].role, "allowed-control");
assert.equal(variants[1].role, "blocked-control");
for (const name of ["case-folded-extension", "trailing-dot", "trailing-space", "double-extension", "encoded-dot", "double-encoded-dot", "encoded-null-suffix", "windows-ads-suffix"]) {
  assert.ok(variants.some((variant) => variant.name === name), `missing ${name}`);
}
for (const operation of plan.operations) {
  const decoded = Buffer.from(operation.body_base64, "base64").toString("binary");
  assert.doesNotMatch(decoded, /<\?(?:php|=)|<script|onerror\s*=|javascript:/i, "payloads stay inert");
  assert.match(decoded, /HuntProxy inert upload marker|PNG|GIF89a|PDF-1\.4/);
}

const observations = plan.operations.map((operation) => observation(operation));
for (const item of observations.filter((entry) => entry.id.startsWith("variant-1-"))) {
  item.status_code = 415; item.response_body_hash = "blocked"; item.response_preview.text = "extension denied";
}
const result = plugin.analyze(input, observations, context);
assert.equal(result.result.allowed_control_accepted, true);
assert.equal(result.result.prohibited_control_blocked, true);
assert.ok(result.findings.some((finding) => finding.metadata.variant === "case-folded-extension"));
assert.ok(result.findings.filter((finding) => finding.metadata.role === "filename-bypass").length >= 8);
assert.ok(!result.findings.some((finding) => finding.metadata.role === "content-validation"), "content mismatch findings require explicit expectation");

const direct = plan.operations.map((operation) => observation(operation));
const directResult = plugin.analyze(input, direct, context);
assert.equal(directResult.result.prohibited_control_accepted, true);
assert.ok(directResult.findings.some((finding) => /Direct prohibited/.test(finding.title)));
assert.ok(!directResult.findings.some((finding) => finding.metadata.role === "filename-bypass"), "no bypass claim without a blocked control");

const contentInput = { ...input, expect_content_validation: true };
assert.ok(plugin.analyze(contentInput, observations, context).findings.some((finding) => finding.metadata.role === "content-validation"));

console.log("UploadAnalyzer hardening tests passed.");
