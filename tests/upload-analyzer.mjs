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
const input = { allow_uploads: true, marker: "hp-upload", allowed_extension: "txt", prohibited_extension: "php", max_files: 19, success_markers: ["stored"] };
const plan = plugin.plan(input, context);
assert.equal(plan.operations.length, 38);
assert.equal(plan.result.executable_payloads, false);
assert.equal(plan.result.retrieval_performed, false);
const variants = Array.from(plan.result.variants);
assert.equal(variants[0].role, "allowed-control");
assert.equal(variants[1].role, "blocked-control");
for (const name of ["case-folded-extension", "trailing-dot", "trailing-space", "double-extension", "encoded-dot", "double-encoded-dot", "encoded-null-suffix", "windows-ads-suffix"]) {
  assert.ok(variants.some((variant) => variant.name === name), `missing ${name}`);
}
for (const name of ["parent-directory", "encoded-parent-directory"]) assert.ok(variants.some((variant) => variant.name === name), `missing ${name}`);
for (const operation of plan.operations) {
  const decoded = Buffer.from(operation.body_base64, "base64").toString("binary");
  assert.doesNotMatch(decoded, /<\?(?:php|=)|<script|onerror\s*=|javascript:/i, "payloads stay inert");
  assert.match(decoded, /HuntProxy inert upload marker|PNG|GIF89a|PDF-1\.4/);
}
assert.match(Buffer.from(plan.operations[14 * 2].body_base64, "base64").toString("binary"), /Content-Type: image\/png/, "non-image bases use the safe declared-image fallback");

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
const traversalIndex = variants.findIndex((variant) => variant.name === "encoded-parent-directory");
for (const item of observations.filter((entry) => entry.id.startsWith(`variant-${traversalIndex}-`))) {
  item.response_body_hash = "traversal"; item.response_preview.text = "stored at avatars/../hp-upload.php";
}
const traversalResult = plugin.analyze(input, observations, context);
assert.ok(traversalResult.findings.some((finding) => finding.metadata.variant === "encoded-parent-directory" && finding.metadata.reflected_parent_path));

const direct = plan.operations.map((operation) => observation(operation));
const directResult = plugin.analyze(input, direct, context);
assert.equal(directResult.result.prohibited_control_accepted, true);
assert.ok(directResult.findings.some((finding) => /Direct prohibited/.test(finding.title)));
assert.ok(!directResult.findings.some((finding) => finding.metadata.role === "filename-bypass"), "no bypass claim without a blocked control");

const contentInput = { ...input, expect_content_validation: true };
assert.ok(plugin.analyze(contentInput, observations, context).findings.some((finding) => finding.metadata.role === "content-validation"));

const imageBody = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="original.jpg"\r\nContent-Type: image/jpeg\r\n\r\noriginal\r\n--${boundary}--\r\n`;
const imageContext = { ...context, base_exchange: { ...context.base_exchange, identity: {
  ...context.base_exchange.identity,
  request_body_base64: Buffer.from(imageBody, "binary").toString("base64"),
} } };
const imagePlan = plugin.plan({ ...input, allowed_extension: "jpg" }, imageContext);
for (const index of [0, 1, 2, 9]) {
  assert.match(Buffer.from(imagePlan.operations[index * 2].body_base64, "base64").toString("binary"), /Content-Type: image\/jpeg/);
}
assert.match(Buffer.from(imagePlan.operations[14 * 2].body_base64, "base64").toString("binary"), /Content-Type: image\/jpeg/);
const imageObservations = imagePlan.operations.map((operation) => observation(operation, { status: 200, hash: "accepted", text: "upload stored" }));
for (const item of imageObservations.filter((entry) => entry.id.startsWith("variant-1-"))) {
  item.status_code = 403; item.response_body_hash = "blocked"; item.response_preview.text = "extension denied";
}
const imageResult = plugin.analyze({ ...input, allowed_extension: "jpg" }, imageObservations, imageContext);
assert.equal(imageResult.result.allowed_control_accepted, true, "image-only endpoints retain an accepted image MIME control");
assert.ok(imageResult.findings.some((finding) => finding.metadata.variant === "encoded-null-suffix"));

console.log("UploadAnalyzer hardening tests passed.");
