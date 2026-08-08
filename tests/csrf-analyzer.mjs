import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const root = new URL("../plugins/", import.meta.url);
const source = await readFile(new URL("csrf-analyzer/index.js", root), "utf8");
const sandbox = { globalThis: {} };
vm.runInNewContext(source, sandbox, { timeout: 500 });
const plugin = sandbox.globalThis.HuntProxyPlugin;
const b64 = (value) => Buffer.from(value, "binary").toString("base64");
function context() {
  return { api_version: 1, action: "scan", resources: {}, related_exchanges: [], base_exchange: {
    exchange_id: 42, method: "POST", url: "https://example.test/profile?csrf=query-good",
    identity: {
      request_headers: [
        { name: "Content-Type", value_base64: b64("application/x-www-form-urlencoded") },
        { name: "Origin", value_base64: b64("https://example.test") },
        { name: "Referer", value_base64: b64("https://example.test/profile") },
        { name: "X-CSRF-Token", value_base64: b64("header-good") },
        { name: "Cookie", value_base64: b64("sid=primary") },
      ],
      request_body_base64: b64("name=alice&csrf_token=body-good"), request_body_truncated: false,
    },
  } };
}
function observation(operation, { status = 200, hash = "success", text = "profile updated", error = null } = {}) {
  return { id: operation.id, exchange_id: 1000 + Math.floor(Math.random() * 100000), status_code: status, response_length: text.length, response_body_hash: hash, response_preview: { text }, response_headers: [], error };
}

assert.throws(() => plugin.plan({}, context()), /allow_state_change/);
const input = {
  allow_state_change: true,
  token_names: ["csrf", "csrf_token", "X-CSRF-Token"],
  secondary_identity: { cookie: "sid=secondary", headers: [{ name: "Authorization", value: "Bearer secondary" }] },
  success_markers: ["updated"], failure_markers: ["rejected"], max_mutations: 80,
};
const plan = plugin.plan(input, context());
const mutations = Array.from(plan.result.mutations, (item) => item.name);
for (const required of [
  "origin-remove", "origin-cross-site", "referer-remove", "referer-cross-site",
  "query-duplicate-invalid-first:csrf", "query-duplicate-invalid-last:csrf",
  "header-duplicate-invalid-first:X-CSRF-Token", "header-duplicate-invalid-last:X-CSRF-Token",
  "body-duplicate-invalid-first:csrf_token", "body-duplicate-invalid-last:csrf_token",
  "content-type-remove", "content-type-text-plain", "method-get-empty-body", "cross-session-original-token",
]) assert.ok(mutations.includes(required), `missing mutation ${required}`);
const crossSession = plan.operations.find((op) => op.id.startsWith(`mutation-${mutations.indexOf("cross-session-original-token")}-`));
assert.ok(crossSession.header_tombstones.includes("Cookie"));
assert.ok(crossSession.headers.some((header) => header.name === "Cookie" && header.value === "sid=secondary"));
const bodyDuplicate = plan.operations.find((op) => op.id.startsWith(`mutation-${mutations.indexOf("body-duplicate-invalid-first:csrf_token")}-`));
const duplicateText = Buffer.from(bodyDuplicate.body_base64, "base64").toString();
assert.match(duplicateText, /csrf_token=huntproxy-invalid-csrf&csrf_token=body-good/);

const observations = plan.operations.map((operation) => observation(operation));
const originIndex = mutations.indexOf("origin-cross-site");
for (const item of observations.filter((entry) => entry.id.startsWith(`mutation-${originIndex}-`))) {
  item.response_body_hash = null;
  item.response_preview.text = `profile updated at 2026-08-08T08:00:${item.id.endsWith("0") ? "01" : "02"}Z token=${item.id}`;
  item.response_length = item.response_preview.text.length;
}
const invalidIndex = mutations.indexOf("body-invalid:csrf_token");
for (const item of observations.filter((entry) => entry.id.startsWith(`mutation-${invalidIndex}-`))) {
  item.status_code = 403; item.response_body_hash = "rejected"; item.response_preview.text = "request rejected";
}
const result = plugin.analyze(input, observations, context());
assert.ok(result.findings.some((finding) => finding.metadata.mutation === "origin-cross-site"), "dynamic successful responses compare semantically");
assert.ok(!result.findings.some((finding) => finding.metadata.mutation === "body-invalid:csrf_token"), "rejected token controls do not become findings");
assert.ok(result.result.outcomes.some((outcome) => outcome.kind === "session-binding"));

const failed = plan.operations.map((operation) => observation(operation));
failed.find((item) => item.id === "baseline-0").error = "transport failed";
assert.equal(plugin.analyze(input, failed, context()).result.baseline_stable, false);

console.log("CSRFAnalyzer hardening tests passed.");
