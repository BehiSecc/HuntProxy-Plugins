import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("../plugins/racer/index.js", import.meta.url), "utf8");
const sandbox = { globalThis: {} };
vm.runInNewContext(source, sandbox, { timeout: 250 });
const racer = sandbox.globalThis.HuntProxyPlugin;
const context = { api_version: 1, action: "run", base_exchange: null, related_exchanges: [], resources: {} };

const semanticSuccess = { body_contains: "coupon applied" };
const input = {
  allow_state_changes: true,
  technique: "last_byte_sync",
  control_mode: "none",
  attempts: 2,
  expected_max_successes: 1,
  requests: [
    { id: "apply", method: "POST", url: "https://example.test/apply", body_text: "code=ONE", copies: 2, success: semanticSuccess },
    { id: "confirm", base_exchange_id: 42, url: "https://example.test/confirm", copies: 1, success: { json: [{ pointer: "/confirmed", equals: true }] } },
  ],
  setup_requests: [{ id: "reset", method: "POST", url: "https://example.test/reset", success: { status_codes: [204] } }],
  validation_requests: [{ id: "state", method: "GET", url: "https://example.test/state", success: { json: [{ pointer: "/violated", equals: true }] } }],
};

const plan = racer.plan(input, context);
assert.deepEqual(Array.from(plan.operations, (operation) => operation.id), ["setup-0", "race-0", "validate-0", "setup-1", "race-1", "validate-1"]);
assert.equal(plan.operations[1].technique, "last_byte_sync");
assert.equal(plan.operations[1].requests.length, 3);
assert.equal(plan.operations[1].requests[0].url, "https://example.test/apply");
assert.equal(plan.operations[1].requests[0].use_project_cookies, true);
assert.equal(plan.operations[1].requests[0].success.body_contains, "coupon applied");
assert.equal(plan.operations[1].requests[2].base_exchange_id, 42);
assert.equal(plan.result.distinct_request_shapes, 2);
assert.equal(plan.result.control_mode, "none");

function response(id, exchangeId, matched, hash = "same") {
  return { id, exchange_id: exchangeId, status_code: 200, response_length: 10, response_body_hash: hash, success: { matched, checks: [] }, error: null };
}
function group(id, responses, synchronized = false) {
  return { id, technique: synchronized ? "last_byte_sync" : "sequential_control", synchronized, release_skew_ms: synchronized ? 0.2 : null, responses };
}
const observations = [
  group("setup-0", [response("reset", 100, true)]),
  group("race-0", [response("a", 101, true), response("b", 102, true), response("c", 103, false)], true),
  group("validate-0", [response("state", 104, true)]),
  group("setup-1", [response("reset", 110, true)]),
  group("race-1", [response("a", 111, true), response("b", 112, true), response("c", 113, false)], true),
  group("validate-1", [response("state", 114, true)]),
];
const result = racer.analyze(input, observations, context);
assert.equal(result.findings.length, 1);
assert.equal(result.findings[0].metadata.control_mode, "none");
assert.equal(result.result.diagnostics[0].semantic_success_used, true);
assert.equal(result.result.diagnostics[0].validation_passed, true);
assert.ok(result.findings[0].evidence_exchange_ids.includes(104));

const rejected = observations.map((observation) => observation.id.startsWith("race-")
  ? { ...observation, responses: observation.responses.map((item) => ({ ...item, success: { matched: false } })) }
  : observation);
assert.equal(racer.analyze(input, rejected, context).findings.length, 0, "HTTP 200 alone must not count when semantic predicates are present");

const sequential = racer.plan({ ...input, technique: "sequential", attempts: 1, setup_requests: undefined, validation_requests: undefined }, context);
assert.equal(sequential.operations[0].technique, "sequential_control");
assert.equal(racer.analyze({ ...input, technique: "sequential", attempts: 1 }, [group("race-0", [response("a", 1, true), response("b", 2, true)])], context).findings.length, 0);

const h2 = racer.plan({ ...input, technique: "h2_single_packet", attempts: 1 }, context);
assert.equal(h2.operations[1].technique, "h2_single_packet");
assert.match(h2.result.no_fallback, /real HTTP\/2 packet/);

assert.throws(() => racer.plan({ ...input, requests: [{ url: "https://example.test", body_text: "a", body_base64: "Yg==" }] }, context), /cannot combine/);

console.log("Racer advanced VM tests passed.");
