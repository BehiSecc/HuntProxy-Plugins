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
assert.equal(plan.execution, "sequential");
assert.deepEqual(Array.from(plan.operations, (operation) => operation.id), ["setup-0", "race-0", "validate-0", "setup-1", "race-1", "validate-1"]);
assert.equal(plan.operations[1].technique, "last_byte_sync");
assert.equal(plan.operations[1].requests.length, 3);
assert.equal(plan.operations[1].requests[0].url, "https://example.test/apply");
assert.equal(plan.operations[1].requests[0].use_project_cookies, true);
assert.equal(plan.operations[1].requests[0].success.body_contains, "coupon applied");
assert.equal(plan.operations[1].requests[2].base_exchange_id, 42);
assert.equal(plan.result.distinct_request_shapes, 2);
assert.equal(plan.result.control_mode, "none");

const templated = racer.plan({
  ...input,
  attempts: 2,
  setup_requests: undefined,
  validation_requests: undefined,
  requests: [{
    id: "register",
    method: "POST",
    url: "https://example.test/register?attempt={attempt}",
    headers: [{ name: "X-Attempt", value: "run-{attempt}" }],
    body_text: "username=user{attempt}&email=user{attempt}%40example.test",
  }],
}, context);
assert.equal(templated.operations[0].requests[0].url, "https://example.test/register?attempt=0");
assert.equal(templated.operations[1].requests[0].headers[0].value, "run-1");
assert.match(templated.operations[1].requests[0].body_text, /username=user1/);
assert.throws(() => racer.plan({
  ...input,
  attempts: 1,
  setup_requests: undefined,
  validation_requests: undefined,
  requests: [{ url: "https://example.test/", body_base64: "{attempt}" }],
}, context), /not supported in body_base64/);

const extracted = racer.plan({
  ...input,
  attempts: 2,
  control_mode: "none",
  setup_requests: [{
    id: "csrf",
    method: "GET",
    url: "https://example.test/form?attempt={attempt}",
    extract: [{ from: "body_regex", name: "csrf", pattern: "name=csrf value=([^&]+)", group: 1, encoding: "url" }],
  }],
  requests: [{
    id: "submit",
    method: "POST",
    url: "https://example.test/submit?csrf={{extract:csrf}}",
    headers: [{ name: "X-CSRF", value: "{{extract:csrf}}" }],
    body_text: "csrf={{extract:csrf}}&attempt={attempt}",
  }],
  validation_requests: [{ method: "GET", url: "https://example.test/state?csrf={{extract:csrf}}" }],
}, context);
assert.equal(extracted.execution, "sequential");
assert.equal(extracted.stop_on_error, true);
assert.equal(extracted.result.setup_extracts_per_attempt, 1);
assert.equal(extracted.operations[0].requests[0].extract[0].name, "csrf.attempt0");
assert.equal(extracted.operations[1].requests[0].url, "https://example.test/submit?csrf={{extract:csrf.attempt0}}");
assert.equal(extracted.operations[1].requests[0].headers[0].value, "{{extract:csrf.attempt0}}");
assert.equal(extracted.operations[1].requests[0].body_text, "csrf={{extract:csrf.attempt0}}&attempt=0");
assert.equal(extracted.operations[2].requests[0].url, "https://example.test/state?csrf={{extract:csrf.attempt0}}");
assert.equal(extracted.operations[3].requests[0].extract[0].name, "csrf.attempt1");
assert.equal(extracted.operations[4].requests[0].url, "https://example.test/submit?csrf={{extract:csrf.attempt1}}");
assert.throws(() => racer.plan({
  ...input,
  control_mode: "none",
  setup_requests: [{ url: "https://example.test/form", copies: 2, extract: [{ from: "header", name: "csrf", header: "X-CSRF" }] }],
  requests: [{ url: "https://example.test/submit", body_text: "csrf={{extract:csrf}}" }],
}, context), /copies=1/);
assert.throws(() => racer.plan({
  ...input,
  control_mode: "none",
  setup_requests: undefined,
  requests: [{ url: "https://example.test/submit", body_text: "csrf={{extract:missing}}" }],
}, context), /not produced/);
assert.throws(() => racer.plan({
  ...input,
  control_mode: "none",
  setup_requests: [{ url: "https://example.test/form", extract: [{ from: "header", name: "csrf", header: "X-CSRF" }] }],
  requests: [{ url: "https://example.test/submit", extract: [{ from: "header", name: "later", header: "X-Later" }] }],
}, context), /only on setup_requests/);

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

const oneHit = racer.analyze(input, [
  observations[0],
  observations[1],
  observations[2],
  observations[3],
  group("race-1", [response("a", 111, true), response("b", 112, false), response("c", 113, false)], true),
  observations[5],
], context);
assert.equal(oneHit.findings.length, 1);
assert.equal(oneHit.findings[0].confidence, "tentative");

const rejected = observations.map((observation) => observation.id.startsWith("race-")
  ? { ...observation, responses: observation.responses.map((item) => ({ ...item, success: { matched: false } })) }
  : observation);
assert.equal(racer.analyze(input, rejected, context).findings.length, 0, "HTTP 200 alone must not count when semantic predicates are present");

const sequential = racer.plan({ ...input, technique: "sequential", attempts: 1, setup_requests: undefined, validation_requests: undefined }, context);
assert.equal(sequential.operations[0].technique, "sequential_control");
assert.equal(racer.analyze({ ...input, technique: "sequential", attempts: 1 }, [group("race-0", [response("a", 1, true), response("b", 2, true)])], context).findings.length, 0);

const h2 = racer.plan({ ...input, technique: "h2_single_packet", attempts: 1 }, context);
const h2Controlled = racer.plan({ ...input, technique: "h2_single_packet", attempts: 1, control_mode: "single_each" }, context);
assert.equal(h2Controlled.operations.find((operation) => operation.id === "control-0").attempt, 0);
assert.equal(h2.operations[1].technique, "h2_single_packet");
assert.match(h2.result.no_fallback, /real HTTP\/2 packet/);
const h2Result = racer.analyze(
  { ...input, technique: "h2_single_packet", attempts: 1 },
  [group("race-0", [response("a", 201, true), response("b", 202, true)], true)],
  context,
);
assert.match(h2Result.result.synchronization, /ALPN h2/);
assert.equal("host_blocker" in h2Result.result, false);
const operationError = racer.analyze(
  { ...input, technique: "h2_single_packet", attempts: 1, control_mode: "none" },
  [{ id: "race-0", error: { code: "protocol_incompatible", message: "h2 unavailable" } }],
  context,
);
assert.equal(operationError.result.diagnostics[0].errors[0].code, "protocol_incompatible");

assert.throws(() => racer.plan({ ...input, requests: [{ url: "https://example.test", body_text: "a", body_base64: "Yg==" }] }, context), /cannot combine/);

console.log("Racer advanced VM tests passed.");
