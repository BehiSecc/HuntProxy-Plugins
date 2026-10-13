import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

async function load(name) {
  const source = await readFile(new URL(`../plugins/${name}/index.js`, import.meta.url), "utf8");
  const sandbox = { globalThis: {} };
  vm.runInNewContext(source, sandbox, { timeout: 250 });
  return sandbox.globalThis.HuntProxyPlugin;
}

const auth = await load("auth-analyzer");
const input = { primary: { cookie: "sid=one" }, secondary: { cookie: "sid=two" }, domains: ["example.test"] };
const shape = (exchange_id, method = "GET", url = "https://example.test/account") => ({ exchange_id, method, url, status_code: 200 });
const context = (base = shape(42), related = [], action = "scan") => ({ action, base_exchange: base, related_exchanges: related });
const observations = (plan) => plan.operations.map((op, index) => ({
  id: op.id, exchange_id: 100 + index, status_code: op.id.includes("anonymous") ? 403 : 200,
  response_preview: { text: op.id.includes("anonymous") ? "sign in" : "account details" },
}));

for (const action of ["scan", "anonymous_audit"]) {
  const ctx = context(shape(42, "POST"), [], action);
  const actionInput = action === "scan" ? input : { domains: input.domains, confirm_expected_protected: true };
  const plan = auth.plan(actionInput, ctx);
  assert.equal(plan.operations.length, 0);
  assert.equal(plan.result.selection.excluded_by_reason.state_change_not_allowed, 1);
  assert.equal(plan.result.selection.exclusions[0].exchange_id, 42);
  assert.equal(plan.result.selection.exclusions[0].method, "POST");
  const result = auth.analyze(actionInput, [], ctx).result;
  assert.equal(result.tested_operations, 0);
  assert.equal(result.coverage.status, "no_executed_coverage");
  assert.equal(result.coverage.planned_operations, 0);
  assert.equal(result.selection.excluded_by_reason.state_change_not_allowed, 1);
  const optedIn = auth.plan({ ...actionInput, allow_state_changes: true }, ctx);
  assert.equal(optedIn.operations.length, action === "scan" ? 6 : 2);
}

const selectionContext = context(shape(42), [shape(42), shape(43, "POST"), shape(44, "GET", "https://other.test/account?token=private"), shape(45)]);
const selectionPlan = auth.plan({ ...input, max_requests: 1 }, selectionContext);
assert.equal(selectionPlan.operations.length, 6, "max_requests remains a request-shape limit");
assert.equal(selectionPlan.result.planned_operations, 6);
assert.equal(selectionPlan.result.selection.selected_shapes, 1);
assert.equal(auth.analyze({ ...input, max_requests: 1 }, observations(selectionPlan), selectionContext).result.coverage.scope, "selected_request_shapes");
assert.equal(auth.plan({ ...input, max_requests: 1.5 }, selectionContext).result.request_shapes, 1);
assert.throws(() => auth.plan({ ...input, max_requests: "unknown" }, selectionContext), /finite request-shape limit/);
assert.deepEqual(JSON.parse(JSON.stringify(selectionPlan.result.selection.excluded_by_reason)), {
  duplicate_exchange: 1, state_change_not_allowed: 1, outside_domains: 1, max_requests: 1,
});
assert.ok(!JSON.stringify(selectionPlan.result.selection).includes("token=private"), "exclusions contain only exchange references, methods and reasons");

const ctx = context();
const plan = auth.plan(input, ctx);
const normal = observations(plan);
const normalResult = auth.analyze(input, normal, ctx).result;
assert.equal(normalResult.tested_operations, 6);
assert.equal(normalResult.coverage.status, "complete");
assert.equal(normalResult.classifications[0].controls.primary.captured_status_match, true);
assert.equal(normalResult.classifications[0].controls.primary.captured_response_match, "not_evaluated");

const skipped = normal.map((item) => ({ id: item.id, skipped: { reason: "previous operation failed" } }));
const skippedResult = auth.analyze(input, skipped, ctx).result;
assert.equal(skippedResult.tested_operations, 0);
assert.equal(skippedResult.coverage.skipped_operations, 6);
assert.equal(skippedResult.coverage.status, "no_executed_coverage");
assert.equal(skippedResult.classifications[0].primary_outcome, "inconclusive");

const failed = normal.map((item) => ({ ...item, transport_error: "connection closed" }));
assert.equal(auth.analyze(input, failed, ctx).result.tested_operations, 0);
assert.equal(auth.analyze(input, failed, ctx).findings.length, 0);

const partial = normal.slice(0, 5);
const partialResult = auth.analyze(input, partial, ctx).result;
assert.equal(partialResult.tested_operations, 5);
assert.equal(partialResult.coverage.missing_operations, 1);
assert.equal(partialResult.coverage.status, "qualified");

const repeated = normal.concat(normal[0], { id: "unrelated", status_code: 200 });
const repeatedResult = auth.analyze(input, repeated, ctx).result;
assert.equal(repeatedResult.tested_operations, 5, "duplicate and unexpected observations never inflate coverage");
assert.equal(repeatedResult.coverage.duplicate_observations, 1);
assert.equal(repeatedResult.coverage.unexpected_observations, 1);
assert.equal(repeatedResult.coverage.status, "qualified");
assert.equal(repeatedResult.classifications[0].primary_outcome, "inconclusive", "duplicate IDs cannot overwrite a control");
const contradictory = normal.concat({ ...normal[0], exchange_id: 999, status_code: 403 });
const contradictoryResult = auth.analyze(input, contradictory, ctx).result;
assert.ok(contradictoryResult.classifications[0].evidence_exchange_ids.includes(normal[0].exchange_id));
assert.ok(contradictoryResult.classifications[0].evidence_exchange_ids.includes(999), "ambiguous observations retain both known exchange references");
assert.equal(auth.analyze(input, normal.concat(null), ctx).result.coverage.unexpected_observations, 1);
assert.equal(auth.analyze(input, normal.concat({ id: "toString", status_code: 200 }), ctx).result.coverage.unexpected_observations, 1);
const invalidStatus = normal.map((item) => ({ ...item, status_code: 200.5 }));
assert.equal(auth.analyze(input, invalidStatus, ctx).result.tested_operations, 0);
assert.equal(auth.analyze(input, invalidStatus, ctx).findings.length, 0);

const truncated = normal.map((item) => ({ ...item, response_body_truncated: true }));
const truncatedResult = auth.analyze(input, truncated, ctx);
assert.equal(truncatedResult.result.tested_operations, 6, "complete status observations remain usable for status-only outcomes");
assert.equal(truncatedResult.result.classifications[0].primary_stable, false);
assert.equal(truncatedResult.result.coverage.status, "qualified");
assert.equal(truncatedResult.findings.length, 0, "truncated response bodies cannot establish equality");
assert.equal(auth.analyze({ ...input, success_markers: ["account"] }, truncated, ctx).result.classifications[0].primary_outcome, "inconclusive");

const denial = normal.map((item) => ({ ...item, status_code: 403, response_preview: { text: "sign in" } }));
const deniedResult = auth.analyze(input, denial, ctx).result;
assert.equal(deniedResult.tested_operations, 6, "a complete denial is an observation, not a transport failure");
assert.equal(deniedResult.classifications[0].controls.primary.captured_status_match, false);
assert.equal(deniedResult.coverage.status, "qualified", "denied primary controls qualify protected-resource coverage");

const smuggler = await load("request-smuggler");
const baselineContext = {
  action: "scan",
  base_exchange: {
    ...shape(42), headers: [],
    raw_request_base64: Buffer.from("GET /account HTTP/1.1\r\nHost: example.test\r\nuSeR-aGeNt: ExampleBrowser/1.0\r\nAccept: text/html\r\n\r\n").toString("base64"),
  },
};
const baselineInput = { marker: "sample123", confirm_intrusive: true, families: ["h2_cl"], repeats: 3, max_techniques: 1 };
const baselinePlan = smuggler.plan(baselineInput, baselineContext);
const baseline = baselinePlan.operations.find((op) => op.id === "h2-direct-base-0");
assert.ok(baseline, "the fixture inspects only an ordinary HTTP/2 baseline");
const userAgents = baseline.streams[0].headers.filter((field) => field.name === "user-agent");
assert.equal(userAgents.length, 1);
assert.equal(userAgents[0].value, "ExampleBrowser/1.0");
assert.ok(baseline.streams[0].headers.some((field) => field.name === "accept" && field.value === "text/html"));

const noAgentContext = { ...baselineContext, base_exchange: { ...baselineContext.base_exchange,
  raw_request_base64: Buffer.from("GET /account HTTP/1.1\r\nHost: example.test\r\n\r\n").toString("base64"),
} };
const fallback = smuggler.plan(baselineInput, noAgentContext).operations.find((op) => op.id === "h2-direct-base-0");
assert.equal(fallback.streams[0].headers.filter((field) => field.name === "user-agent").length, 1);

const baselineAnalysis = smuggler.analyze(baselineInput, [], baselineContext).result;
assert.equal(baselineAnalysis.protocol_baselines.http2.endpoint.usable_attempts, 0);
assert.equal(baselineAnalysis.protocol_baselines.http2.endpoint.captured_response_match, "not_evaluated");
assert.ok(baselineAnalysis.diagnostics.every((item) => item.coverage_qualified));
assert.ok(baselineAnalysis.diagnostics.every((item) => item.baseline_limitations.includes("direct_controls_unstable_or_unavailable")));

function rawObservation(id, status, body, overrides = {}) {
  const wire = `HTTP/1.1 ${status} Test\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  return { id, raw: {
    read_outcome: "idle", response_complete: true,
    response_transcript_base64: Buffer.from(wire).toString("base64"),
    responses: [{ status_code: status, offset: 0, length: wire.length }], ...overrides,
  } };
}
const ordinaryControls = [0, 1].flatMap((repeat) => [
  rawObservation(`direct-base-${repeat}`, 200, "account"),
  rawObservation(`direct-canary-${repeat}`, 404, "missing"),
]);
const ordinaryBaselines = smuggler.analyze(baselineInput, ordinaryControls, baselineContext).result.protocol_baselines.http1;
assert.equal(ordinaryBaselines.endpoint.usable_attempts, 2);
assert.equal(ordinaryBaselines.endpoint.stable, true);
assert.equal(ordinaryBaselines.endpoint.captured_status_match, true);
for (const failure of [
  { read_outcome: "timeout" }, { transport_error: "connection reset" },
  { truncated: true }, { response_complete: false },
]) {
  const retainedControls = ordinaryControls.map((item) => ({ ...item, raw: { ...item.raw, ...failure } }));
  const retainedResult = smuggler.analyze(baselineInput, retainedControls, baselineContext).result;
  assert.equal(retainedResult.protocol_baselines.http1.endpoint.usable_attempts, 0);
  assert.equal(retainedResult.protocol_baselines.http1.endpoint.stable, false);
  assert.ok(retainedResult.protocol_baselines.http1.endpoint.limitations.includes("unusable_response_evidence"));
  assert.ok(retainedResult.diagnostics.every((item) => item.coverage_qualified));
}
for (const invalid of [200.5, "invalid", 99, 600]) {
  const malformed = [0, 1].map((repeat) => rawObservation(`direct-base-${repeat}`, invalid, "account"));
  assert.equal(smuggler.analyze(baselineInput, malformed, baselineContext).result.protocol_baselines.http1.endpoint.usable_attempts, 0);
}

console.log("Plugin baseline and evidence-accounting fixtures passed.");
