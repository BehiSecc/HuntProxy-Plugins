import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const root = new URL("../plugins/", import.meta.url);
async function load(id) {
  const source = await readFile(new URL(`${id}/index.js`, root), "utf8");
  const sandbox = { globalThis: {} };
  vm.runInNewContext(source, sandbox, { timeout: 250 });
  return sandbox.globalThis.HuntProxyPlugin;
}
function context(url = "https://example.test/account") {
  return { api_version: 1, action: "scan", base_exchange: { exchange_id: 42, method: "GET", url, headers: [] }, related_exchanges: [], resources: {} };
}

{
  const plugin = await load("request-smuggler");
  const ctx = context();
  ctx.base_exchange.raw_request_base64 = Buffer.from("GET /account HTTP/1.1\r\nHost: example.test\r\nCookie: sid=secret\r\n\r\n").toString("base64");
  const input = { marker: "abc12345", confirm_intrusive: true, families: ["cl_te"] };
  const plan = plugin.plan(input, ctx);
  assert.equal(plan.operations.length, 6);
  assert.ok(plan.operations.every((operation) => operation.type === "raw_http1"));
  assert.match(Buffer.from(plan.operations[4].request_base64, "base64").toString(), /Cookie: sid=secret/);
  const observations = plan.operations.map((operation, index) => ({
    id: operation.id,
    raw: {
      exchange_id: index + 200,
      read_outcome: operation.id.startsWith("probe-") ? "timeout" : "idle",
      responses: operation.id.startsWith("control-pipeline") ? [{ status_code: 200 }, { status_code: 200 }] : [{ status_code: 200 }],
    },
  }));
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].metadata.family, "cl_te");
  assert.ok(result.result.limitations.some((value) => /HTTP\/2/.test(value)));
  const all = plugin.plan({ marker: "abc12345", confirm_intrusive: true }, ctx);
  assert.ok(all.result.techniques.some((value) => value.family === "te_te"));
  assert.ok(all.result.techniques.some((value) => value.family === "pause_based"));
  assert.ok(all.operations.some((operation) => operation.options.pause_at_byte > 0));
}

{
  const plugin = await load("racer");
  const input = { allow_state_changes: true, exchange_ids: [42, 43], copies: 1, attempts: 2, technique: "last_byte_sync", expected_max_successes: 1 };
  const plan = plugin.plan(input, context());
  assert.equal(plan.operations[0].technique, "sequential_control");
  assert.equal(plan.operations[1].technique, "last_byte_sync");
  assert.deepEqual(Array.from(plan.operations[1].requests, (request) => request.base_exchange_id), [42, 43]);
  const makeResponses = (start, statuses) => statuses.map((status, index) => ({ id: `request-${index}`, exchange_id: start + index, status_code: status, response_length: 10, response_body_hash: status === 200 ? "ok" : "denied", duration_ms: 20, error: null }));
  const observations = [
    { id: "control-0", technique: "sequential_control", attempt: 0, synchronized: false, release_skew_ms: null, responses: makeResponses(300, [200, 409]) },
    { id: "race-0", technique: "last_byte_sync", attempt: 0, synchronized: true, release_skew_ms: 0.5, responses: makeResponses(310, [200, 200]) },
    { id: "race-1", technique: "last_byte_sync", attempt: 1, synchronized: true, release_skew_ms: 0.4, responses: makeResponses(320, [200, 200]) },
  ];
  const result = plugin.analyze(input, observations, context());
  assert.ok(result.findings.some((finding) => /limit overrun/i.test(finding.title)));
  const h2Plan = plugin.plan({ ...input, technique: "h2_single_packet" }, context());
  assert.equal(h2Plan.operations[1].technique, "h2_single_packet");
  assert.match(h2Plan.result.no_fallback, /real HTTP\/2 packet/);
}

console.log("Request Smuggler and Racer VM tests passed.");
