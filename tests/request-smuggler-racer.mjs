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
  const input = { marker: "abc12345", confirm_intrusive: true, families: ["cl_te"], repeats: 3 };
  const plan = plugin.plan(input, ctx);
  assert.equal(plan.operations.length, 16);
  assert.ok(plan.operations.every((operation) => operation.type === "raw_http1"));
  const attack = Buffer.from(plan.operations.find((operation) => operation.id === "probe-0-0").request_base64, "base64").toString();
  assert.doesNotMatch(attack, /Cookie: sid=secret/);
  assert.match(attack, /Content-Length: [0-9]+\r\nTransfer-Encoding: chunked/);
  assert.match(attack, /GET \/hp-abc12345-not-found HTTP\/1\.1/);
  const authenticated = plugin.plan({ ...input, include_auth: true }, ctx);
  assert.match(Buffer.from(authenticated.operations.find((operation) => operation.id === "probe-0-0").request_base64, "base64").toString(), /Cookie: sid=secret/);
  const teCl = plugin.plan({ ...input, families: ["te_cl"] }, ctx);
  const teClAttack = Buffer.from(teCl.operations.find((operation) => operation.id === "probe-0-0").request_base64, "base64").toString();
  assert.match(teClAttack, /POST \/hp-abc12345-not-found HTTP\/1\.1/);
  assert.match(teClAttack, /Content-Length: 15\r\n\r\n\r\n0\r\n\r\n$/);

  function wire(responses) {
    let transcript = ""; const summaries = [];
    for (const response of responses) {
      const bytes = `HTTP/1.1 ${response.status} Test\r\nContent-Length: ${response.body.length}\r\n\r\n${response.body}`;
      summaries.push({ status_code: response.status, offset: transcript.length, length: bytes.length }); transcript += bytes;
    }
    return { read_outcome: "idle", responses: summaries, response_transcript_base64: Buffer.from(transcript).toString("base64") };
  }
  const observations = plan.operations.map((operation, index) => {
    const responses = operation.id.startsWith("direct-canary") ? [{ status: 404, body: "unique canary page" }]
      : operation.id === "control-0-1" ? [{ status: 200, body: "globally changed account state" }]
      : operation.id.startsWith("control-") || operation.id.startsWith("recovery-") ? [{ status: 200, body: "normal account" }]
      : operation.id.startsWith("victim-") ? [{ status: 404, body: "unique canary page" }]
      : operation.id.startsWith("probe-") ? [{ status: 200, body: "normal account" }]
      : [{ status: 200, body: "normal account" }];
    return { id: operation.id, raw: { exchange_id: index + 200, ...wire(responses) } };
  });
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].metadata.family, "cl_te");
  assert.equal(result.findings[0].metadata.signal, "marker_contamination");
  assert.ok(result.result.limitations.some((value) => /HTTP\/2/.test(value)));
  const all = plugin.plan({ marker: "abc12345", confirm_intrusive: true }, ctx);
  assert.ok(all.result.techniques.some((value) => value.family === "te_te"));
  assert.ok(all.result.techniques.some((value) => value.family === "cl_0"));
  assert.ok(all.result.limitations.some((value) => /Pause-based/.test(value)));
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
