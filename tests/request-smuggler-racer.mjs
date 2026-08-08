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
  assert.equal(plan.execution, "sequential");
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
  const clZero = plugin.plan({ ...input, families: ["cl_0"], probe_path: "/resources/images/blog.svg" }, ctx);
  const clZeroAttack = Buffer.from(clZero.operations.find((operation) => operation.id === "probe-0-0").request_base64, "base64").toString();
  assert.match(clZeroAttack, /GET \/hp-abc12345-not-found HTTP\/1\.1\r\nX-HuntProxy-Desync: abc12345GET \/resources\/images\/blog\.svg HTTP\/1\.1/);
  assert.doesNotMatch(clZeroAttack, /GET \/hp-abc12345-not-found HTTP\/1\.1\r\nHost:/);
  const pooled = plugin.plan({ ...input, families: ["cl_te", "te_cl"] }, ctx);
  const firstPooledProbe = pooled.operations.findIndex((operation) => operation.id.startsWith("probe-"));
  assert.ok(pooled.operations.filter((operation) => operation.id.startsWith("control-")).every((operation) => pooled.operations.indexOf(operation) < firstPooledProbe));
  assert.ok(pooled.operations.findIndex((operation) => operation.id === "control-1-2") < firstPooledProbe, "all selected techniques establish controls before any probe");
  assert.ok(pooled.operations.findIndex((operation) => operation.id === "observer-0-0-0") > pooled.operations.findIndex((operation) => operation.id === "probe-0-0"));
  assert.equal(pooled.operations.some((operation) => /^(victim|recovery)-/.test(operation.id)), false, "post-pair observations are never reused as controls");
  const zeroCl = plugin.plan({ ...input, families: ["0_cl"], probe_path: "/resources/images/blog.svg" }, ctx);
  const zeroClPair = zeroCl.operations.find((operation) => operation.id === "pair-0-0");
  assert.equal(zeroClPair.type, "raw_http1_group");
  assert.deepEqual(Array.from(zeroClPair.members, (member) => member.id), ["probe-0-0", "victim-0-0"]);
  const zeroClEarly = Buffer.from(zeroClPair.members[0].request_base64, "base64").toString();
  const zeroClVictim = Buffer.from(zeroClPair.members[1].request_base64, "base64").toString();
  assert.match(zeroClEarly, /Content-Length : 45\r\n/);
  assert.match(zeroClVictim, /^GET \/resources\/images\/blog\.svg HTTP\/1\.1\r\nX: yGET \/hp-abc12345-not-found HTTP\/1\.1/);
  assert.equal(zeroClPair.members[1].options.pause_at_byte, 1);
  assert.equal(zeroClPair.members[1].options.pause_ms, 50);
  assert.equal(Buffer.from(zeroCl.operations.find((operation) => operation.id === "control-0-0").request_base64, "base64").toString(), zeroClVictim);
  assert.equal(zeroCl.result.techniques.length, 26);
  assert.equal(zeroCl.result.request_count, 394);
  assert.ok(zeroCl.operations.indexOf(zeroCl.operations.find((operation) => operation.id === "control-0-2")) < zeroCl.operations.indexOf(zeroClPair));
  assert.ok(zeroCl.operations.indexOf(zeroCl.operations.find((operation) => operation.id === "control-25-2")) < zeroCl.operations.indexOf(zeroClPair));
  assert.equal(zeroCl.operations.filter((operation) => operation.id.startsWith("observer-0-")).length, 6);
  const connectionState = plugin.plan({ ...input, families: ["connection_state"], connection_state_host: "192.0.2.10", connection_state_path: "/admin" }, ctx);
  const connectionProbe = Buffer.from(connectionState.operations.find((operation) => operation.id === "probe-0-0").request_base64, "base64").toString();
  assert.match(connectionProbe, /^GET \/account HTTP\/1\.1/);
  assert.match(connectionProbe, /GET \/admin HTTP\/1\.1\r\nHost: 192\.0\.2\.10/);

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
      : operation.id.startsWith("control-") ? [{ status: 200, body: "normal account" }]
      : operation.id.startsWith("observer-") && operation.id.endsWith("-0") ? [{ status: 404, body: "unique canary page" }]
      : operation.id.startsWith("probe-") ? [{ status: 200, body: "normal account" }]
      : [{ status: 200, body: "normal account" }];
    return { id: operation.id, raw: { exchange_id: index + 200, ...wire(responses) } };
  });
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].metadata.family, "cl_te");
  assert.equal(result.findings[0].metadata.signal, "marker_contamination");
  assert.ok(result.result.limitations.some((value) => /HTTP\/2/.test(value)));
  const zeroClObservations = zeroCl.operations.map((operation, index) => {
    if (operation.type === "raw_http1_group") return {
      id: operation.id,
      dispatch: "parallel_barrier",
      members: operation.members.map((member, memberIndex) => ({ id: member.id, raw: { exchange_id: 350 + index * 2 + memberIndex, ...wire([{ status: member.id.startsWith("victim-") ? 404 : 200, body: member.id.startsWith("victim-") ? "canary" : "normal account" }]) } })),
    };
    const responses = operation.id.startsWith("direct-canary") ? [{ status: 404, body: "canary" }]
      : operation.id.startsWith("control-") ? [{ status: 200, body: "normal account" }]
      : [{ status: 200, body: "normal account" }];
    return { id: operation.id, raw: { exchange_id: 350 + index, ...wire(responses) } };
  });
  const zeroClResult = plugin.analyze({ ...input, families: ["0_cl"], probe_path: "/resources/images/blog.svg" }, zeroClObservations, ctx);
  assert.equal(zeroClResult.findings.length, 26);
  assert.equal(zeroClResult.findings[0].metadata.family, "0_cl");
  const unstableInput = { ...input, families: ["0_cl"], repeats: 5, max_techniques: 1, zero_cl_offsets: [4], zero_cl_delay_ms: 75, probe_path: "/resources/images/blog.svg" };
  const unstablePlan = plugin.plan(unstableInput, ctx);
  assert.equal(unstablePlan.operations.find((operation) => operation.type === "raw_http1_group").members[1].options.pause_ms, 75);
  const unstableObservations = unstablePlan.operations.map((operation, index) => {
    if (operation.type === "raw_http1_group") return {
      id: operation.id,
      dispatch: "parallel_barrier",
      members: operation.members.map((member, memberIndex) => {
        const divergent = member.id.startsWith("victim-") && /-(0|1)$/.test(member.id);
        return { id: member.id, raw: { exchange_id: 700 + index * 2 + memberIndex, ...wire([{ status: divergent ? 400 : 200, body: divergent ? "invalid request" : "normal account" }]) } };
      }),
    };
    const responses = operation.id.startsWith("direct-canary") ? [{ status: 404, body: "canary" }] : [{ status: 200, body: "normal account" }];
    return { id: operation.id, raw: { exchange_id: 700 + index, ...wire(responses) } };
  });
  const unstableResult = plugin.analyze(unstableInput, unstableObservations, ctx);
  assert.equal(unstableResult.findings.length, 1);
  assert.equal(unstableResult.findings[0].confidence, "tentative");
  assert.equal(unstableResult.findings[0].metadata.signal, "victim_divergence");
  const delayedMarkerObservations = unstablePlan.operations.map((operation, index) => {
    if (operation.type === "raw_http1_group") return {
      id: operation.id,
      dispatch: "parallel_barrier",
      members: operation.members.map((member, memberIndex) => ({ id: member.id, raw: { exchange_id: 800 + index * 2 + memberIndex, ...wire([{ status: 200, body: "normal account" }]) } })),
    };
    const delayedCanary = operation.id === "observer-0-3-0";
    const directCanary = operation.id.startsWith("direct-canary");
    const responses = delayedCanary || directCanary ? [{ status: 404, body: "canary" }] : [{ status: 200, body: "normal account" }];
    return { id: operation.id, raw: { exchange_id: 800 + index, ...wire(responses) } };
  });
  const delayedMarkerResult = plugin.analyze(unstableInput, delayedMarkerObservations, ctx);
  assert.equal(delayedMarkerResult.findings.length, 1);
  assert.equal(delayedMarkerResult.findings[0].confidence, "tentative");
  assert.equal(delayedMarkerResult.findings[0].metadata.signal, "marker_contamination_unstable");
  assert.equal(delayedMarkerResult.findings[0].metadata.confirmations, 1);
  const uniformEdgeObservations = unstablePlan.operations.map((operation, index) => {
    if (operation.type === "raw_http1_group") return {
      id: operation.id,
      dispatch: "parallel_barrier",
      members: operation.members.map((member, memberIndex) => ({ id: member.id, raw: { exchange_id: 900 + index * 2 + memberIndex, ...wire([{ status: 504, body: "edge timeout" }]) } })),
    };
    return { id: operation.id, raw: { exchange_id: 900 + index, ...wire([{ status: 504, body: "edge timeout" }]) } };
  });
  const uniformEdgeResult = plugin.analyze(unstableInput, uniformEdgeObservations, ctx);
  assert.equal(uniformEdgeResult.findings.length, 0);
  assert.equal(uniformEdgeResult.result.diagnostics[0].canary_confirmations, 0, "a non-distinct canary baseline cannot increment confirmations");
  const connectionObservations = connectionState.operations.map((operation, index) => {
    const responses = operation.id.startsWith("direct-canary") ? [{ status: 404, body: "canary" }]
      : operation.id.startsWith("control-") ? [{ status: 421, body: "invalid host" }]
      : operation.id.startsWith("probe-") ? [{ status: 200, body: "normal account" }, { status: 200, body: "admin" }]
      : [{ status: 200, body: "normal account" }];
    return { id: operation.id, raw: { exchange_id: 400 + index, ...wire(responses) } };
  });
  const connectionResult = plugin.analyze({ ...input, families: ["connection_state"], connection_state_host: "192.0.2.10", connection_state_path: "/admin" }, connectionObservations, ctx);
  assert.equal(connectionResult.findings[0].metadata.family, "connection_state");
  const pauseInput = { ...input, families: ["pause"], probe_path: "/resources", pause_ms: 61000 };
  const pausePlan = plugin.plan(pauseInput, ctx);
  const pauseOperation = pausePlan.operations.find((operation) => operation.id === "probe-0-0");
  const pauseBytes = Buffer.from(pauseOperation.request_base64, "base64").toString();
  assert.equal(pauseOperation.options.pause_ms, 61000);
  assert.equal(pauseOperation.options.pause_at_byte, pauseBytes.indexOf("\r\n\r\n") + 4);
  assert.equal(pauseOperation.options.await_response_before_continue, false);
  assert.equal((pauseBytes.match(/POST \/resources HTTP\/1\.1/g) || []).length, 2);
  const pauseObservations = pausePlan.operations.map((operation, index) => {
    const responses = operation.id.startsWith("direct-canary") ? [{ status: 404, body: "canary" }]
      : operation.id.startsWith("probe-") ? [{ status: 301, body: "redirect" }, { status: 404, body: "canary" }]
      : [{ status: 200, body: "normal" }];
    return { id: operation.id, raw: { exchange_id: 450 + index, ...wire(responses) } };
  });
  assert.equal(plugin.analyze(pauseInput, pauseObservations, ctx).findings[0].metadata.family, "pause");
  const all = plugin.plan({ marker: "abc12345", confirm_intrusive: true }, ctx);
  assert.ok(all.result.techniques.some((value) => value.family === "te_te"));
  assert.ok(all.result.techniques.some((value) => value.family === "cl_0"));
  assert.ok(all.result.limitations.some((value) => /Pause-based/.test(value)));

  const teTeInput = { ...input, families: ["te_te"], repeats: 5 };
  const teTePlan = plugin.plan(teTeInput, ctx);
  const largeNormal = "normal-page-".repeat(1200);
  const largeCanary = "canary-page-".repeat(1200);
  const teTeObservations = teTePlan.operations.map((operation, index) => {
    const responses = operation.id.startsWith("direct-canary") || operation.id.startsWith("observer-")
      ? [{ status: 404, body: largeCanary }]
      : [{ status: 200, body: largeNormal }];
    return { id: operation.id, raw: { exchange_id: 500 + index, ...wire(responses) } };
  });
  const started = performance.now();
  const teTeResult = plugin.analyze(teTeInput, teTeObservations, ctx);
  assert.ok(performance.now() - started < 250, "TE.TE analysis must stay well below the host JavaScript stage budget");
  assert.equal(teTeResult.result.diagnostics.length, 12);

  const h2Input = { ...input, families: ["h2_cl"], repeats: 3 };
  const h2Plan = plugin.plan(h2Input, ctx);
  assert.ok(h2Plan.operations.every((operation) => operation.type === "raw_http1" || operation.type === "raw_http2"));
  const h2Probe = h2Plan.operations.find((operation) => operation.id === "probe-0-0");
  assert.equal(h2Probe.type, "raw_http2");
  assert.deepEqual(Array.from(h2Probe.streams[0].headers, (header) => [header.name, header.value]).slice(0, 4), [
    [":method", "POST"], [":scheme", "https"], [":authority", "example.test"], [":path", "/account"],
  ]);
  assert.ok(h2Probe.streams[0].headers.some((header) => header.name === "content-length" && header.value === "0"));
  assert.match(h2Probe.streams[0].body_text, /^GET \/hp-abc12345-not-found HTTP\/1\.1/);
  function h2Observation(operation, index) {
    const status = operation.id.startsWith("h2-direct-canary") || operation.id.startsWith("observer-") ? 404 : 200;
    return operation.type === "raw_http2" ? { id: operation.id, protocol: "h2", timed_out: false, streams: [{ id: `${operation.id}-stream`, exchange_id: 900 + index, status_code: status, response_body_base64: Buffer.from(status === 404 ? "canary" : "normal").toString("base64") }] }
      : { id: operation.id, raw: { exchange_id: 900 + index, ...wire([{ status: 200, body: "normal" }]) } };
  }
  const h2Result = plugin.analyze(h2Input, h2Plan.operations.map(h2Observation), ctx);
  assert.equal(h2Result.findings[0].metadata.family, "h2_cl");
  assert.match(h2Result.findings[0].title, /HTTP\/2/);
  const tunnel = plugin.plan({ ...input, families: ["h2_tunnel"], repeats: 3 }, ctx);
  const nameTunnel = tunnel.operations.find((operation) => operation.id === "probe-0-0").streams[0];
  const pathTunnel = tunnel.operations.find((operation) => operation.id === "probe-1-0").streams[0];
  const hostInjection = tunnel.operations.find((operation) => operation.id === "probe-2-0").streams[0];
  assert.ok(nameTunnel.headers.some((header) => header.name.includes("\r\n\r\nGET")));
  assert.ok(pathTunnel.headers.some((header) => header.name === ":path" && header.value.includes("\r\n\r\nGET")));
  assert.ok(hostInjection.headers.some((header) => header.name.includes("\r\nHost: abc12345.example.test")));
  const tunnelObservations = tunnel.operations.map((operation, index) => {
    if (operation.type !== "raw_http2") return { id: operation.id, raw: { exchange_id: 1100 + index, ...wire([{ status: 200, body: "normal" }]) } };
    const canary = operation.id.startsWith("h2-direct-canary"), nested = operation.id.startsWith("probe-");
    const body = nested ? "prefix HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" : (canary ? "canary" : "normal");
    return { id: operation.id, protocol: "h2", timed_out: false, streams: [{ id: `${operation.id}-stream`, exchange_id: 1100 + index, status_code: canary ? 404 : 200, response_length: body.length, response_body_hash: canary ? "canary-hash" : (nested ? "nested-hash" : "base-hash"), response_body_base64: Buffer.from(body).toString("base64") }] };
  });
  const tunnelStarted = performance.now();
  const tunnelResult = plugin.analyze({ ...input, families: ["h2_tunnel"], repeats: 3 }, tunnelObservations, ctx);
  assert.equal(tunnelResult.findings.length, 3);
  assert.ok(performance.now() - tunnelStarted < 250, "H2 tunnelling analysis must stay below the host JavaScript stage budget");
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
