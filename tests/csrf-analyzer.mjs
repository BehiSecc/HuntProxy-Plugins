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
  paired_cookie_tests: [{ name: "double-submit", identity: { cookie: "sid=victim; csrf=paired" }, token: { location: "body", name: "csrf_token", value: "paired" } }],
  success_markers: ["updated"], failure_markers: ["rejected"], max_mutations: 80,
};
const plan = plugin.plan(input, context());
const mutations = Array.from(plan.result.mutations, (item) => item.name);
for (const required of [
  "origin-remove", "origin-cross-site", "referer-remove", "referer-cross-site",
  "origin-cross-site+token-remove", "referer-cross-site+token-remove", "control-invalid-all-tokens",
  "query-duplicate-invalid-first:csrf", "query-duplicate-invalid-last:csrf",
  "header-duplicate-invalid-first:X-CSRF-Token", "header-duplicate-invalid-last:X-CSRF-Token",
  "body-duplicate-invalid-first:csrf_token", "body-duplicate-invalid-last:csrf_token",
  "content-type-remove", "content-type-text-plain", "method-get-form-query", "cross-session-original-token", "paired-cookie:double-submit",
]) assert.ok(mutations.includes(required), `missing mutation ${required}`);
const crossSession = plan.operations.find((op) => op.id.startsWith(`mutation-${mutations.indexOf("cross-session-original-token")}-`));
assert.ok(crossSession.header_tombstones.includes("Cookie"));
assert.ok(crossSession.headers.some((header) => header.name === "Cookie" && header.value === "sid=secondary"));
const bodyDuplicate = plan.operations.find((op) => op.id.startsWith(`mutation-${mutations.indexOf("body-duplicate-invalid-first:csrf_token")}-`));
const duplicateText = Buffer.from(bodyDuplicate.body_base64, "base64").toString();
assert.match(duplicateText, /csrf_token=huntproxy-invalid-csrf&csrf_token=body-good/);
const methodGet = plan.operations.find((op) => op.id.startsWith(`mutation-${mutations.indexOf("method-get-form-query")}-`));
assert.equal(methodGet.method, "GET");
assert.equal(methodGet.body_base64, b64(""));
assert.ok(methodGet.query_params.some((part) => part.name === "name" && part.value === "alice"));
assert.ok(methodGet.query_params.some((part) => part.name === "csrf" && part.value === null));
const paired = plan.operations.find((op) => op.id.startsWith(`mutation-${mutations.indexOf("paired-cookie:double-submit")}-`));
assert.ok(paired.headers.some((header) => header.name === "Cookie" && header.value.includes("csrf=paired")));
assert.ok(paired.body_params.some((part) => part.name === "csrf_token" && part.value === "paired"));

const observations = plan.operations.map((operation) => observation(operation));
const originIndex = mutations.indexOf("origin-cross-site");
for (const item of observations.filter((entry) => entry.id.startsWith(`mutation-${originIndex}-`))) {
  item.response_body_hash = null;
  item.response_preview.text = `profile updated at 2026-08-08T08:00:${item.id.endsWith("0") ? "01" : "02"}Z token=${item.id}`;
  item.response_length = item.response_preview.text.length;
}
const combinedOriginIndex = mutations.indexOf("origin-cross-site+token-remove");
for (const item of observations.filter((entry) => entry.id.startsWith(`mutation-${combinedOriginIndex}-`))) {
  item.response_body_hash = null;
  item.response_preview.text = `profile updated at 2026-08-08T08:00:${item.id.endsWith("0") ? "01" : "02"}Z token=${item.id}`;
  item.response_length = item.response_preview.text.length;
}
const invalidIndex = mutations.indexOf("body-invalid:csrf_token");
for (const item of observations.filter((entry) => entry.id.startsWith(`mutation-${invalidIndex}-`))) {
  item.status_code = 403; item.response_body_hash = "rejected"; item.response_preview.text = "request rejected";
}
const invalidAllIndex = mutations.indexOf("control-invalid-all-tokens");
for (const item of observations.filter((entry) => entry.id.startsWith(`mutation-${invalidAllIndex}-`))) {
  item.status_code = 403; item.response_body_hash = "rejected-all"; item.response_preview.text = "request rejected";
}
const result = plugin.analyze(input, observations, context());
assert.ok(result.findings.some((finding) => finding.metadata.mutation === "origin-cross-site+token-remove"), "combined dynamic successful responses compare semantically");
assert.ok(!result.findings.some((finding) => finding.metadata.mutation === "origin-cross-site"), "isolated header acceptance with a valid token is diagnostic only");
assert.ok(!result.findings.some((finding) => finding.metadata.mutation === "body-invalid:csrf_token"), "rejected token controls do not become findings");
const combinedOrigin = plan.operations.find((op) => op.id.startsWith(`mutation-${combinedOriginIndex}-`));
assert.ok(combinedOrigin.header_tombstones.includes("X-CSRF-Token"));
assert.ok(combinedOrigin.query_params.some((part) => part.name === "csrf" && part.value === null));
assert.ok(combinedOrigin.body_params.some((part) => part.name === "csrf_token" && part.value === null));
assert.ok(result.result.outcomes.some((outcome) => outcome.kind === "session-binding"));

const failed = plan.operations.map((operation) => observation(operation));
failed.find((item) => item.id === "baseline-0").error = "transport failed";
assert.equal(plugin.analyze(input, failed, context()).result.baseline_stable, false);

const nestedContext=context();
nestedContext.base_exchange.identity.request_headers[0].value_base64=b64("application/json");
nestedContext.base_exchange.identity.request_body_base64=b64(JSON.stringify({profile:{name:"alice",security:{csrf_token:"nested-good"}}}));
const nestedPlan=plugin.plan({allow_state_change:true,token_names:["csrf_token"],max_mutations:10},nestedContext);
const nestedMutations=Array.from(nestedPlan.result.mutations,(item)=>item.name);
assert.ok(nestedMutations.includes("json-remove:/profile/security/csrf_token"));
assert.ok(nestedMutations.includes("json-invalid:/profile/security/csrf_token"));
const nestedInvalid=nestedPlan.operations.find((op)=>op.id.startsWith(`mutation-${nestedMutations.indexOf("json-invalid:/profile/security/csrf_token")}-`));
assert.equal(JSON.parse(Buffer.from(nestedInvalid.body_base64,"base64")).profile.security.csrf_token,"huntproxy-invalid-csrf");

const freshInput={allow_state_change:true,token_names:["csrf_token"],max_mutations:80,fresh_token:{acquire_url:"https://example.test/profile",body_regex:'name="csrf_token" value="([^"]+)"',location:"body",name:"csrf_token"},secondary_identity:{cookie:"sid=secondary"},paired_cookie_tests:[{name:"explicit-pair",identity:{cookie:"sid=victim; csrf=paired"},token:{location:"body",name:"csrf_token",value:"paired-explicit"}}]};
const freshPlan=plugin.plan(freshInput,context());
assert.equal(freshPlan.result.fresh_token_workflows,true);
assert.equal(freshPlan.result.planned_requests,freshPlan.operations.length*2);
assert.ok(freshPlan.operations.every((op)=>op.type==="http_workflow"&&op.steps.length===2));
assert.equal(freshPlan.operations[0].steps[0].extract[0].name,"csrf_fresh");
assert.ok(freshPlan.operations[0].steps[1].request.body_params.some((part)=>part.name==="csrf_token"&&part.value==="{{extract:csrf_fresh}}"));
const freshMutations=Array.from(freshPlan.result.mutations,(item)=>item.name);
function freshSubmit(name){const index=freshMutations.indexOf(name);assert.ok(index>=0,`missing ${name}`);return freshPlan.operations.find((op)=>op.id===`mutation-${index}-0`).steps[1].request;}
assert.deepEqual(Array.from(freshSubmit("body-remove:csrf_token").body_params,(item)=>item.value),[null]);
assert.deepEqual(Array.from(freshSubmit("body-invalid:csrf_token").body_params,(item)=>item.value),["huntproxy-invalid-csrf"]);
assert.deepEqual(Array.from(freshSubmit("body-duplicate-invalid-first:csrf_token").body_params,(item)=>item.value),["huntproxy-invalid-csrf","{{extract:csrf_fresh}}"]);
assert.deepEqual(Array.from(freshSubmit("body-duplicate-invalid-last:csrf_token").body_params,(item)=>item.value),["{{extract:csrf_fresh}}","huntproxy-invalid-csrf"]);
assert.deepEqual(Array.from(freshSubmit("paired-cookie:explicit-pair").body_params,(item)=>item.value),["paired-explicit"],"paired-cookie probes preserve the caller-supplied token instead of replacing it with the primary fresh token");
const freshObservations=freshPlan.operations.map((op)=>{const final=observation({id:op.id});return {id:op.id,steps:[],terminal:final,error:null};});
const freshAnalysis=plugin.analyze(freshInput,freshObservations,context());
assert.equal(freshAnalysis.result.baseline_successful,true);
assert.equal(freshAnalysis.result.fresh_token_workflows,true);

console.log("CSRFAnalyzer hardening tests passed.");
