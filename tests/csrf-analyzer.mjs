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
const responseHeader = (name, value) => ({ name, value_base64: b64(value) });

const manifest = JSON.parse(await readFile(new URL("csrf-analyzer/plugin.json", root), "utf8"));
const expectedTokenNames = ["csrf", "csrf_token", "_csrf", "xsrf", "_token", "authenticity_token", "x-csrf-token", "x-xsrf-token", "csrfmiddlewaretoken", "x-csrftoken", "csrftoken", "__requestverificationtoken", "_xsrf"];
for (const action of manifest.actions) assert.deepEqual(action.input_schema.properties.token_names.default, expectedTokenNames, `${action.name} token defaults must match runtime discovery`);
const browserAction = manifest.actions.find((action) => action.name === "browser_scan");
assert.deepEqual(browserAction.input_schema.required, ["allow_state_change", "identity"]);
assert.equal(browserAction.input_schema.properties.identity.additionalProperties, false);
assert.equal(browserAction.input_schema.properties.identity.properties.profile.pattern, "^[A-Za-z0-9_-]{1,64}$");

assert.throws(() => plugin.plan({}, context()), /allow_state_change/);
const input = {
  allow_state_change: true,
  token_names: ["csrf", "csrf_token", "X-CSRF-Token"],
  secondary_identity: { cookie: "sid=secondary", headers: [{ name: "Authorization", value: "Bearer secondary" }] },
  paired_cookie_tests: [{ name: "double-submit", identity: { cookie: "sid=victim; csrf=paired" }, token: { location: "body", name: "csrf_token", value: "paired" } }],
  success_markers: ["updated"], failure_markers: ["rejected"], max_mutations: 80,
};
const plan = plugin.plan(input, context());
assert.equal(plan.execution, undefined, "ordinary CSRF plans retain the host's bounded concurrency");
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

const defaultTokenPlan = plugin.plan({allow_state_change:true,max_mutations:80}, context());
const defaultMutations = Array.from(defaultTokenPlan.result.mutations, (item) => item.name);
assert.ok(defaultMutations.includes("header-remove:X-CSRF-Token"), "runtime defaults include the documented CSRF header names");

const failed = plan.operations.map((operation) => observation(operation));
failed.find((item) => item.id === "baseline-0").error = "transport failed";
assert.equal(plugin.analyze(input, failed, context()).result.baseline_stable, false);
assert.equal(plugin.analyze(input, failed, context()).result.baseline_error,"operation_failed");
const scopeFailed=plan.operations.map((operation)=>observation(operation));
scopeFailed.find((item)=>item.id==="baseline-0").error={code:"scope_denied",message:"outside scope"};
assert.equal(plugin.analyze(input,scopeFailed,context()).result.baseline_error,"scope_denied","host scope failures are not mislabeled as transport errors");

const nestedContext=context();
nestedContext.base_exchange.identity.request_headers[0].value_base64=b64("application/json");
nestedContext.base_exchange.identity.request_body_base64=b64(JSON.stringify({profile:{name:"alice",security:{csrf_token:"nested-good"}}}));
const nestedPlan=plugin.plan({allow_state_change:true,token_names:["csrf_token"],max_mutations:10},nestedContext);
const nestedMutations=Array.from(nestedPlan.result.mutations,(item)=>item.name);
assert.ok(nestedMutations.includes("json-remove:/profile/security/csrf_token"));
assert.ok(nestedMutations.includes("json-invalid:/profile/security/csrf_token"));
const nestedInvalid=nestedPlan.operations.find((op)=>op.id.startsWith(`mutation-${nestedMutations.indexOf("json-invalid:/profile/security/csrf_token")}-`));
assert.equal(JSON.parse(Buffer.from(nestedInvalid.body_base64,"base64")).profile.security.csrf_token,"huntproxy-invalid-csrf");

const freshInput={allow_state_change:true,token_names:["csrf_token"],max_mutations:80,fresh_token:{acquire_url:"https://example.test/profile",body_regex:'name="csrf_token" value="([^"]+)"',location:"body",name:"csrf_token"},secondary_identity:{cookie:"sid=secondary"},paired_cookie_tests:[{name:"explicit-pair",identity:{cookie:"sid=victim; csrf=paired"},token:{location:"body",name:"csrf_token",value:"paired-explicit"}}],per_request_values:[{location:"body",name:"email",value_template:"hp-{counter}@invalid.example"}]};
const freshPlan=plugin.plan(freshInput,context());
assert.equal(freshPlan.result.fresh_token_workflows,true);
assert.equal(freshPlan.execution,"sequential","rotating token acquisition and submit workflows cannot overlap");
assert.equal(freshPlan.result.planned_requests,freshPlan.operations.length*2);
assert.ok(freshPlan.operations.every((op)=>op.type==="http_workflow"&&op.steps.length===2));
assert.equal(freshPlan.operations[0].steps[0].extract[0].name,"csrf_fresh");
assert.ok(freshPlan.operations[0].steps[1].request.body_params.some((part)=>part.name==="csrf_token"&&part.value==="{{extract:csrf_fresh}}"));
const freshMutations=Array.from(freshPlan.result.mutations,(item)=>item.name);
function freshSubmit(name){const index=freshMutations.indexOf(name);assert.ok(index>=0,`missing ${name}`);return freshPlan.operations.find((op)=>op.id===`mutation-${index}-0`).steps[1].request;}
function freshTokenValues(name){return Array.from(freshSubmit(name).body_params.filter((item)=>item.name==="csrf_token"),(item)=>item.value);}
assert.deepEqual(freshTokenValues("body-remove:csrf_token"),[null]);
assert.deepEqual(freshTokenValues("body-invalid:csrf_token"),["huntproxy-invalid-csrf"]);
assert.deepEqual(freshTokenValues("body-duplicate-invalid-first:csrf_token"),["huntproxy-invalid-csrf","{{extract:csrf_fresh}}"]);
assert.deepEqual(freshTokenValues("body-duplicate-invalid-last:csrf_token"),["{{extract:csrf_fresh}}","huntproxy-invalid-csrf"]);
assert.deepEqual(freshTokenValues("paired-cookie:explicit-pair"),["paired-explicit"],"paired-cookie probes preserve the caller-supplied token instead of replacing it with the primary fresh token");
const dynamicValues=freshPlan.operations.map((op)=>op.steps[1].request.body_params.find((item)=>item.name==="email").value);
assert.equal(new Set(dynamicValues).size,freshPlan.operations.length,"every logical submit receives a distinct caller-owned value");
assert.deepEqual(Array.from(freshSubmit("body-remove:csrf_token").body_params.filter((item)=>item.name==="csrf_token"),(item)=>item.value),[null],"dynamic fields preserve token removal semantics");
assert.deepEqual(Array.from(freshSubmit("paired-cookie:explicit-pair").body_params.filter((item)=>item.name==="csrf_token"),(item)=>item.value),["paired-explicit"],"dynamic fields preserve paired identity token semantics");
assert.throws(()=>plugin.plan({...freshInput,per_request_values:[{location:"body",name:"csrf_token",value_template:"value-{counter}"}]},context()),/cannot target/);
const freshObservations=freshPlan.operations.map((op)=>{const final=observation({id:op.id});return {id:op.id,steps:[],terminal:final,error:null};});
const freshAnalysis=plugin.analyze(freshInput,freshObservations,context());
assert.equal(freshAnalysis.result.baseline_successful,true);
assert.equal(freshAnalysis.result.fresh_token_workflows,true);

const redirectInput={allow_state_change:true,token_names:["csrf_token"],max_mutations:80};
const redirectPlan=plugin.plan(redirectInput,context());
const redirectMutations=Array.from(redirectPlan.result.mutations,(item)=>item.name);
const redirectObservations=redirectPlan.operations.map((op)=>{
  const item=observation(op,{status:302,hash:"empty",text:""});
  item.response_headers=[responseHeader("Location","%2Fmy-account")];
  return item;
});
for(const name of ["body-invalid:csrf_token","control-invalid-all-tokens"]){
  const index=redirectMutations.indexOf(name);assert.ok(index>=0);
  for(const item of redirectObservations.filter((entry)=>entry.id.startsWith(`mutation-${index}-`)))item.response_headers=[responseHeader("Location","/login")];
}
const redirectAnalysis=plugin.analyze(redirectInput,redirectObservations,context());
assert.equal(redirectAnalysis.result.baseline_successful,true,"empty redirect baselines are accepted and stable");
const redirectRemoval=redirectAnalysis.findings.find((finding)=>finding.metadata.mutation==="body-remove:csrf_token");
assert.ok(redirectRemoval,"a matching accepted redirect with a distinct invalid-token redirect is reported");
assert.equal(redirectRemoval.confidence,"tentative","redirect differential alone does not claim durable state");
assert.equal(redirectRemoval.evidence_exchange_ids.length,6,"both accepted baseline, mutation, and negative-control repeats are retained as evidence");

const readbackInput={allow_state_change:true,token_names:["csrf_token"],max_mutations:80,per_request_values:[{location:"body",name:"email",value_template:"hp-{counter}@invalid.example"}],readback:{url:"https://example.test/profile",predicate:{status_codes:[200],body_contains:"hp-{counter}@invalid.example"}}};
const readbackPlan=plugin.plan(readbackInput,context());
assert.equal(readbackPlan.execution,"sequential");
assert.equal(readbackPlan.result.readback_workflows,true);
assert.equal(readbackPlan.result.planned_requests,readbackPlan.operations.length*2);
assert.ok(readbackPlan.operations.every((op)=>op.type==="http_workflow"&&op.steps.length===2&&op.steps[1].id==="readback"));
const counterForOperation=(id)=>id.startsWith("baseline-")?Number(id.slice("baseline-".length)):2+Number(id.split("-")[1])*2+Number(id.split("-")[2]);
const readbackObservations=readbackPlan.operations.map((op)=>{
  const submit=observation({id:"submit"});
  const counter=counterForOperation(op.id),read=observation({id:"readback"},{text:`account email hp-${counter}@invalid.example`,hash:`read-${counter}`});
  return {id:op.id,steps:[submit,read],terminal:read,error:null};
});
const readbackAnalysis=plugin.analyze(readbackInput,readbackObservations,context());
assert.equal(readbackAnalysis.result.baseline_successful,true,"both baseline read-backs use their own bound counter");
const bodyRemovalIndex=Array.from(readbackPlan.result.mutations,(item)=>item.name).indexOf("body-remove:csrf_token");
const invalidControlIndex=Array.from(readbackPlan.result.mutations,(item)=>item.name).indexOf("body-invalid:csrf_token");
for(const item of readbackObservations.filter((entry)=>entry.id.startsWith(`mutation-${invalidControlIndex}-`))){item.steps[0].status_code=403;item.steps[0].response_preview.text="request rejected";item.steps[0].response_body_hash="rejected";}
const confirmed=plugin.analyze(readbackInput,readbackObservations,context()).findings.find((finding)=>finding.metadata.mutation==="body-remove:csrf_token");
assert.ok(confirmed);
assert.equal(confirmed.confidence,"firm");
assert.equal(confirmed.evidence_exchange_ids.length,10,"both submit/read-back confirmations and both negative controls are retained as evidence");
const secondReadback=readbackObservations.find((entry)=>entry.id===`mutation-${bodyRemovalIndex}-1`).steps[1];secondReadback.response_preview.text="old account value";secondReadback.response_body_hash="old";
const failedReadback=plugin.analyze(readbackInput,readbackObservations,context()).result.outcomes.find((outcome)=>outcome.mutation==="body-remove:csrf_token");
assert.equal(failedReadback.error,"readback_predicate_not_met","failure of either repeated read-back prevents confirmation");

assert.throws(()=>plugin.plan({...readbackInput,readback:{...readbackInput.readback,url:"https://other.test/profile"}},context()),/same-origin/);

const browserContext=context();browserContext.action="browser_scan";
const browserPlan=plugin.plan({allow_state_change:true,identity:{profile:"portswigger-victim"},token_names:["csrf_token"]},browserContext);
assert.equal(browserPlan.execution,"sequential");
assert.equal(browserPlan.operations.length,2);
assert.ok(browserPlan.operations.every((op)=>op.type==="browser_csrf"&&op.mode==="cross_site_form_post"&&op.identity.profile==="portswigger-victim"));
assert.ok(browserPlan.operations[0].body_params.some((part)=>part.name==="csrf_token"&&part.value===null));
const browserAnalysis=plugin.analyze({},browserPlan.operations.map((op,index)=>({id:op.id,tested:true,status:"completed",exchanges:[{exchange_id:9000+index}],cookie_delivery:{managed_cookie_delivered:true,sent_matched_count:1},browser:{isolated:true,initiator:"opaque_cross_site_document"}})),browserContext);
assert.equal(browserAnalysis.findings.length,0,"browser delivery alone never becomes a confirmed finding");
assert.equal(browserAnalysis.result.browser_managed_cookie_delivery_reproducible,true);
assert.equal(browserAnalysis.result.acceptance_candidates[0].status,"awaiting_state_confirmation");
const unauthenticatedBrowserAnalysis=plugin.analyze({},browserPlan.operations.map((op)=>({id:op.id,tested:true,status:"completed",exchanges:[],cookie_delivery:{managed_cookie_delivered:false,sent_matched_count:0}})),browserContext);
assert.equal(unauthenticatedBrowserAnalysis.result.acceptance_candidates.length,0,"navigation without an applicable managed cookie is not a delivery candidate");
assert.throws(()=>plugin.plan({allow_state_change:true,identity_profile:"portswigger-victim",token_names:["csrf_token"]},browserContext),/named managed profile selector/);
assert.throws(()=>plugin.plan({allow_state_change:true,identity:{cookie_file:"victim.json"},token_names:["csrf_token"]},browserContext),/named managed profile selector/);
assert.throws(()=>plugin.plan({allow_state_change:true,identity:{profile:"invalid profile"},token_names:["csrf_token"]},browserContext),/named managed profile selector/);


// Review fixes: fresh tokens never undo a removal or a rewritten body.
{
  const headerFresh={allow_state_change:true,token_names:["X-CSRF-Token"],max_mutations:80,fresh_token:{acquire_url:"https://example.test/profile",body_regex:'csrf="([^"]+)"',location:"header",name:"X-CSRF-Token"}};
  const headerPlan=plugin.plan(headerFresh,context());
  const names=Array.from(headerPlan.result.mutations,(item)=>item.name);
  const submit=(name)=>headerPlan.operations.find((op)=>op.id===`mutation-${names.indexOf(name)}-0`).steps[1].request;
  for(const name of ["header-remove:X-CSRF-Token","origin-cross-site+token-remove"]){
    const request=submit(name);
    assert.ok(request.header_tombstones.includes("X-CSRF-Token"),`${name} removes the token header`);
    assert.ok(!(request.headers||[]).some((header)=>header.name==="X-CSRF-Token"),`${name} does not re-add a fresh token header`);
  }
  const duplicate=submit("header-duplicate-invalid-first:X-CSRF-Token").headers.filter((header)=>header.name==="X-CSRF-Token");
  assert.deepEqual(Array.from(duplicate,(header)=>header.value),["huntproxy-invalid-csrf, {{extract:csrf_fresh}}"],"the host keeps one header per name, so duplicates are sent as one combined field");
  assert.ok(submit("origin-cross-site").headers.some((header)=>header.name==="X-CSRF-Token"&&header.value==="{{extract:csrf_fresh}}"),"non-token probes still carry a fresh token");

  const jsonContext=context();
  jsonContext.base_exchange.identity.request_headers[0].value_base64=b64("application/json");
  jsonContext.base_exchange.identity.request_body_base64=b64('{"name":"\\u4e2d","csrf_token":"json-good"}');
  const jsonPlan=plugin.plan({allow_state_change:true,token_names:["csrf_token"],max_mutations:80,fresh_token:{acquire_url:"https://example.test/profile",body_regex:'csrf="([^"]+)"',location:"body",name:"csrf_token"}},jsonContext);
  const jsonNames=Array.from(jsonPlan.result.mutations,(item)=>item.name);
  const jsonSubmit=jsonPlan.operations.find((op)=>op.id===`mutation-${jsonNames.indexOf("json-remove:/csrf_token")}-0`).steps[1].request;
  assert.ok(jsonSubmit.body_base64,"JSON removal keeps its explicit body");
  assert.equal(jsonSubmit.body_params,undefined,"no body_params that would make the host rebuild the original body");
  const jsonInvalid=Buffer.from(jsonPlan.operations.find((op)=>op.id===`mutation-${jsonNames.indexOf("json-invalid:/csrf_token")}-0`).steps[1].request.body_base64,"base64").toString("latin1");
  assert.ok(jsonInvalid.includes('"name":"\\u4e2d"'),"characters above U+00FF survive as JSON escapes");
  assert.equal(JSON.parse(jsonInvalid).csrf_token,"huntproxy-invalid-csrf");
}

// Review fixes: framework token names are discovered without configuration, including multipart fields.
{
  const djangoContext=context();
  djangoContext.base_exchange.url="https://example.test/profile";
  djangoContext.base_exchange.identity.request_headers=djangoContext.base_exchange.identity.request_headers.filter((header)=>header.name!=="X-CSRF-Token");
  djangoContext.base_exchange.identity.request_body_base64=b64("name=alice&csrfmiddlewaretoken=django-good");
  const names=Array.from(plugin.plan({allow_state_change:true,max_mutations:80},djangoContext).result.mutations,(item)=>item.name);
  assert.ok(names.includes("body-remove:csrfmiddlewaretoken"));
  assert.ok(names.includes("origin-cross-site+token-remove"),"Origin probes get a token-removed variant and a negative control");
  assert.ok(!Array.from(plugin.plan({allow_state_change:true,max_mutations:80,token_names:["csrf"]},djangoContext).result.mutations,(item)=>item.name).includes("body-remove:csrfmiddlewaretoken"),"an explicit token_names list is used as given");
  assert.ok(Array.from(plugin.plan({allow_state_change:true,max_mutations:80,token_names:["csrf"],token_name_discovery:true},djangoContext).result.mutations,(item)=>item.name).includes("body-remove:csrfmiddlewaretoken"),"discovery can be added to an explicit list");
  const customContext=context();customContext.base_exchange.url="https://example.test/profile";
  customContext.base_exchange.identity.request_headers=customContext.base_exchange.identity.request_headers.filter((header)=>header.name!=="X-CSRF-Token");
  customContext.base_exchange.identity.request_body_base64=b64("name=alice&app_antiforgery=custom-good");
  assert.ok(Array.from(plugin.plan({allow_state_change:true,max_mutations:80},customContext).result.mutations,(item)=>item.name).includes("body-remove:app_antiforgery"),"pattern discovery finds names outside the default list");
  assert.ok(!Array.from(plugin.plan({allow_state_change:true,max_mutations:80,token_name_discovery:false},customContext).result.mutations,(item)=>item.name).includes("body-remove:app_antiforgery"),"discovery can be disabled");

  const boundary="----hpboundary";
  const multipart=`--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n--${boundary}\r\nContent-Disposition: form-data; name="__RequestVerificationToken"\r\n\r\nnet-good\r\n--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\n\u0000ÿ\u0080bytes\r\n--${boundary}--\r\n`;
  const multipartContext=context();
  multipartContext.base_exchange.url="https://example.test/upload";
  multipartContext.base_exchange.identity.request_headers=[{name:"Content-Type",value_base64:b64(`multipart/form-data; boundary=${boundary}`)},{name:"Cookie",value_base64:b64("sid=primary")}];
  multipartContext.base_exchange.identity.request_body_base64=b64(multipart);
  const mpPlan=plugin.plan({allow_state_change:true,max_mutations:80},multipartContext);
  const mpNames=Array.from(mpPlan.result.mutations,(item)=>item.name);
  for(const name of ["multipart-remove:__RequestVerificationToken","multipart-invalid:__RequestVerificationToken","multipart-duplicate-invalid-first:__RequestVerificationToken","control-invalid-all-tokens","origin-cross-site+token-remove"]) assert.ok(mpNames.includes(name),`missing ${name}`);
  const removed=Buffer.from(mpPlan.operations.find((op)=>op.id===`mutation-${mpNames.indexOf("multipart-remove:__RequestVerificationToken")}-0`).body_base64,"base64").toString("latin1");
  assert.ok(!removed.includes("net-good")&&!removed.includes("__RequestVerificationToken"));
  assert.ok(removed.includes("\u0000ÿ\u0080bytes"),"binary file parts are preserved byte for byte");
  assert.ok(removed.endsWith(`--${boundary}--\r\n`));
  assert.throws(()=>plugin.plan({allow_state_change:true,fresh_token:{acquire_url:"https://example.test/upload",body_regex:"x(.)",location:"body",name:"__RequestVerificationToken"}},multipartContext),/not multipart/);
}

// Review fixes: GET conversions have no body, identity swaps drop custom credentials, truncated bodies are not rebuilt.
{
  const names=Array.from(plan.result.mutations,(item)=>item.name);
  const methodGet=plan.operations.find((op)=>op.id.startsWith(`mutation-${names.indexOf("method-get-form-query")}-`));
  assert.equal(methodGet.body_params,undefined,"a GET conversion does not rebuild the form body through body_params");
  const apiContext=context();
  apiContext.base_exchange.identity.request_headers.push({name:"X-Api-Key",value_base64:b64("primary-key")});
  const apiPlan=plugin.plan(input,apiContext);
  const apiNames=Array.from(apiPlan.result.mutations,(item)=>item.name);
  const swapped=apiPlan.operations.find((op)=>op.id.startsWith(`mutation-${apiNames.indexOf("cross-session-original-token")}-`));
  assert.ok(swapped.header_tombstones.includes("X-Api-Key"),"custom credential headers of the primary identity are removed");
  assert.ok(!swapped.header_tombstones.includes("X-CSRF-Token"),"the original CSRF token is kept for the session-binding test");
  const truncatedContext=context();
  truncatedContext.base_exchange.identity.request_headers[0].value_base64=b64("application/json");
  truncatedContext.base_exchange.identity.request_body_base64=b64('{"csrf_token":"cut');
  truncatedContext.base_exchange.identity.request_body_truncated=true;
  const truncatedPlan=plugin.plan({allow_state_change:true,token_names:["csrf_token"],max_mutations:80},truncatedContext);
  assert.ok(!truncatedPlan.result.mutations.some((item)=>item.name.startsWith("json-")),"truncated JSON bodies are not replayed");
}

// Review fixes: verdicts need ambient credentials and a per-request read-back, and an embedded token is not a rejection.
{
  const bearerContext=context();
  bearerContext.base_exchange.identity.request_headers=bearerContext.base_exchange.identity.request_headers.filter((header)=>header.name!=="Cookie").concat([{name:"Authorization",value_base64:b64("Bearer api-token")}]);
  const redirectBearer=redirectPlan.operations.map((op)=>{const item=observation(op,{status:302,hash:"empty",text:""});item.response_headers=[responseHeader("Location","%2Fmy-account")];return item;});
  for(const name of ["body-invalid:csrf_token","control-invalid-all-tokens"]){const index=redirectMutations.indexOf(name);for(const item of redirectBearer.filter((entry)=>entry.id.startsWith(`mutation-${index}-`)))item.response_headers=[responseHeader("Location","/login")];}
  const bearer=plugin.analyze(redirectInput,redirectBearer,bearerContext);
  assert.equal(bearer.findings.length,0,"bearer-only requests are not CSRF-exploitable from a browser");
  assert.equal(bearer.result.ambient_credentials,false);
  assert.ok(plugin.analyze(redirectInput,redirectBearer,context()).findings.length>0,"the same evidence with a session cookie is still reported");

  const staticReadback={...readbackInput,readback:{...readbackInput.readback,predicate:{body_contains:"account email"}}};
  const staticFinding=plugin.analyze(staticReadback,readbackObservations.map((item)=>item.id===`mutation-${bodyRemovalIndex}-1`?{...item,steps:[item.steps[0],observation({id:"readback"},{text:"account email hp-1@invalid.example",hash:"read"})]}:item),context()).findings.find((finding)=>finding.metadata.mutation==="body-remove:csrf_token");
  assert.ok(staticFinding);
  assert.equal(staticFinding.confidence,"tentative","a read-back predicate without {counter} cannot tell this request's write from the baseline's");

  const tokenPage=plan.operations.map((op)=>observation(op,{text:'<meta name="csrf-token" content="abc"> profile updated'}));
  assert.equal(plugin.analyze(input,tokenPage,context()).result.baseline_successful,true,"a successful page that embeds a CSRF token is not a rejection");
  assert.equal(plugin.analyze(input,plan.operations.map((op)=>observation(op,{text:"CSRF token missing or incorrect"})),context()).result.baseline_successful,false);
}

console.log("CSRFAnalyzer hardening tests passed.");
