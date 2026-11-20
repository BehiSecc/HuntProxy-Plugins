import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

// Regression tests for plugin verdicts that previously reported normal behavior as vulnerabilities.
const root = new URL("../plugins/", import.meta.url);
async function load(id) {
  const sandbox = { globalThis: {} };
  vm.runInNewContext(await readFile(new URL(`${id}/index.js`, root), "utf8"), sandbox, { timeout: 500 });
  return sandbox.globalThis.HuntProxyPlugin;
}
const b64 = (value) => Buffer.from(value, "binary").toString("base64");
function identityContext({ url = "https://example.test/account", method = "GET", headers = [], body = "", action = "scan", related = [] } = {}) {
  return {
    api_version: 1, action, execution_nonce: "0123456789abcdef0123456789abcdef", resources: {}, related_exchanges: related,
    base_exchange: { exchange_id: 42, method, url, headers: headers.map(([name]) => ({ name, value: "<redacted>" })), identity: { request_headers: headers.map(([name, value]) => ({ name, value_base64: b64(value) })), request_body_base64: b64(body), request_body_truncated: false } },
  };
}
function observation(id, { status = 200, text = "ok", hash = "same", headers = [], error = null } = {}) {
  return { id, exchange_id: 1000 + Math.floor(Math.random() * 100000), status_code: status, response_length: text.length, response_body_hash: hash, response_preview: { text }, response_headers: headers.map(([name, value]) => ({ name, value_base64: b64(value) })), error };
}

// JWTAnalyzer: a supplied token replaces the token the application actually reads.
{
  const plugin = await load("jwt-analyzer");
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const jwt = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ sub: "alice", exp: 4102444800 })}.c2ln`;
  const other = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ sub: "bob", exp: 4102444800 })}.c2ln`;
  const cookieContext = identityContext({ headers: [["Cookie", `theme=dark; session=${jwt}`]] });
  for (const token of [jwt, other]) {
    const plan = plugin.plan({ active: true, token }, cookieContext);
    assert.ok(plan.operations.length > 2);
    for (const op of plan.operations) {
      assert.equal(op.headers, undefined, "no Authorization header the server would ignore");
      assert.equal(op.cookie_params.length, 1);
      assert.equal(op.cookie_params[0].name, "session", "the cookie that carries the JWT is replaced");
    }
  }
  const bearer = plugin.plan({ active: true, token: other }, identityContext({ headers: [["Authorization", `Bearer ${jwt}`]] }));
  assert.ok(bearer.operations.every((op) => op.headers && op.headers[0].name === "Authorization" && !op.cookie_params));
  const none = plugin.plan({ active: true, token: jwt }, identityContext({ headers: [["Accept", "*/*"]] }));
  assert.ok(none.operations.every((op) => op.headers[0].name === "Authorization"), "without a JWT in the request, the token is sent as a bearer token");

  const plan = plugin.plan({ active: true }, cookieContext);
  const observations = plan.operations.map((op, index) => observation(op.id, { error: index === plan.operations.length - 1 ? { code: "scope_denied", message: "outside scope" } : null }));
  const result = plugin.analyze({ active: true }, observations, cookieContext).result;
  assert.equal(result.token_location, "cookie");
  assert.deepEqual(Array.from(result.operation_errors, (item) => item.error), ["scope_denied"], "failed operations are reported instead of looking like rejected variants");
}

// ParamFinder: parameters already in the request are not probed as hidden ones.
{
  const plugin = await load("param-finder");
  const ctx = { api_version: 1, action: "scan", execution_nonce: "0123456789abcdef0123456789abcdef", resources: {},
    base_exchange: { exchange_id: 42, method: "POST", url: "https://example.test/profile?id=5&view=full", headers: [{ name: "X-Forwarded-Host", value: "example.test" }, { name: "Cookie", value: "<redacted>" }], request_preview: { text: "role=user&enabled=1" } } };
  const plan = plugin.plan({ locations: ["query", "header", "body", "cookie"], use_only_supplied_words: false, cache_key_tests: false }, ctx);
  const sample = plan.result.candidate_sample;
  assert.ok(!plan.result.candidate_sample.query.includes("id"), "an existing query parameter is not a candidate");
  for (const op of plan.operations) {
    assert.ok(!(op.query_params || []).some((item) => item.name === "id" || item.name === "view"));
    assert.ok(!(op.headers || []).some((item) => item.name.toLowerCase() === "x-forwarded-host"));
    assert.ok(!(op.body_params || []).some((item) => item.name === "role" || item.name === "enabled"));
  }
  assert.ok(sample.query.includes("admin") && sample.body.includes("admin"), "other default candidates remain");

  const confirmInput = { phase: "confirm", locations: ["cookie"], words_by_location: { cookie: ["session"] }, use_only_supplied_words: true, cache_key_tests: false };
  const confirm = plugin.plan(confirmInput, ctx);
  const absent = confirm.operations.find((op) => op.id === "confirm-absent-cookie-0");
  assert.deepEqual(Array.from(absent.cookie_params, (item) => [item.name, item.value]), [["session", null]], "a removal control tells an existing cookie from a hidden one");
  const baseline = (id) => observation(id, { text: "logged in as alice", hash: "base" });
  const loggedOut = (id) => observation(id, { status: 302, text: "", hash: "out", headers: [["Location", "/login"]] });
  const overwrite = confirm.operations.map((op) => op.id.startsWith("baseline-") ? baseline(op.id) : loggedOut(op.id));
  const existing = plugin.analyze(confirmInput, overwrite, ctx);
  assert.equal(existing.findings.length, 0, "an existing session cookie whose removal changes the response is not hidden");
  assert.deepEqual(Array.from(existing.result.existing_parameters_skipped, (item) => item.parameter), ["session"]);
  const hidden = confirm.operations.map((op) => op.id.startsWith("baseline-") || op.id.startsWith("confirm-absent-") ? baseline(op.id) : observation(op.id, { text: "debug panel enabled", hash: "debug" }));
  const found = plugin.analyze(confirmInput, hidden, ctx);
  assert.equal(found.findings.length, 1);
  assert.equal(found.findings[0].confidence, "firm");
}

// AuthAnalyzer: login redirects are denials, enforced boundaries are not findings, unconfirmed exposure is tentative.
{
  const plugin = await load("auth-analyzer");
  const anonymousContext = identityContext({ action: "anonymous_audit" });
  const audit = { domains: ["example.test"], confirm_expected_protected: true };
  const auditPlan = plugin.plan(audit, anonymousContext);
  const redirect = plugin.analyze(audit, auditPlan.operations.map((op) => observation(op.id, { status: 302, text: "", headers: [["Location", "https://example.test/login?next=%2Faccount"]] })), anonymousContext);
  assert.equal(redirect.findings.length, 0, "a redirect to sign-in is the expected denial");
  const softLogin = plugin.analyze(audit, auditPlan.operations.map((op) => observation(op.id, { text: '<form><input name="user"><input type="password" name="pass"></form>' })), anonymousContext);
  assert.equal(softLogin.findings.length, 0, "a 200 login form is a denial for the anonymous control");
  const exposed = plugin.analyze(audit, auditPlan.operations.map((op) => observation(op.id, { text: "account balance 100" })), anonymousContext);
  assert.equal(exposed.findings.length, 1, "real anonymous access is still reported");

  const ctx = identityContext();
  const input = { domains: ["example.test"], primary: { cookie: "sid=alice" }, secondary: { cookie: "sid=bob" } };
  const plan = plugin.plan(input, ctx);
  const enforced = plan.operations.map((op) => op.id.includes("-primary-") ? observation(op.id, { text: "alice account", hash: "alice" }) : observation(op.id, { status: 403, text: "forbidden", hash: "denied" }));
  const enforcedResult = plugin.analyze(input, enforced, ctx);
  assert.equal(enforcedResult.findings.length, 0, "owner allowed and other user denied is the correct boundary");
  assert.equal(enforcedResult.result.classifications[0].primary_allowed, true);
  assert.equal(enforcedResult.result.classifications[0].secondary_allowed, false);

  const shared = plan.operations.map((op) => op.id.includes("-anonymous-") ? observation(op.id, { status: 401, text: "login required", hash: "anon" }) : observation(op.id, { text: "team dashboard", hash: "shared" }));
  assert.equal(plugin.analyze(input, shared, ctx).findings[0].confidence, "tentative", "identical responses may be shared data unless the caller says they are identity-specific");
  assert.equal(plugin.analyze({ ...input, confirm_identity_specific: true }, shared, ctx).findings[0].confidence, "firm");

  const publicPage = plan.operations.map((op) => observation(op.id, { text: "public homepage", hash: "public" }));
  const publicFindings = plugin.analyze({ ...input, include_anonymous: true }, publicPage, ctx).findings.filter((finding) => /unauthenticated/i.test(finding.title));
  assert.equal(publicFindings[0].confidence, "tentative");
  assert.equal(publicFindings[0].severity, "medium");

  const changing = plugin.plan({ ...input, allow_state_changes: true }, identityContext({ method: "DELETE", url: "https://example.test/items/7" }));
  assert.equal(changing.execution, "sequential", "state-changing replays do not overlap");
  assert.equal(plan.execution, undefined, "read-only comparisons keep host concurrency");
}

console.log("Review-fix regression tests passed.");
