import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const root = new URL("../plugins/", import.meta.url);
async function load(id) {
  const source = await readFile(new URL(`${id}/index.js`, root), "utf8");
  const sandbox = { globalThis: {} };
  vm.runInNewContext(source, sandbox, { timeout: 250 });
  return sandbox.globalThis.HuntProxyPlugin;
}
function context(url = "https://example.test/admin") {
  return { api_version: 1, action: "scan", base_exchange: { exchange_id: 42, method: "GET", url, headers: [] }, resources: {} };
}
function observation(operation, status = 403, hash = "base", text = "denied") {
  return { id: operation.id, exchange_id: Math.floor(Math.random() * 100000) + 1, status_code: status, response_length: text.length, response_body_hash: hash, response_preview: { text }, response_headers: [] };
}

{
  const plugin = await load("param-finder");
  const params = await readFile(new URL("param-finder/resources/params", root), "utf8");
  const resourceContext = context(); resourceContext.resources = { params };
  const resourcePlan = plugin.plan({ locations: ["query"], max_words: 20 }, resourceContext);
  assert.ok(resourcePlan.result.candidates.query.includes("account"));
  const input = { phase: "confirm", locations: ["query"], words_by_location: { query: ["debug"] }, max_words: 20 };
  const plan = plugin.plan(input, context());
  assert.ok(plan.operations.length >= 4);
  assert.ok(plan.operations.every((op) => op.type === "http_request" && op.base_exchange_id === 42));
  assert.ok(plan.operations.every((op) => op.query_params?.some((param) => param.name === "hp_pf_cb")));
  const observations = plan.operations.map((op) => observation(op, 200, op.id.startsWith("baseline") ? "a" : "b", op.id.startsWith("baseline") ? "base" : "changed"));
  const result = plugin.analyze(input, observations, context());
  assert.ok(result.findings.some((finding) => finding.metadata.parameter === "debug"));
  assert.ok(plugin.plan({ phase: "screen", locations: ["cookie"], words: ["debug"], max_words: 10 }, context()).operations.some((op) => Array.isArray(op.cookie_params)));
  assert.ok(plugin.plan({ phase: "screen", locations: ["body"], words: ["debug"], max_words: 10 }, context()).operations.some((op) => Array.isArray(op.body_params)));

  const cacheInput = { phase: "screen", locations: ["query"], words: ["utm_content"], use_only_supplied_words: true, marker: "cache-oracle", max_words: 10 };
  const cachePlan = plugin.plan(cacheInput, context());
  const cacheObservations = cachePlan.operations.map((op) => {
    const poison = op.id === "cache-screen-poison-query-0";
    const clean = op.id === "cache-screen-clean-query-0";
    return observation(op, 200, op.id, poison || clean ? "canonical cache-oracle-cache-probe-screen-query-0" : "ordinary page");
  });
  const cacheScreen = plugin.analyze(cacheInput, cacheObservations, context());
  assert.deepEqual(Array.from(cacheScreen.result.candidate_buckets.query), ["utm_content"]);
  assert.equal(cacheScreen.result.follow_up.cache_key_tests, true);
  const cacheConfirmInput = cacheScreen.result.follow_up;
  const cacheConfirmPlan = plugin.plan(cacheConfirmInput, context());
  const cacheConfirmObservations = cacheConfirmPlan.operations.map((op) => {
    const match = op.id.match(/^cache-(?:poison|clean)-query-0-(\d)$/);
    return observation(op, 200, op.id, match ? `canonical cache-oracle-cache-probe-query-0-${match[1]}` : "ordinary page");
  });
  const cacheConfirmed = plugin.analyze(cacheConfirmInput, cacheConfirmObservations, context());
  assert.ok(cacheConfirmed.findings.some((finding) => /Unkeyed cache query parameter: utm_content/.test(finding.title)));
}

{
  const plugin = await load("403-bypasser");
  const plan = plugin.plan({}, context());
  assert.ok(plan.operations.length > 10 && plan.operations.length <= 202);
  assert.ok(plan.operations.some((op) => op.id === "carrier-root-0"));
  const originalUrlCarrier = plan.operations.find((op) => op.headers?.some((header) => header.name === "X-Original-URL") && op.url === "https://example.test/");
  assert.ok(originalUrlCarrier, "forwarding-header bypasses are tested on a benign carrier path");
  const observations = plan.operations.map((op) => observation(op));
  for (const item of observations.filter((item) => item.id.startsWith("carrier-root-"))) {
    item.status_code = 200; item.response_body_hash = "ordinary-root"; item.response_preview.text = "ordinary root";
  }
  const originalIndex = plan.result.variants.indexOf("header:x-original-url:root-carrier");
  for (const item of observations.filter((item) => item.id === `variant-${originalIndex}-0` || item.id === `variant-${originalIndex}-1`)) {
    item.status_code = 200; item.response_body_hash = "protected-admin"; item.response_preview.text = "protected admin";
  }
  const result = plugin.analyze({}, observations, context());
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].title, /Access-control bypass/);

  const falsePositive = plan.operations.map((op) => observation(op));
  for (const item of falsePositive.filter((item) => item.id.startsWith("carrier-root-") || /^variant-(?:[0-9]+)-(?:0|1)$/.test(item.id))) {
    const variant = item.id.match(/^variant-([0-9]+)-/) && plan.result.variants[Number(item.id.match(/^variant-([0-9]+)-/)[1])];
    if (item.id.startsWith("carrier-root-") || /:root-carrier$/.test(variant || "")) {
      item.status_code = 200; item.response_body_hash = "ordinary-root"; item.response_preview.text = "ordinary root";
    }
  }
  assert.equal(plugin.analyze({}, falsePositive, context()).findings.length, 0, "ordinary carrier responses are not bypasses");

  const methodContext = privilegedContext({ method: "POST", url: "https://example.test/admin-roles", headers: [["Content-Type", "application/x-www-form-urlencoded"]], body: "username=missing&action=upgrade" });
  const methodInput = { allow_state_changes: true, success_markers: ["could not change user role"] };
  const methodPlan = plugin.plan(methodInput, methodContext);
  const getIndex = Array.from(methodPlan.result.variants).indexOf("method:get");
  const getOps = methodPlan.operations.filter((op) => op.id.startsWith(`variant-${getIndex}-`));
  assert.equal(getOps.length, 2);
  assert.ok(getOps.every((op) => op.method === "GET" && op.body_base64 === ""));
  assert.ok(getOps.every((op) => op.query_params.some((part) => part.name === "username" && part.value === "missing")));
  const methodObservations = methodPlan.operations.map((op) => observation(op, op.id.startsWith(`variant-${getIndex}-`) ? 400 : 401, op.id.startsWith(`variant-${getIndex}-`) ? "protected-outcome" : "denied", op.id.startsWith(`variant-${getIndex}-`) ? "Could not change user role" : "Unauthorized"));
  assert.ok(plugin.analyze(methodInput, methodObservations, methodContext).findings.some((finding) => finding.metadata.variant === "method:get"));

  const refererInput = { referer_values: ["https://example.test/admin"], success_markers: ["could not change user role"] };
  const refererPlan = plugin.plan(refererInput, context());
  const refererIndex = Array.from(refererPlan.result.variants).indexOf("header:referer:0");
  assert.ok(refererIndex >= 0);
  assert.ok(refererPlan.operations.filter((op) => op.id.startsWith(`variant-${refererIndex}-`)).every((op) => op.headers.some((header) => header.name === "Referer" && header.value === "https://example.test/admin")));
  const refererObservations = refererPlan.operations.map((op) => observation(op, op.id.startsWith(`variant-${refererIndex}-`) ? 400 : 403, op.id.startsWith(`variant-${refererIndex}-`) ? "handler" : "denied", op.id.startsWith(`variant-${refererIndex}-`) ? "Could not change user role" : "Unauthorized"));
  assert.ok(plugin.analyze(refererInput, refererObservations, context()).findings.some((finding) => finding.metadata.variant === "header:referer:0"));
}

{
  const plugin = await load("cache-analyzer");
  const input = { marker: "a1b2c3d4e5", allow_cache_side_effects: true, use_header_wordlist: false, max_header_candidates: 4, max_poison_variants: 4, max_deception_variants: 4 };
  const plan = plugin.plan(input, context("https://example.test/account"));
  assert.ok(plan.operations.length <= 50);
  assert.notEqual(plan.operations.find((op) => op.id === "poison-0").url, plan.operations.find((op) => op.id === "poison-1").url, "each poison candidate gets an isolated cache key");
  const observations = plan.operations.map((op) => {
    const baseAnonymous = op.id === "baseline-anon";
    const deceptive = op.id.startsWith("deception-");
    return observation(op, 200, baseAnonymous ? "anon" : "private", baseAnonymous ? "anonymous" : deceptive ? "private account" : "normal");
  });
  for (const item of observations.filter((item) => ["poison-0", "poison-clean-0", "poison-confirm-0"].includes(item.id))) {
    item.response_body_hash = "poisoned"; item.response_preview.text = "hpa1b2c3d4e5";
  }
  const result = plugin.analyze(input, observations, context("https://example.test/account"));
  assert.ok(result.findings.some((finding) => /cache poisoning/i.test(finding.title)));
  assert.ok(result.findings.some((finding) => /cache deception/i.test(finding.title)));

  const cookieContext = context("https://example.test/");
  cookieContext.resources.cookies = "fehost\nsession\n";
  const cookieInput = { marker: "cookie1234", allow_cache_side_effects: true, modes: ["poisoning"], cookie_names: ["fehost"], use_header_wordlist: false, max_header_candidates: 1 };
  const cookiePlan = plugin.plan(cookieInput, cookieContext);
  const cookiePoison = cookiePlan.operations.find((op) => op.cookie_params?.[0]?.name === "fehost" && op.id.startsWith("poison-"));
  assert.ok(cookiePoison, "explicit cookie candidates generate a poison operation");
  const cookieIndex = cookiePoison.id.slice("poison-".length);
  const cleanCookie = cookiePlan.operations.find((op) => op.id === `poison-clean-${cookieIndex}`);
  const confirmCookie = cookiePlan.operations.find((op) => op.id === `poison-confirm-${cookieIndex}`);
  assert.equal(cookiePoison.url, cleanCookie.url, "cookie poison and clean control share one cache key");
  assert.notEqual(cookiePoison.cookie_params[0].value, cleanCookie.cookie_params[0].value, "clean control uses a non-poison cookie value");
  assert.deepEqual(cleanCookie.cookie_params, confirmCookie.cookie_params, "clean control is repeated stably");
  const cookieObservations = cookiePlan.operations.map((op) => observation(op, 200, "ordinary", "ordinary"));
  for (const item of cookieObservations.filter((item) => [cookiePoison.id, cleanCookie.id, confirmCookie.id].includes(item.id))) {
    item.response_body_hash = "cookie-poisoned"; item.response_preview.text = cookiePoison.cookie_params[0].value;
    item.response_headers = [{ name: "age", value_base64: Buffer.from(item.id === cookiePoison.id ? "0" : "3").toString("base64") }];
  }
  assert.ok(plugin.analyze(cookieInput, cookieObservations, cookieContext).findings.some((finding) => finding.metadata.variant === "cookie:fehost"));
  assert.throws(() => plugin.plan({ ...cookieInput, cookie_names: ["session"] }, cookieContext), /allow_sensitive_cookie_mutation/);
  assert.doesNotThrow(() => plugin.plan({ ...cookieInput, cookie_names: ["session"], allow_sensitive_cookie_mutation: true }, cookieContext));

  const privacyPlan = plugin.plan(input, context("https://example.test/account"));
  const privacyObservations = privacyPlan.operations.map((op) => observation(op, 200, "same", "same body"));
  privacyObservations.find((item) => item.id === "baseline-auth").response_headers = [{ name: "x-cache", value_base64: Buffer.from("miss").toString("base64") }];
  privacyObservations.find((item) => item.id === "baseline-anon").response_headers = [{ name: "x-cache", value_base64: Buffer.from("hit").toString("base64") }, { name: "age", value_base64: Buffer.from("3").toString("base64") }];
  assert.equal(plugin.analyze(input, privacyObservations, context("https://example.test/account")).result.base_appears_private, false, "volatile cache headers do not imply private content");
}

function privilegedContext({ url = "https://example.test/admin", method = "GET", headers = [], body = "", related = [] } = {}) {
  return {
    api_version: 1,
    action: "scan",
    base_exchange: {
      exchange_id: 42, method, url, headers: [],
      identity: {
        request_headers: headers.map(([name, value]) => ({ name, value_base64: Buffer.from(value).toString("base64") })),
        request_body_base64: Buffer.from(body, "binary").toString("base64"), request_body_truncated: false,
      },
    },
    related_exchanges: related,
    resources: {},
  };
}

{
  const plugin = await load("auth-analyzer");
  const ctx = privilegedContext({ related: [{ exchange_id: 43, method: "POST", url: "https://api.example.test/change" }] });
  assert.throws(() => plugin.plan({ primary: {}, secondary: {}, domains: ["example.test"] }, ctx), /non-empty/);
  assert.throws(() => plugin.plan({ primary: { cookie: "sid=same" }, secondary: { cookie: "sid=same" }, domains: ["example.test"] }, ctx), /distinct/);
  const input = { primary: { cookie: "sid=one" }, secondary: { headers: [{ name: "Authorization", value: "Bearer two" }] }, domains: ["example.test", "*.example.test"] };
  const plan = plugin.plan(input, ctx);
  assert.equal(plan.operations.length, 6, "unsafe related shape is skipped by default");
  assert.ok(plan.operations.every((op) => op.header_tombstones.includes("Cookie") && op.header_tombstones.includes("Authorization")));
  const observations = plan.operations.map((op) => observation(op, op.id.includes("anonymous") ? 403 : 200, op.id.includes("anonymous") ? "denied" : "private", "response"));
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].title, /cross-user/i);

  const differential = plan.operations.map((op) => {
    const secondary = op.id.includes("secondary");
    const anonymous = op.id.includes("anonymous");
    return observation(op, secondary ? 200 : 403, `${op.id}-${Math.random()}`, secondary ? `<input name="csrf" value="${Math.random()}">admin` : "denied");
  });
  const differentialResult = plugin.analyze(input, differential, ctx);
  assert.ok(differentialResult.findings.some((finding) => /outcome changes/i.test(finding.title)));

  const anonymousContext = privilegedContext(); anonymousContext.action = "anonymous_audit";
  const anonymousInput = { domains: ["example.test"], confirm_expected_protected: true, anonymous_context: { cookie: "affinity=guest" }, max_requests: 1 };
  assert.throws(() => plugin.plan({ domains: ["example.test"] }, anonymousContext), /confirm_expected_protected/);
  const anonymousPlan = plugin.plan(anonymousInput, anonymousContext);
  assert.equal(anonymousPlan.operations.length, 2);
  assert.ok(anonymousPlan.operations.every((op) => op.id.includes("anonymous") && op.header_tombstones.includes("Cookie")));
  assert.ok(anonymousPlan.operations.every((op) => op.headers.some((header) => header.name === "Cookie" && header.value === "affinity=guest")));
  assert.deepEqual(Array.from(anonymousPlan.result.identities), ["anonymous"]);
  const anonymousObservations = anonymousPlan.operations.map((op) => observation(op, 200, "public-admin", "admin users"));
  const anonymousResult = plugin.analyze(anonymousInput, anonymousObservations, anonymousContext);
  assert.equal(anonymousResult.findings.length, 1);
  assert.equal(anonymousResult.result.classifications[0].mode, "anonymous_audit");
  assert.equal(Object.hasOwn(anonymousResult.result.classifications[0], "primary_allowed"), false);
  assert.throws(() => plugin.plan({ domains: ["example.test"], confirm_expected_protected: true, anonymous_context: {} }, anonymousContext), /anonymous_context/);

  const semanticInput = { ...input, success_markers: ["could not change user role"], failure_markers: ["unauthorized"] };
  const semanticPlan = plugin.plan(semanticInput, ctx);
  const semanticObservations = semanticPlan.operations.map((op) => observation(op, op.id.includes("anonymous") ? 401 : 400, op.id.includes("anonymous") ? "denied" : "handler", op.id.includes("anonymous") ? "Unauthorized" : "Could not change user role"));
  const semanticResult = plugin.analyze(semanticInput, semanticObservations, ctx);
  assert.ok(semanticResult.findings.some((finding) => /cross-user authorization exposure/i.test(finding.title)), "explicit semantic markers support stable non-2xx application outcomes");
}

{
  const plugin = await load("jwt-analyzer");
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ sub: "1", exp: 4102444800 })}.signature`;
  const ctx = privilegedContext({ headers: [["Authorization", `Bearer ${token}`]] });
  const input = { active: true, tests: ["none", "invalid_signature", "expired"] };
  const plan = plugin.plan(input, ctx);
  assert.equal(plan.operations.length, 8);
  assert.ok(plan.operations.every((op) => op.type === "http_request" && op.headers[0].name === "Authorization"));
  const observations = plan.operations.map((op) => observation(op, 200, "authenticated", "account"));
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.filter((finding) => /bypass/i.test(finding.title)).length, 3);

  const hsHeader = encode({ alg: "HS256", typ: "JWT" });
  const hsPayload = encode({ sub: "user", exp: 4102444800 });
  const hsSignature = createHmac("sha256", "secret1").update(`${hsHeader}.${hsPayload}`).digest("base64url");
  const hsToken = `${hsHeader}.${hsPayload}.${hsSignature}`;
  const hsContext = privilegedContext({ headers: [["Authorization", `Bearer ${hsToken}`]] });
  hsContext.resources = { "hmac-secrets": "password\nsecret1\nnot-it\n" };
  const hsInput = { active: true, tests: ["weak_hmac"], target_subject: "administrator" };
  const hsPlan = plugin.plan(hsInput, hsContext);
  assert.equal(hsPlan.result.weak_hmac_secret_found, true);
  assert.equal(hsPlan.operations.length, 4);
  const proofToken = hsPlan.operations.find((op) => op.id === "variant-0-0").headers[0].value.slice(7);
  const proofParts = proofToken.split(".");
  assert.equal(JSON.parse(Buffer.from(proofParts[1], "base64url")).sub, "administrator");
  assert.equal(proofParts[2], createHmac("sha256", "secret1").update(`${proofParts[0]}.${proofParts[1]}`).digest("base64url"));
  const hsObservations = hsPlan.operations.map((op, index) => observation(op, 200, `volatile-${index}`, `<input name="csrf" value="${index}-${Math.random()}"> Account for administrator`));
  const hsResult = plugin.analyze(hsInput, hsObservations, hsContext);
  assert.ok(hsResult.findings.some((finding) => /weak HMAC secret/i.test(finding.title)));
  assert.ok(hsResult.findings.some((finding) => /bypass using weak hmac/i.test(finding.title)));

  const specialistInput = {
    active: true,
    tests: ["embedded_jwk"],
    prebuilt_tokens: { embedded_jwk: token },
    target_url: "https://example.test/my-account?id=administrator",
    success: {
      status_codes: [200],
      body_contains: "administrator",
      headers: [{ name: "X-Role", equals: "administrator" }],
      json: [{ pointer: "/user/role", equals: "administrator" }],
    },
  };
  const specialistPlan = plugin.plan(specialistInput, ctx);
  assert.ok(specialistPlan.operations.every((op) => op.url === specialistInput.target_url));
  const specialistObservations = specialistPlan.operations.map((op) => {
    const accepted = op.id.startsWith("variant-");
    const body = accepted ? JSON.stringify({ user: { role: "administrator" }, text: "administrator" }) : JSON.stringify({ error: "login" });
    return {
      ...observation(op, accepted ? 200 : 302, accepted ? "accepted-admin" : "negative-control", body),
      response_body_base64: Buffer.from(body).toString("base64"),
      response_headers: accepted ? [{ name: "X-Role", value: "administrator" }] : [{ name: "Location", value: "/login" }],
    };
  });
  const specialistResult = plugin.analyze(specialistInput, specialistObservations, ctx);
  assert.equal(specialistResult.findings.length, 1);
  assert.equal(specialistResult.result.negative_control_rejected, true);
  const falsePositive = specialistObservations.map((item) => ({ ...item, status_code: 200, response_body_base64: Buffer.from(JSON.stringify({ user: { role: "administrator" }, text: "administrator" })).toString("base64"), response_headers: [{ name: "X-Role", value: "administrator" }] }));
  assert.equal(plugin.analyze(specialistInput, falsePositive, ctx).findings.length, 0, "matching original-token controls suppress specialist findings");

  const redirectInput = { ...specialistInput, success: { status_codes: [302], redirect_location: { contains: "/administrator" } } };
  const redirectObservations = specialistPlan.operations.map((op) => ({
    ...observation(op, 302, op.id.startsWith("variant-") ? "redirect-admin" : "redirect-login", ""),
    response_headers: [{ name: "Location", value: op.id.startsWith("variant-") ? "/administrator" : "/login" }],
  }));
  assert.equal(plugin.analyze(redirectInput, redirectObservations, ctx).findings.length, 1);
}

{
  const plugin = await load("csrf-analyzer");
  const ctx = privilegedContext({
    method: "POST", url: "https://example.test/profile?csrf=query-token",
    headers: [["Content-Type", "application/x-www-form-urlencoded"], ["X-CSRF-Token", "header-token"]],
    body: "name=alice&csrf_token=body-token",
  });
  assert.throws(() => plugin.plan({}, ctx), /allow_state_change/);
  const input = { allow_state_change: true, token_names: ["csrf", "csrf_token", "X-CSRF-Token"] };
  const plan = plugin.plan(input, ctx);
  assert.ok(plan.operations.some((op) => op.query_params));
  assert.ok(plan.operations.some((op) => op.body_params));
  assert.ok(plan.operations.some((op) => op.header_tombstones && op.header_tombstones.includes("Origin")));
  const observations = plan.operations.map((op) => observation(op, 200, "success", "updated"));
  assert.ok(plugin.analyze(input, observations, ctx).findings.length >= 3);
}

{
  const plugin = await load("upload-analyzer");
  const boundary = "huntproxy-boundary";
  const body = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="original.txt"\r\nContent-Type: text/plain\r\n\r\noriginal\r\n--${boundary}--\r\n`;
  const ctx = privilegedContext({ method: "POST", url: "https://example.test/upload", headers: [["Content-Type", `multipart/form-data; boundary=${boundary}`]], body });
  assert.throws(() => plugin.plan({}, ctx), /allow_uploads/);
  const input = { allow_uploads: true, marker: "hp-upload", max_files: 4 };
  const plan = plugin.plan(input, ctx);
  assert.equal(plan.operations.length, 8);
  const decoded = Buffer.from(plan.operations[0].body_base64, "base64").toString("binary");
  assert.match(decoded, /filename="hp-upload\.txt"/);
  assert.match(decoded, /--huntproxy-boundary--/);
  const observations = plan.operations.map((op) => observation(op, 201, "accepted", "uploaded"));
  assert.ok(plugin.analyze(input, observations, ctx).findings.some((finding) => /Direct prohibited/.test(finding.title)));
}

{
  const plugin = await load("request-smuggler");
  const smuggleContext = context("https://example.test/account");
  smuggleContext.base_exchange.raw_request_base64 = Buffer.from("GET /account HTTP/1.1\r\nHost: example.test\r\nCookie: sid=secret\r\n\r\n").toString("base64");
  const input = { marker: "abc12345", confirm_intrusive: true, families: ["cl_te"], repeats: 3 };
  const plan = plugin.plan(input, smuggleContext);
  assert.equal(plan.operations.length, 16);
  assert.ok(plan.operations.every((operation) => operation.type === "raw_http1"));
  assert.doesNotMatch(Buffer.from(plan.operations.find((operation) => operation.id === "probe-0-0").request_base64, "base64").toString(), /Cookie: sid=secret/);
  const observations = plan.operations.map((operation, index) => ({
    id: operation.id,
    raw: {
      exchange_id: index + 200,
      read_outcome: operation.id.startsWith("probe-") ? "timeout" : "idle",
      responses: [],
    },
  }));
  const result = plugin.analyze(input, observations, smuggleContext);
  assert.equal(result.findings.length, 0, "timeouts without stable response signatures are not findings");
  assert.ok(result.result.limitations.some((value) => /HTTP\/2/.test(value)));
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

console.log("Implemented plugin VM tests passed.");
