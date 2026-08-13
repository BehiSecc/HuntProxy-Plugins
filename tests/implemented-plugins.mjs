import assert from "node:assert/strict";
import { createHmac, createPublicKey, verify as verifySignature } from "node:crypto";
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
  const plugin = await load("ip-rotate");
  const enableContext = context(); enableContext.action = "enable";
  const enable = plugin.plan({ target_url: "https://api.example.test", regions: ["us-east-1", "eu-west-1"] }, enableContext);
  assert.equal(enable.execution, "sequential");
  assert.equal(enable.stop_on_error, true);
  assert.equal(enable.operations.length, 1);
  assert.deepEqual(Array.from(enable.operations[0].regions), ["us-east-1", "eu-west-1"]);
  assert.equal(enable.operations[0].action, "enable");
  assert.equal(enable.operations[0].type, "aws_api_gateway");
  assert.throws(() => plugin.plan({ target_url: "https://api.example.test/path", regions: ["us-east-1"] }, enableContext), /exact HTTP/);

  const statusContext = context(); statusContext.action = "status";
  const status = plugin.plan({}, statusContext);
  assert.equal(status.operations[0].action, "status");
  const analyzed = plugin.analyze({}, [{ id: "ip-rotation-status", ip_rotation: { action: "status", profiles: [] } }], statusContext);
  assert.deepEqual(Array.from(analyzed.result.ip_rotation.profiles), []);

  const disableContext = context(); disableContext.action = "disable";
  const disable = plugin.plan({ target_url: "https://api.example.test" }, disableContext);
  assert.equal(disable.stop_on_error, true);
  assert.equal(disable.operations[0].action, "disable");
}

{
  const plugin = await load("param-finder");
  const params = await readFile(new URL("param-finder/resources/params", root), "utf8");
  const resourceContext = context(); resourceContext.resources = { params };
  const resourcePlan = plugin.plan({ locations: ["query"], max_words: 20 }, resourceContext);
  assert.ok(resourcePlan.result.candidate_sample.query.includes("account"));
  const lateContext = context(); lateContext.resources = { params: Array.from({ length: 700 }, (_, index) => `ordinary_${index}`).concat(["roleid", "chosen_discount"]).join("\n"), headers: Array.from({ length: 700 }, (_, index) => `X-Ordinary-${index}`).concat(["X-Custom-IP-Authorization"]).join("\n") };
  const latePlan = plugin.plan({ locations: ["query", "header"], cache_key_tests: false }, lateContext);
  assert.ok(latePlan.result.candidate_sample.query.includes("roleid"));
  assert.ok(latePlan.result.candidate_sample.query.includes("chosen_discount"));
  assert.ok(latePlan.result.candidate_sample.header.includes("X-Custom-IP-Authorization"));
  assert.ok(latePlan.result.candidate_counts.query > 500);
  assert.equal(latePlan.result.truncated, false);
  const lateObservations = latePlan.operations.map((op) => observation(op, 200, op.id.startsWith("screen-") ? "changed" : "baseline", op.id.startsWith("screen-") ? "changed response" : "baseline response"));
  const lateScreen = plugin.analyze({ locations: ["query", "header"], cache_key_tests: false }, lateObservations, lateContext);
  assert.ok(lateScreen.result.candidate_buckets.query.length > 500);
  assert.ok(lateScreen.result.follow_up.max_words >= lateScreen.result.candidate_buckets.query.length);
  const lateConfirmPlan = plugin.plan(lateScreen.result.follow_up, lateContext);
  assert.equal(lateConfirmPlan.result.candidate_counts.query, lateScreen.result.candidate_buckets.query.length);
  const input = { phase: "confirm", locations: ["query"], words_by_location: { query: ["debug"] }, max_words: 20 };
  const plan = plugin.plan(input, context());
  assert.ok(plan.operations.length >= 4);
  assert.ok(plan.operations.every((op) => op.type === "http_request" && op.base_exchange_id === 42));
  assert.ok(plan.operations.every((op) => op.query_params?.some((param) => param.name === "hp_pf_cb")));
  const observations = plan.operations.map((op) => observation(op, 200, op.id.startsWith("baseline") ? "a" : "b", op.id.startsWith("baseline") ? "base" : "changed"));
  const result = plugin.analyze(input, observations, context());
  assert.ok(result.findings.some((finding) => finding.metadata.parameter === "debug"));
  const compactedParam = observations.map((item) => ({ ...item, response_body_base64: null, response_body_omitted_reason: "analysis_budget", response_preview: { text: "same truncated prefix" } }));
  assert.equal(plugin.analyze(input, compactedParam, context()).findings.length, 0, "compacted bodies cannot create parameter-change proof from matching previews");
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

  const pagedInput = { locations: ["query"], words: ["one", "two", "three", "four", "five"], use_only_supplied_words: true, bucket_size: 2, max_requests: 5, cache_key_tests: true };
  let paged = pagedInput, screenedNames = [], screenPages = 0;
  do {
    const pagePlan = plugin.plan(paged, context());
    screenPages += 1;
    assert.equal(pagePlan.execution, "sequential");
    assert.equal(pagePlan.operations.length, 5, "screen pages contain controls plus one complete cache group");
    assert.deepEqual(Array.from(pagePlan.operations, (op) => op.id.replace(/^(?:cache-screen-)?(?:poison-|clean-)?/, "")).slice(0, 2), ["baseline-0", "baseline-1"]);
    const screen = pagePlan.operations.find((op) => op.id.startsWith("screen-"));
    screenedNames.push(...screen.query_params.filter((item) => item.name !== "hp_pf_cb").map((item) => item.name));
    const poisonIndex = pagePlan.operations.findIndex((op) => op.id.startsWith("cache-screen-poison-"));
    assert.ok(poisonIndex > 0 && pagePlan.operations[poisonIndex + 1].id.startsWith("cache-screen-clean-"));
    const analyzedPage = plugin.analyze(paged, pagePlan.operations.map((op) => observation(op, 200, "stable", "stable response")), context());
    assert.equal(analyzedPage.result.coverage.tested, screenedNames.length);
    paged = analyzedPage.result.follow_up;
  } while (paged);
  assert.equal(screenPages, 3);
  assert.deepEqual(screenedNames, ["one", "two", "three", "four", "five"]);

  const hitPagePlan = plugin.plan(pagedInput, context());
  const hitPageAnalysis = plugin.analyze(pagedInput, hitPagePlan.operations.map((op) => observation(op, 200, op.id.startsWith("screen-") ? "changed" : "base", op.id.startsWith("screen-") ? "changed response" : "base response")), context());
  assert.equal(hitPageAnalysis.result.follow_up.phase, "confirm");
  assert.equal(hitPageAnalysis.result.follow_up.max_requests, 8, "generated confirmation has enough budget for one atomic query group");
  assert.equal(hitPageAnalysis.result.follow_up.resume_screen.phase, "screen");
  const hitConfirmPlan = plugin.plan(hitPageAnalysis.result.follow_up, context());
  const hitConfirmAnalysis = plugin.analyze(hitPageAnalysis.result.follow_up, hitConfirmPlan.operations.map((op) => observation(op, 200, op.id.startsWith("baseline") ? "base" : "changed", op.id.startsWith("baseline") ? "base" : "changed")), context());
  assert.equal(hitConfirmAnalysis.result.follow_up.phase, "confirm", "confirmation pagination remains inside the chain");
  const finalHitConfirmPlan = plugin.plan(hitConfirmAnalysis.result.follow_up, context());
  const finalHitConfirmAnalysis = plugin.analyze(hitConfirmAnalysis.result.follow_up, finalHitConfirmPlan.operations.map((op) => observation(op, 200, op.id.startsWith("baseline") ? "base" : "changed", op.id.startsWith("baseline") ? "base" : "changed")), context());
  assert.equal(finalHitConfirmAnalysis.result.follow_up.phase, "screen", "confirmation resumes the deferred screen page");

  assert.throws(() => plugin.plan({ ...pagedInput, max_requests: 4 }, context()), /at least 5 requests/);
  const guarded = plugin.plan(pagedInput, context()).result;
  assert.throws(() => plugin.plan({ ...pagedInput, cursor: guarded.next_cursor }, context()), /requires candidate_signature/);
  assert.throws(() => plugin.plan({ ...pagedInput, cursor: guarded.next_cursor, candidate_signature: guarded.candidate_signature || "deadbeef", words: ["changed"] }, context()), /candidate set/);

  const confirmPagedInput = { phase: "confirm", locations: ["query"], words_by_location: { query: ["first", "second"] }, use_only_supplied_words: true, max_requests: 8 };
  const firstConfirmPage = plugin.plan(confirmPagedInput, context());
  assert.equal(firstConfirmPage.operations.length, 8);
  assert.equal(firstConfirmPage.operations.filter((op) => op.id.startsWith("confirm-")).length, 2);
  assert.equal(firstConfirmPage.operations.filter((op) => op.id.startsWith("cache-poison-")).length, 2);
  assert.equal(firstConfirmPage.operations.filter((op) => op.id.startsWith("cache-clean-")).length, 2);
  const firstConfirmAnalysis = plugin.analyze(confirmPagedInput, firstConfirmPage.operations.map((op) => observation(op, 200, op.id.startsWith("baseline") ? "base" : "changed", op.id.startsWith("baseline") ? "base" : "changed")), context());
  assert.equal(firstConfirmAnalysis.result.coverage.tested, 1);
  assert.equal(firstConfirmAnalysis.result.follow_up.cursor, 1);
  const secondConfirmPlan = plugin.plan(firstConfirmAnalysis.result.follow_up, context());
  assert.ok(secondConfirmPlan.operations.some((op) => op.id === "confirm-query-1-0"), "later pages retain absolute candidate indexes");

  const defaultBudgetWords = Array.from({ length: 10000 }, (_, index) => `candidate_${index}`);
  const defaultBudgetPlan = plugin.plan({ locations: ["query", "header"], words: defaultBudgetWords, use_only_supplied_words: true }, context());
  assert.ok(defaultBudgetPlan.operations.length <= 500, "runtime default matches the manifest's 500-request default");
  assert.equal(defaultBudgetPlan.result.request_budget_exhausted, true);

  const wordLimited = plugin.plan({ locations: ["query"], words: ["a", "b", "c", "d"], use_only_supplied_words: true, max_words: 3, cache_key_tests: false }, context());
  assert.equal(wordLimited.result.candidate_word_limit_reached, true);
  assert.equal(wordLimited.result.coverage.source_complete, false);
}

{
  const plugin = await load("403-bypasser");
  const plan = plugin.plan({}, context());
  assert.ok(plan.operations.length > 10 && plan.operations.length <= 202);
  assert.ok(plan.operations.some((op) => op.id === "carrier-root-0"));
  const originalUrlCarrier = plan.operations.find((op) => op.headers?.some((header) => header.name === "X-Original-URL") && op.url === "https://example.test/");
  assert.ok(originalUrlCarrier, "forwarding-header bypasses are tested on a benign carrier path");
  for (const name of [
    "path:trailing-dot-segment", "path:double-slash-trailing", "path:triple-slash-trailing",
    "path:dot-segment-trailing", "path:dot-segment-wrapped", "path:dotdot-semicolon",
    "path:leading-dotdot-semicolon", "path:semicolon-slash", "path:leading-semicolon",
    "path:encoded-space", "path:encoded-tab", "path:html-extension", "path:php-extension",
    "path:wildcard-suffix", "path:query-suffix", "header:x-forwarded-for-url",
    "header:x-custom-ip-authorization", "header:x-forwarded-host", "header:x-host",
    "header:host-localhost", "header:host-localhost-x-forwarded-for"
  ]) assert.ok(plan.result.variants.includes(name), `missing ${name}`);
  assert.ok(!plan.result.variants.includes("method:post-empty-body"), "empty POST stays behind the state-change gate");
  const exactPaths = {
    "path:trailing-dot-segment": "https://example.test/admin/.",
    "path:double-slash-trailing": "https://example.test//admin//",
    "path:triple-slash-trailing": "https://example.test///admin///",
    "path:dot-segment-trailing": "https://example.test/./admin/",
    "path:dot-segment-wrapped": "https://example.test/./admin/./",
    "path:dotdot-semicolon": "https://example.test/admin..;/",
    "path:leading-dotdot-semicolon": "https://example.test/..;/admin",
    "path:semicolon-slash": "https://example.test/admin;/",
    "path:leading-semicolon": "https://example.test/;/admin",
    "path:encoded-space": "https://example.test/admin%20",
    "path:encoded-tab": "https://example.test/admin%09",
    "path:html-extension": "https://example.test/admin.html",
    "path:php-extension": "https://example.test/admin.php",
    "path:wildcard-suffix": "https://example.test/admin/*",
    "path:query-suffix": "https://example.test/admin/?anything"
  };
  for (const [name, url] of Object.entries(exactPaths)) {
    const index = plan.result.variants.indexOf(name);
    const operations = plan.operations.filter((op) => op.id.startsWith(`variant-${index}-`));
    assert.equal(operations.length, 2, `${name} is repeated`);
    assert.ok(operations.every((op) => op.url === url), `${name} preserves its exact path form`);
  }
  const localhostForwarded = plan.operations.find((op) => op.headers?.some((header) => header.name === "Host" && header.value === "localhost") && op.headers.some((header) => header.name === "X-Forwarded-For" && header.value === "127.0.0.1"));
  assert.ok(localhostForwarded, "Host and loopback forwarding are tested together");
  assert.ok(localhostForwarded.header_tombstones.includes("Host"), "Host is replaced rather than appended");
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
  const compacted403 = observations.map((item) => ({ ...item, response_body_hash: null, response_body_base64: null, response_body_omitted_reason: "analysis_budget", response_preview: { text: "same truncated prefix" } }));
  assert.equal(plugin.analyze({}, compacted403, context()).findings.length, 0, "compacted previews cannot prove a 403 bypass");

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
  const emptyPostIndex = Array.from(methodPlan.result.variants).indexOf("method:post-empty-body");
  assert.ok(emptyPostIndex >= 0);
  const emptyPostOps = methodPlan.operations.filter((op) => op.id.startsWith(`variant-${emptyPostIndex}-`));
  assert.equal(emptyPostOps.length, 2);
  assert.ok(emptyPostOps.every((op) => op.method === "POST" && op.body_base64 === ""));
  assert.ok(emptyPostOps.every((op) => op.header_tombstones.includes("Content-Type")));
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
  const cacheManifest = JSON.parse(await readFile(new URL("cache-analyzer/plugin.json", root), "utf8"));
  const headerResource = await readFile(new URL("cache-analyzer/resources/headers", root), "utf8");
  const cookieResource = await readFile(new URL("cache-analyzer/resources/cookies", root), "utf8");
  const parameterResource = await readFile(new URL("cache-analyzer/resources/parameters", root), "utf8");
  const responseHeader = (name, value) => ({ name, value_base64: Buffer.from(value).toString("base64") });
  const hitHeaders = [responseHeader("X-Cache", "HIT"), responseHeader("Age", "3")];
  const cacheContext = context("https://example.test/account");
  cacheContext.resources = { headers: headerResource, cookies: cookieResource, parameters: parameterResource };

  assert.equal(cacheManifest.version, "0.15.0");
  assert.equal(cacheManifest.limits.memory_mb, 96);
  assert.equal(cacheManifest.limits.js_stage_timeout_ms, 60000);
  assert.equal(cacheManifest.actions[0].input_schema.properties.scan_mode.default, "full");

  const fullInput = { marker: "fullstage123", allow_cache_side_effects: true, modes: ["poisoning"], header_bucket_size: 8 };
  const discoveryContext = context("https://example.test/");
  discoveryContext.resources = cacheContext.resources;
  discoveryContext.base_exchange.page_discovery = { targets: ["https://example.test/resources/js/geolocate.js"] };
  const discoveryInput = { ...fullInput, allow_shared_cache_key_tests: true };
  const discoveryPlan = plugin.plan(discoveryInput, discoveryContext);
  assert.equal(discoveryPlan.result.phase, "discover");
  assert.equal(discoveryPlan.operations.length, 12, "discovery verifies two isolated keys plus exact mode for the saved page and one same-origin asset");
  assert.ok(discoveryPlan.operations.every((op) => op.credential_mode === "without_project_credentials"));
  const discoveryObservations = discoveryPlan.operations.map((op) => {
    const asset = /geolocate\.js/.test(op.url), repeat = /-repeat-/.test(op.id);
    const item = observation(op, 200, asset ? "asset" : "page", asset ? "cacheable asset" : "uncacheable page");
    item.response_headers = [responseHeader("X-Cache", asset && repeat ? "HIT" : "MISS")];
    return item;
  });
  const discoveryResult = plugin.analyze(discoveryInput, discoveryObservations, discoveryContext);
  assert.equal(discoveryResult.findings.length, 0);
  assert.equal(discoveryResult.result.discovery_targets.find((target) => target.selected).url, "https://example.test/resources/js/geolocate.js");
  assert.equal(discoveryResult.result.follow_up.phase, "screen");
  assert.equal(discoveryResult.result.follow_up.target_url, "https://example.test/resources/js/geolocate.js");
  assert.equal(plugin.plan(discoveryResult.result.follow_up, discoveryContext).result.phase, "screen");
  const exactOnlyDiscovery = discoveryObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  exactOnlyDiscovery.find((item) => item.id === "discover-isolated-b-prime-1").response_headers = hitHeaders;
  const exactOnlyResult = plugin.analyze(discoveryInput, exactOnlyDiscovery, discoveryContext);
  assert.equal(exactOnlyResult.result.follow_up.target_key_mode, "shared");
  assert.equal(exactOnlyResult.result.follow_up.shared_header_cache_key_oracle, true, "exact-only targets propagate shared-key safety mode");
  const noCacheDiscovery = discoveryObservations.map((item) => ({ ...item, response_headers: [responseHeader("X-Cache", "MISS")] }));
  const noCacheResult = plugin.analyze(discoveryInput, noCacheDiscovery, discoveryContext);
  assert.equal(noCacheResult.result.follow_up, null);
  assert.equal(noCacheResult.result.selection_reason, "no_cacheable_target_found", "discovery stops before broad probing when no usable cacheable target is proven");
  const lightDiscovery = plugin.analyze({ ...discoveryInput, scan_mode: "light" }, discoveryObservations, discoveryContext);
  assert.equal(lightDiscovery.result.follow_up.phase, "confirm", "Light also switches to a discovered cacheable target before high-yield confirmation");
  const redirectDiscovery = discoveryObservations.map((item) => ({ ...item, status_code: /geolocate\.js/.test(discoveryPlan.operations.find((op) => op.id === item.id).url) ? 302 : item.status_code, response_length: /geolocate\.js/.test(discoveryPlan.operations.find((op) => op.id === item.id).url) ? 0 : item.response_length, response_headers: item.response_headers.slice() }));
  redirectDiscovery.filter((item) => /geolocate\.js/.test(discoveryPlan.operations.find((op) => op.id === item.id).url)).forEach((item) => item.response_headers.push(responseHeader("Location", "/login")));
  assert.equal(plugin.analyze(discoveryInput, redirectDiscovery, discoveryContext).result.follow_up.target_url, "https://example.test/resources/js/geolocate.js", "stable cached 301/302-style redirects with Location remain eligible discovery targets");
  const redirectWithoutLocation = redirectDiscovery.map((item) => ({ ...item, response_headers: item.response_headers.filter((header) => header.name.toLowerCase() !== "location") }));
  assert.equal(plugin.analyze(discoveryInput, redirectWithoutLocation, discoveryContext).result.follow_up, null, "empty redirect responses without Location are not discovery targets");

  const screenPlan = plugin.plan(fullInput, cacheContext);
  assert.ok(screenPlan.operations.filter((op) => op.id.startsWith("screen-")).every((op) => op.observe?.body_bytes === 0 && op.observe.body_contains.length > 0), "screening uses host-side full-body marker search without copying bodies into analysis");
  assert.equal(screenPlan.result.scan_mode, "full");
  assert.equal(screenPlan.result.phase, "screen");
  assert.equal(plugin.plan({ ...fullInput, marker: "hpfullstage123" }, cacheContext).result.marker, "hpfullstage123", "already namespaced markers are not double-prefixed");
  assert.ok(screenPlan.operations.length < 2000);
  assert.equal(screenPlan.result.coverage.headers.generated, screenPlan.result.coverage.headers.tested, "all eligible bundled headers are screened rather than silently truncated");
  assert.ok(screenPlan.result.coverage.headers.generated > 2500, "Full consumes the complete bundled header source");
  assert.deepEqual(Array.from(screenPlan.operations.slice(0, 8), (op) => op.id), [
    "baseline-with-project-credentials-1", "baseline-with-project-credentials-2",
    "baseline-without-project-credentials-1", "baseline-without-project-credentials-2",
    "cache-profile-a-prime", "cache-profile-a-repeat", "cache-profile-b-prime", "cache-profile-b-repeat",
  ]);
  assert.ok(screenPlan.operations.find((op) => op.id === "baseline-without-project-credentials-1").header_tombstones.includes("Authorization"));

  const firstScreen = screenPlan.operations.find((op) => op.id === "screen-headers-poison-0");
  const forwardedFor = firstScreen.headers.find((header) => header.name.toLowerCase() === "x-forwarded-for");
  const forwardedHost = firstScreen.headers.find((header) => header.name.toLowerCase() === "x-forwarded-host");
  const forwardedProto = firstScreen.headers.find((header) => header.name.toLowerCase() === "x-forwarded-proto");
  assert.match(forwardedFor.value, /^2001:db8::[0-9a-f]+$/i, "IP forwarding headers receive a typed documentation address");
  assert.match(forwardedHost.value, /\.invalid$/, "host headers receive a syntactically valid harmless host");
  assert.equal(forwardedProto.value, "http", "scheme headers receive a typed value");
  assert.equal(screenPlan.preview.scope, "current_stage");
  assert.equal(screenPlan.preview.selected_mode, "full");
  assert.ok(screenPlan.preview.candidate_count > 2500, "plan preview exposes stage-scoped candidate counts without exposing operations");

  const screenObservations = screenPlan.operations.map((op) => observation(op, 200, "stable", "ordinary preview"));
  for (const id of ["cache-profile-a-prime", "cache-profile-a-repeat", "cache-profile-b-prime", "cache-profile-b-repeat"]) {
    const item = screenObservations.find((entry) => entry.id === id);
    item.response_preview.text = "stable profile";
    if (id.endsWith("repeat")) item.response_headers = hitHeaders;
  }
  const hostMarker = forwardedHost.value.replace(/\.invalid$/, "");
  for (const id of ["screen-headers-poison-0", "screen-headers-clean-0"]) {
    const item = screenObservations.find((entry) => entry.id === id);
    item.response_body_base64 = Buffer.from(`body beyond preview ${hostMarker}`).toString("base64");
    if (id === "screen-headers-clean-0") item.response_headers = hitHeaders;
  }
  const firstQueryScreen = screenPlan.operations.find((op) => op.id === "screen-query-parameters-poison-0");
  const queryMarker = firstQueryScreen.query_params[0].value;
  for (const id of ["screen-query-parameters-poison-0", "screen-query-parameters-clean-0"]) {
    const item = screenObservations.find((entry) => entry.id === id);
    item.response_body_base64 = Buffer.from(`query body ${queryMarker}`).toString("base64");
    if (id.endsWith("clean-0")) item.response_headers = hitHeaders;
  }
  const screenResult = plugin.analyze(fullInput, screenObservations, cacheContext);
  assert.deepEqual(Array.from(screenResult.result.candidate_headers), ["X-Forwarded-Host"], "full-body marker attribution narrows a bucket to the responsible header");
  assert.deepEqual(Array.from(screenResult.result.candidate_parameters), ["utm_source"], "query screening attributes a reflected marker to one parameter");
  assert.equal(screenResult.findings.length, 0, "screening never persists an overconfident finding");
  assert.equal(screenResult.result.follow_up.phase, "confirm");
  assert.equal(screenResult.result.follow_up.use_only_supplied_headers, true);

  const confirmInput = screenResult.result.follow_up;
  const confirmPlan = plugin.plan(confirmInput, cacheContext);
  assert.equal(confirmPlan.result.phase, "confirm");
  assert.equal(confirmPlan.result.poison_variants, 2);
  assert.notEqual(screenPlan.operations.find((op) => op.id === "cache-profile-a-prime").url, confirmPlan.operations.find((op) => op.id === "cache-profile-a-prime").url, "each stage gets a fresh cache-profile namespace");
  const poisonOp = confirmPlan.operations.find((op) => op.id === "poison-0");
  const exactMarker = poisonOp.headers[0].value.replace(/\.invalid$/, "");
  const confirmedObservations = confirmPlan.operations.map((op) => observation(op, 200, "stable", "ordinary"));
  for (const id of ["cache-profile-a-prime", "cache-profile-a-repeat", "cache-profile-b-prime", "cache-profile-b-repeat"]) {
    const item = confirmedObservations.find((entry) => entry.id === id);
    item.response_preview.text = "stable profile";
    if (id.endsWith("repeat")) item.response_headers = hitHeaders;
  }
  for (const id of ["poison-0", "poison-clean-0", "poison-confirm-0"]) {
    const item = confirmedObservations.find((entry) => entry.id === id);
    item.response_body_base64 = Buffer.from(`full response ${exactMarker}`).toString("base64");
    item.response_headers = id === "poison-0" ? [responseHeader("X-Cache", "MISS")] : hitHeaders;
  }
  const queryPoison = confirmPlan.operations.find((op) => op.id === "poison-1");
  const confirmQueryMarker = new URL(queryPoison.url).searchParams.get("utm_source");
  for (const id of ["poison-1", "poison-clean-1", "poison-confirm-1"]) {
    const item = confirmedObservations.find((entry) => entry.id === id);
    item.response_body_base64 = Buffer.from(`query full response ${confirmQueryMarker}`).toString("base64");
    item.response_headers = id === "poison-1" ? [responseHeader("X-Cache", "MISS")] : hitHeaders;
  }
  const confirmed = plugin.analyze(confirmInput, confirmedObservations, cacheContext);
  assert.equal(confirmed.findings.length, 2);
  assert.equal(confirmed.findings[0].confidence, "firm");
  assert.equal(confirmed.findings[0].metadata.proof, "same_key_marker_persistence_with_explicit_hit");
  assert.equal(confirmed.findings[0].metadata.credential_policy, "with_project_credentials");
  assert.equal(Object.hasOwn(confirmed.findings[0], "remediation"), false);
  const redirectInput = { marker: "redirect123", allow_cache_side_effects: true, scan_mode: "light", phase: "confirm", modes: ["poisoning"], headers: ["X-Forwarded-Scheme"], use_only_supplied_headers: true, oracle_families: ["headers"] };
  const redirectPlan = plugin.plan(redirectInput, cacheContext);
  const redirectObservations = redirectPlan.operations.map((op) => observation(op, 200, "ordinary", "ordinary"));
  for (const id of ["cache-profile-a-prime", "cache-profile-a-repeat", "cache-profile-b-prime", "cache-profile-b-repeat"]) {
    const item = redirectObservations.find((entry) => entry.id === id); item.response_preview.text = "stable profile"; if (id.endsWith("repeat")) item.response_headers = hitHeaders;
  }
  for (const index of [0, 1]) for (const id of [`poison-${index}`, `poison-clean-${index}`, `poison-confirm-${index}`]) {
    const item = redirectObservations.find((entry) => entry.id === id); item.status_code = 302; item.response_length = 0; item.response_body_hash = "empty"; item.response_headers = [responseHeader("Location", `http://example.test/login?hp_cache_bust=trial${index}`), responseHeader("X-Cache", id === `poison-${index}` ? "MISS" : "HIT")];
  }
  const redirectResult = plugin.analyze(redirectInput, redirectObservations, cacheContext);
  assert.equal(redirectResult.findings.length, 1, "a fresh scheme-induced redirect persisting in two clean HIT responses is confirmed");
  assert.equal(redirectResult.findings[0].metadata.proof, "same_key_redirect_persistence_with_explicit_hit");
  const httpsBaselineRedirect = redirectObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const id of ["cache-profile-a-prime", "cache-profile-a-repeat", "cache-profile-b-prime", "cache-profile-b-repeat"]) {
    const item = httpsBaselineRedirect.find((entry) => entry.id === id); item.status_code = 302; item.response_length = 0; item.response_body_hash = "empty"; item.response_headers = [responseHeader("Location", "/login"), responseHeader("X-Cache", id.endsWith("repeat") ? "HIT" : "MISS")];
  }
  const httpsBaselineResult = plugin.analyze(redirectInput, httpsBaselineRedirect, cacheContext);
  assert.equal(httpsBaselineResult.findings.length, 1, "a stable HTTPS or relative baseline redirect can prove an otherwise identical HTTP scheme mutation");
  assert.equal(httpsBaselineResult.findings[0].evidence_exchange_ids.length, 6, "both independent redirect trials are retained as finding evidence");
  const changedRedirectTarget = httpsBaselineRedirect.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const index of [0, 1]) for (const id of [`poison-${index}`, `poison-clean-${index}`, `poison-confirm-${index}`]) {
    const item = changedRedirectTarget.find((entry) => entry.id === id); item.response_headers = [responseHeader("Location", `http://example.test/other?hp_cache_bust=trial${index}`), responseHeader("X-Cache", id === `poison-${index}` ? "MISS" : "HIT")];
  }
  assert.equal(plugin.analyze(redirectInput, changedRedirectTarget, cacheContext).findings.length, 0, "a markerless scheme oracle cannot claim a redirect whose host/path target also changed");
  const preexistingRedirect = redirectObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const [index, id] of ["baseline-with-project-credentials-1", "baseline-with-project-credentials-2", "baseline-without-project-credentials-1", "baseline-without-project-credentials-2"].entries()) {
    const item = preexistingRedirect.find((entry) => entry.id === id); item.status_code = 302; item.response_headers = [responseHeader("Location", `http://example.test/login?hp_cache_bust=existing${index}`)];
  }
  assert.equal(plugin.analyze(redirectInput, preexistingRedirect, cacheContext).findings.length, 0, "a redirect already present in clean baselines is not credited to the scheme header");
  const ordinaryVaryingRedirect = redirectObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const [index, id] of ["baseline-with-project-credentials-1", "baseline-with-project-credentials-2", "baseline-without-project-credentials-1", "baseline-without-project-credentials-2"].entries()) {
    const item = ordinaryVaryingRedirect.find((entry) => entry.id === id); item.status_code = 302; item.response_headers = [responseHeader("Location", `http://example.test/login?hp_cache_bust=baseline${index}`)];
  }
  assert.equal(plugin.analyze(redirectInput, ordinaryVaryingRedirect, cacheContext).findings.length, 0, "ordinary redirects that differ only by the cache buster cannot satisfy the markerless scheme oracle");
  assert.deepEqual({ ...confirmed.result.credential_mode }, {
    baseline_with_project_credentials: "with_project_credentials",
    baseline_without_project_credentials: "without_project_credentials",
  });
  assert.equal(confirmed.result.follow_up.phase, "advanced");
  assert.deepEqual(Array.from(confirmed.result.follow_up.confirmed_query_parameters), ["utm_source"]);
  assert.deepEqual(Array.from(confirmed.result.follow_up.known_root_causes), Array.from(confirmed.findings, (finding) => finding.metadata.root_cause));

  const mergedInputKinds = confirmedObservations.map((item) => ({ ...item }));
  for (const [index, candidateMarker] of [[0, exactMarker], [1, confirmQueryMarker]]) {
    for (const id of [`poison-${index}`, `poison-clean-${index}`, `poison-confirm-${index}`]) {
      mergedInputKinds.find((entry) => entry.id === id).response_body_base64 = Buffer.from(`shared effect ${candidateMarker}`).toString("base64");
    }
  }
  const mergedInputKindsResult = plugin.analyze(confirmInput, mergedInputKinds, cacheContext);
  assert.equal(mergedInputKindsResult.findings.length, 1, "equivalent header and query effects deduplicate to one root cause");
  assert.equal(mergedInputKindsResult.findings[0].metadata.variant_count, 2);
  assert.deepEqual(Array.from(mergedInputKindsResult.result.follow_up.confirmed_query_parameters), ["utm_source"], "dedup preserves confirmed query inputs for advanced follow-up generation");

  const mutationOnly = confirmedObservations.map((item) => ({ ...item, response_preview: { text: item.response_preview.text } }));
  for (const item of mutationOnly.filter((entry) => /^poison-(?:clean-|confirm-)?[01]$/.test(entry.id))) {
    delete item.response_body_base64; item.response_preview.text = "same changed representation";
  }
  const mutationResult = plugin.analyze(confirmInput, mutationOnly, cacheContext);
  assert.equal(mutationResult.findings.length, 0, "marker-free response mutations never become findings");
  assert.ok(mutationResult.result.mutation_diagnostics.some((item) => item.classification === "inconclusive_mutation_only"));

  const noHit = confirmedObservations.map((item) => ({ ...item, response_headers: [] }));
  const noHitResult = plugin.analyze(confirmInput, noHit, cacheContext);
  assert.equal(noHitResult.findings.length, 0, "marker persistence without an explicit cache HIT remains diagnostic");
  assert.ok(noHitResult.result.mutation_diagnostics.some((item) => item.classification === "marker_persisted_proof_incomplete"));
  const noIsolation = confirmedObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  noIsolation.find((item) => item.id === "cache-profile-b-repeat").response_headers = [];
  assert.equal(plugin.analyze(confirmInput, noIsolation, cacheContext).findings.length, 0, "isolated-key findings require a two-key isolation profile");
  const poisonAlreadyHit = confirmedObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  poisonAlreadyHit.find((item) => item.id === "poison-0").response_headers = hitHeaders;
  assert.ok(!plugin.analyze(confirmInput, poisonAlreadyHit, cacheContext).findings.some((finding) => finding.metadata.variant === "header:x-forwarded-host"), "a marker-bearing cache HIT cannot be credited as the seeding request");

  const lightInput = { marker: "lightmode123", allow_cache_side_effects: true, scan_mode: "light", modes: ["poisoning"] };
  const lightPlan = plugin.plan(lightInput, cacheContext);
  assert.equal(lightPlan.result.phase, "confirm");
  assert.ok(lightPlan.result.poison_variants <= 20);
  assert.ok(lightPlan.operations.filter((op) => /^poison-\d+$/.test(op.id)).every((op) => op.headers.length <= 2));
  assert.ok(lightPlan.operations.some((op) => op.headers?.some((header) => header.name === "X-Forwarded-Host")));
  assert.ok(lightPlan.operations.some((op) => op.headers?.some((header) => header.name === "X-Forwarded-Host") && op.headers?.some((header) => header.name === "X-Forwarded-Scheme")), "Light includes the common forwarding-host plus scheme combination");
  assert.ok(lightPlan.operations.every((op) => !op.headers?.some((header) => header.name === "AB-API-Company-ID")), "Light excludes the long-tail bundled wordlist");
  const delayedPlan = plugin.plan({ ...lightInput, poison_attempts: 20, poison_interval_ms: 30000, max_poison_variants: 500 }, cacheContext);
  assert.equal(delayedPlan.result.poison_variants, 1, "cumulative retry delays bound the number of selected variants");
  assert.ok(delayedPlan.operations.filter((op) => op.delay_before_ms).reduce((total, op) => total + op.delay_before_ms, 0) <= delayedPlan.result.cumulative_delay_budget_ms);

  const advancedInput = { ...confirmed.result.follow_up, allow_shared_cache_key_tests: true, confirmed_query_parameters: ["utm_source", "callback"] };
  const advancedPlan = plugin.plan(advancedInput, cacheContext);
  const advancedPoisons = advancedPlan.operations.filter((op) => /^poison-\d+$/.test(op.id));
  assert.equal(advancedPlan.result.phase, "advanced");
  assert.notEqual(confirmPlan.operations.find((op) => op.id === "cache-profile-a-prime").url, advancedPlan.operations.find((op) => op.id === "cache-profile-a-prime").url, "advanced profiling cannot reuse warmed confirmation keys");
  assert.ok(advancedPoisons.some((op) => op.cookie_params), "Full advanced covers bundled cookie candidates");
  assert.ok(advancedPoisons.some((op) => op.body_base64), "Full advanced covers fat GET candidates");
  const reflectedFatGetPlan = plugin.plan({ ...advancedInput, confirmed_query_parameters: [], parameter_names: ["utm_content"], use_parameter_wordlist: false }, cacheContext);
  assert.ok(reflectedFatGetPlan.operations.some((op) => op.body_base64), "Full advanced tests a reflected keyed-query name as a potential unkeyed GET-body input");
  assert.equal(reflectedFatGetPlan.result.coverage["fat-get"].skipped, 0, "Fat GET coverage does not contradict generated and tested probes");
  const combinedFatGetPlan = plugin.plan({ ...advancedInput, confirmed_query_parameters: [], parameter_names: ["utm_content"], fat_get_parameters: ["explicit_name"], use_parameter_wordlist: false }, cacheContext);
  const fatGetBodies = combinedFatGetPlan.operations.filter((op) => op.body_base64).map((op) => Buffer.from(op.body_base64, "base64").toString());
  assert.ok(fatGetBodies.some((body) => body.startsWith("explicit_name=")) && fatGetBodies.some((body) => body.startsWith("utm_content=")), "explicit Fat GET names augment rather than replace reflected candidates");
  const singleCarrierCloaking = plugin.plan({ ...advancedInput, confirmed_query_parameters: ["utm_content"], parameter_names: ["utm_content"], use_parameter_wordlist: false }, cacheContext);
  assert.ok(singleCarrierCloaking.operations.some((op) => /utm_content=.*;callback=/.test(op.url)), "one confirmed unkeyed carrier generates bounded cloaking probes for common target parameters");
  const reflectedCarrierCloaking = plugin.plan({ ...advancedInput, confirmed_query_parameters: [], parameter_names: ["utm_content", "callback"], use_parameter_wordlist: false }, cacheContext);
  const reflectedCloakingPoison = reflectedCarrierCloaking.operations.find((op) => /^poison-\d+$/.test(op.id) && /utm_content=.*;callback=/.test(op.url));
  assert.ok(reflectedCloakingPoison, "screen-reflected carrier names remain eligible for exact-marker cloaking confirmation");
  assert.ok(/[?&]hp_cache_bust=/.test(reflectedCloakingPoison.url), "cloaking uses a fresh isolated cache key instead of the public target key");
  assert.ok(reflectedCloakingPoison.headers.some((header) => header.name === "Cache-Control" && header.value === "no-cache"), "cloaking poison requests force bounded revalidation");
  assert.ok(advancedPoisons.some((op) => /;/.test(op.url)), "Full advanced covers parameter cloaking");
  assert.ok(advancedPoisons.some((op) => /\?hpfullstage123q0$/.test(op.url)), "shared full-query testing is included only after acknowledgement");
  const fullQueryPoison = advancedPoisons.find((op) => /\?hpfullstage123q0$/.test(op.url));
  assert.ok(fullQueryPoison.headers.some((header) => header.name === "Cache-Control" && header.value === "no-cache"), "shared full-query poison requests ask the cache to revalidate instead of crediting a pre-existing HIT");
  for (const family of ["header-combinations", "cookies", "full-query", "parameter-cloaking", "fat-get"]) {
    assert.ok(advancedPlan.result.coverage[family].tested > 0, `fair selection gives ${family} coverage`);
  }
  assert.equal(advancedPlan.result.coverage["query-parameters"].tested, 0, "advanced does not repeat direct query probes already completed by confirmation");
  const repeatedRootObservations = advancedPlan.operations.map((op) => observation(op, 200, "stable", "ordinary"));
  for (const id of ["cache-profile-a-prime", "cache-profile-a-repeat", "cache-profile-b-prime", "cache-profile-b-repeat"]) {
    const item = repeatedRootObservations.find((entry) => entry.id === id);
    item.response_preview.text = "stable profile";
    if (id.endsWith("repeat")) item.response_headers = hitHeaders;
  }
  const combinationPoison = advancedPoisons.find((op) => op.headers?.some((header) => header.name === "X-Forwarded-Host") && op.headers?.some((header) => header.name === "X-Forwarded-Scheme"));
  assert.ok(combinationPoison, "advanced includes the default forwarding-header combination");
  const combinationIndex = combinationPoison.id.match(/^poison-(\d+)$/)[1];
  const combinationMarker = combinationPoison.headers.find((header) => header.name === "X-Forwarded-Host").value.replace(/\.invalid$/, "");
  for (const id of [`poison-${combinationIndex}`, `poison-clean-${combinationIndex}`, `poison-confirm-${combinationIndex}`]) {
    const item = repeatedRootObservations.find((entry) => entry.id === id);
    item.response_body_base64 = Buffer.from(`full response ${combinationMarker}`).toString("base64");
    item.response_headers = id === `poison-${combinationIndex}` ? [responseHeader("X-Cache", "MISS")] : hitHeaders;
  }
  const repeatedRootResult = plugin.analyze(advancedInput, repeatedRootObservations, cacheContext);
  assert.equal(repeatedRootResult.findings.length, 0, "advanced aliases of a root cause persisted by confirmation are suppressed across stages");
  assert.ok(repeatedRootResult.result.mutation_diagnostics.some((item) => item.classification === "duplicate_root_cause_suppressed"));
  const queuedTargetResult = plugin.analyze({ ...advancedInput, target_queue: [{ url: "https://example.test/resources/js/next.js", cache_key_mode: "isolated" }] }, repeatedRootObservations, cacheContext);
  assert.equal(queuedTargetResult.result.follow_up.phase, "screen");
  assert.equal(queuedTargetResult.result.follow_up.target_url, "https://example.test/resources/js/next.js", "Full continues with the next bounded cacheable target after advanced analysis");
  assert.ok(queuedTargetResult.result.follow_up.known_root_causes.length >= advancedInput.known_root_causes.length);

  const separatedDeceptionPlan = plugin.plan({ marker: "separate123", allow_cache_side_effects: true, scan_mode: "full", phase: "advanced", modes: ["deception"], target_url: "https://example.test/resources/js/app.js", deception_base_url: "https://example.test/account" }, cacheContext);
  assert.ok(separatedDeceptionPlan.operations.filter((op) => op.id.startsWith("deception-")).every((op) => !/\/resources\/js\/app\.js/.test(op.url)), "discovered poisoning targets do not redirect deception probes into resource paths");

  const sharedDenied = { ...advancedInput };
  delete sharedDenied.allow_shared_cache_key_tests;
  const safeAdvanced = plugin.plan(sharedDenied, cacheContext);
  assert.ok(!safeAdvanced.operations.some((op) => op.type === "raw_http1"), "shared-key normalization remains acknowledgement-gated");
  assert.ok(!safeAdvanced.operations.some((op) => /\?hpfullstage123q0$/.test(op.url)), "full-query remains acknowledgement-gated");
  assert.ok(safeAdvanced.operations.some((op) => /^poison-\d+$/.test(op.id) && /[?&]hp_cache_bust=/.test(op.url) && /;/.test(op.url)), "isolated parameter cloaking does not require shared-key acknowledgement");

  const strictInput = { marker: "stricthead12", allow_cache_side_effects: true, scan_mode: "light", modes: ["poisoning"], shared_header_cache_key_oracle: true, allow_shared_cache_key_tests: true };
  const strictPlan = plugin.plan(strictInput, context("https://example.test/js/app.js?callback=x"));
  assert.equal(strictPlan.operations.find((op) => op.id === "poison-0").url, "https://example.test/js/app.js?callback=x");

  const pagedContext = context();
  pagedContext.resources = { headers: Array.from({ length: 5000 }, (_, index) => `X-Paged-${index}`).join("\n"), parameters: "", cookies: "" };
  const pagedInput = { marker: "pagination12", allow_cache_side_effects: true, modes: ["poisoning"], header_bucket_size: 2, use_parameter_wordlist: false };
  const firstPage = plugin.plan(pagedInput, pagedContext);
  assert.ok(firstPage.result.screen_next_cursor > 0);
  assert.ok(firstPage.result.coverage.headers.deferred > 0, "partial pages report deferred coverage honestly");
  const firstPageObservations = firstPage.operations.map((op) => observation(op, 200, "stable", "stable"));
  const firstPageResult = plugin.analyze(pagedInput, firstPageObservations, pagedContext);
  assert.equal(firstPageResult.result.follow_up.phase, "screen");
  assert.equal(firstPageResult.result.follow_up.screen_cursor, firstPage.result.screen_next_cursor);
  const secondPage = plugin.plan(firstPageResult.result.follow_up, pagedContext);
  assert.ok(secondPage.result.coverage.headers.tested > firstPage.result.coverage.headers.tested, "screen continuation coverage is cumulative");

  const stressContext = context();
  stressContext.resources = { headers: Array.from({ length: 5000 }, (_, index) => `X-Stress-${index}`).join("\n"), parameters: "", cookies: "" };
  const stressInput = { marker: "stresscache12", allow_cache_side_effects: true, modes: ["poisoning"], header_bucket_size: 2, use_parameter_wordlist: false };
  const stressPlan = plugin.plan(stressInput, stressContext);
  assert.ok(stressPlan.operations.length >= 1900 && stressPlan.operations.length <= 2000);
  const largeBody = Buffer.from("S".repeat(9500)).toString("base64");
  const serializedStress = JSON.stringify(stressPlan.operations.map((op) => ({ ...observation(op, 200, "stress", "stable"), response_body_base64: largeBody })));
  const stressStarted = performance.now();
  const stressResult = plugin.analyze(stressInput, JSON.parse(serializedStress), stressContext);
  const stressElapsed = performance.now() - stressStarted;
  assert.equal(stressResult.findings.length, 0);
  assert.ok(stressElapsed < 5000, `large captured-body aggregation took ${stressElapsed.toFixed(0)}ms`);

  const normalizationInput = { marker: "rawnorm123", allow_cache_side_effects: true, scan_mode: "full", phase: "advanced", modes: ["poisoning"], oracle_families: ["url-normalization"], allow_shared_cache_key_tests: true, url_normalization_oracle: true };
  const normalizationPlan = plugin.plan(normalizationInput, context());
  assert.equal(normalizationPlan.operations.filter((op) => op.type === "raw_http1").length, 6);
  const rawObservation = (op) => {
    const repeat = op.id.endsWith("-0") ? 0 : 1;
    const response = `HTTP/1.1 200 OK\r\nX-Cache: ${op.id.startsWith("normalization-poison-") ? "MISS" : "HIT"}\r\n\r\nPath <hprawnorm123n${repeat}>`;
    return { id: op.id, raw: { exchange_id: Math.floor(Math.random() * 100000) + 1, response_transcript_base64: Buffer.from(response).toString("base64"), responses: [{ offset: 0, length: response.length }] } };
  };
  const normalizationObservations = normalizationPlan.operations.map((op) => op.type === "raw_http1" ? rawObservation(op) : observation(op, 200, "stable", "stable"));
  assert.ok(plugin.analyze(normalizationInput, normalizationObservations, context()).findings.some((finding) => finding.metadata.variant === "url-normalization"));

  const duplicateDeceptionInput = { marker: "dedupe1234", allow_cache_side_effects: true, scan_mode: "light", modes: ["deception"], static_extensions: ["js"], path_delimiters: [";", ";"], static_directories: ["assets"], normalization_delimiters: ["%23"], exact_cache_files: ["index.html"], max_deception_variants: 10 };
  const fullDeceptionOnly = plugin.plan({ ...duplicateDeceptionInput, scan_mode: "full" }, context("https://example.test/account"));
  assert.equal(fullDeceptionOnly.result.phase, "advanced", "deception-only Full scans do not require irrelevant poisoning screen follow-ups");
  assert.ok(fullDeceptionOnly.operations.some((op) => op.id.startsWith("deception-with-project-credentials-")));
  const duplicatePlan = plugin.plan(duplicateDeceptionInput, context("https://example.test/account"));
  const duplicateObservations = duplicatePlan.operations.map((op) => {
    const without = op.id.startsWith("baseline-without-project-credentials-") || op.id.startsWith("deception-baseline-without-project-credentials-");
    const deceptive = op.id.startsWith("deception-");
    const item = observation(op, 200, without ? "public" : "private", without ? "public" : deceptive ? "private" : "private");
    if (op.id.startsWith("deception-with-project-credentials-") && !op.id.startsWith("deception-baseline-")) item.response_headers = [responseHeader("X-Cache", "MISS"), responseHeader("Cache-Control", "max-age=30")];
    if (op.id.startsWith("deception-without-project-credentials-") || op.id.startsWith("deception-confirm-")) item.response_headers = hitHeaders.concat(responseHeader("Cache-Control", "max-age=30"));
    return item;
  });
  const deduped = plugin.analyze(duplicateDeceptionInput, duplicateObservations, context("https://example.test/account")).findings;
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0].metadata.proof, "private_miss_then_two_anonymous_hits");
  assert.ok(deduped[0].metadata.variant_count > 1);
  assert.equal(deduped[0].metadata.seed_credential_policy, "with_project_credentials");
  assert.equal(deduped[0].metadata.retrieval_credential_policy, "without_project_credentials");
  assert.equal(new Set(deduped.map((finding) => finding.metadata.root_cause)).size, deduped.length, "findings are deduplicated by concrete root cause");
  const genericFallback = duplicateObservations.map((item) => ({ ...item, response_preview: { text: item.id.startsWith("deception-") ? "generic SPA shell" : item.response_preview.text }, response_body_hash: item.id.startsWith("deception-") ? "generic-shell" : item.response_body_hash }));
  assert.equal(plugin.analyze(duplicateDeceptionInput, genericFallback, context("https://example.test/account")).findings.length, 0, "a generic SPA fallback that does not match the stable private baseline is not deception");
  const fullBodyCollision = duplicateObservations.map((item) => ({ ...item }));
  for (const item of fullBodyCollision) {
    const credentialFreeRetrieval = item.id.startsWith("deception-without-project-credentials-") || item.id.startsWith("deception-confirm-");
    if (credentialFreeRetrieval) {
      item.response_body_base64 = Buffer.from("different full anonymous body outside shared preview").toString("base64"); item.response_body_hash = "anonymous-full";
    } else if (!item.id.startsWith("baseline-without-project-credentials-")) {
      item.response_body_base64 = Buffer.from("credentialed private body").toString("base64"); item.response_body_hash = "private-full";
    }
  }
  assert.equal(plugin.analyze(duplicateDeceptionInput, fullBodyCollision, context("https://example.test/account")).findings.length, 0, "matching previews cannot hide different full bodies in deception proof");
  const preexistingDeception = duplicateObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const item of preexistingDeception.filter((entry) => entry.id.startsWith("deception-with-project-credentials-"))) item.response_headers = hitHeaders;
  assert.equal(plugin.analyze(duplicateDeceptionInput, preexistingDeception, context("https://example.test/account")).findings.length, 0, "an already cached credentialed deception probe cannot prove a fresh private seed");
  const unknownSeed = duplicateObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const item of unknownSeed.filter((entry) => entry.id.startsWith("deception-with-project-credentials-"))) item.response_headers = [responseHeader("Cache-Control", "max-age=30")];
  assert.equal(plugin.analyze(duplicateDeceptionInput, unknownSeed, context("https://example.test/account")).findings.length, 0, "an unclassified seed is not credited as a fresh cache fill");
  const oneHitOnly = duplicateObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const item of oneHitOnly.filter((entry) => entry.id.startsWith("deception-without-project-credentials-"))) item.response_headers = [responseHeader("X-Cache", "MISS")];
  assert.equal(plugin.analyze(duplicateDeceptionInput, oneHitOnly, context("https://example.test/account")).findings.length, 0, "both anonymous retrievals must independently report HIT");

  const deceptionDiscoveryContext = context("https://example.test/account");
  deceptionDiscoveryContext.resources = cacheContext.resources;
  deceptionDiscoveryContext.base_exchange.page_discovery = { targets: ["https://example.test/app.js"] };
  assert.equal(plugin.plan({ ...duplicateDeceptionInput, scan_mode: "full" }, deceptionDiscoveryContext).result.phase, "advanced", "deception-only scans do not require the private base URL to be cacheable before testing path variants");

  const separatedInput = { ...duplicateDeceptionInput, scan_mode: "full", phase: "advanced", target_url: "https://example.test/resources/app.js", deception_base_url: "https://example.test/account" };
  const separatedPlan = plugin.plan(separatedInput, cacheContext);
  const separatedObservations = separatedPlan.operations.map((op) => {
    const publicResource = op.id.startsWith("baseline-");
    const publicAccount = op.id.startsWith("deception-baseline-without-");
    const item = observation(op, 200, publicResource ? "resource" : publicAccount ? "public-account" : "private-account", publicResource ? "public resource" : publicAccount ? "login" : "private account data");
    if (op.id.startsWith("deception-with-project-credentials-") && !op.id.startsWith("deception-baseline-")) item.response_headers = [responseHeader("X-Cache", "MISS"), responseHeader("Cache-Control", "max-age=30")];
    if (op.id.startsWith("deception-without-project-credentials-") || op.id.startsWith("deception-confirm-")) item.response_headers = hitHeaders.concat(responseHeader("Cache-Control", "max-age=30"));
    return item;
  });
  const separatedFinding = plugin.analyze(separatedInput, separatedObservations, cacheContext).findings.find((finding) => finding.metadata.variant === "delimiter:;:js");
  assert.ok(separatedFinding, "PortSwigger-style path delimiter deception is proven without marker reflection even when poisoning uses a separate public resource target");
  const conflictingCache = separatedObservations.map((item) => ({ ...item, response_headers: item.response_headers.slice() }));
  for (const item of conflictingCache.filter((entry) => entry.id.startsWith("deception-without-project-credentials-") || entry.id.startsWith("deception-confirm-"))) item.response_headers.push(responseHeader("Cache-Control", "private"));
  assert.equal(plugin.analyze(separatedInput, conflictingCache, cacheContext).findings.length, 0, "private/no-store evidence overrides apparent HIT headers");

  assert.throws(() => plugin.plan({ marker: "unsafe1234", scan_mode: "light" }, cacheContext), /allow_cache_side_effects/);
  assert.throws(() => plugin.plan({ ...strictInput, allow_shared_cache_key_tests: undefined }, cacheContext), /allow_shared_cache_key_tests/);
  const postContext = context(); postContext.base_exchange.method = "POST";
  assert.throws(() => plugin.plan({ marker: "safemethod12", allow_cache_side_effects: true }, postContext), /GET or HEAD/);
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
  assert.ok(plan.operations.every((op) => op.credential_mode === "without_project_credentials"));
  const referencedPlan = plugin.plan({ primary: { profile: "sco" }, secondary: { cookie_file: "/private/second.json" }, domains: ["example.test"] }, ctx);
  assert.equal(referencedPlan.operations.find((op) => op.id.includes("primary")).identity.profile, "sco");
  assert.equal(referencedPlan.operations.find((op) => op.id.includes("secondary")).identity.cookie_file, "/private/second.json");
  const observations = plan.operations.map((op) => observation(op, op.id.includes("anonymous") ? 403 : 200, op.id.includes("anonymous") ? "denied" : "private", "response"));
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].title, /cross-user/i);
  assert.equal(result.result.classifications[0].evidence_exchange_ids.length, 6);
  assert.equal(result.findings[0].evidence_exchange_ids.length, 6);

  const volatile = plan.operations.map((op) => {
    const anonymous = op.id.includes("anonymous");
    const repeat = op.id.endsWith("1") ? "2" : "1";
    return observation(op, anonymous ? 403 : 200, `volatile-${op.id}`, anonymous ? "denied" : JSON.stringify({ artists: [{ id: 7, name: "same", avatar: `https://cdn.test/a.jpg?sig=${repeat}&expires=170000000${repeat}` }], logid: `log-${repeat}`, timestamp: 1700000000 + Number(repeat) }));
  });
  const volatileResult = plugin.analyze(input, volatile, ctx);
  assert.equal(volatileResult.result.classifications[0].primary_outcome, "allowed");
  assert.equal(volatileResult.result.classifications[0].primary_allowed, true);
  assert.equal(volatileResult.result.classifications[0].primary_stable, true, "known volatile fields are normalized conservatively");

  const materiallyDifferent = volatile.map((item) => ({ ...item }));
  materiallyDifferent.find((item) => item.id === "shape-0-primary-1").response_preview.text = JSON.stringify({ artists: [{ id: 99, name: "different" }] });
  const materiallyDifferentResult = plugin.analyze(input, materiallyDifferent, ctx);
  assert.equal(materiallyDifferentResult.result.classifications[0].primary_outcome, "allowed");
  assert.equal(materiallyDifferentResult.result.classifications[0].primary_stable, false);
  const compactedAuth = observations.map((item) => ({ ...item, response_body_base64: null, response_body_omitted_reason: "analysis_budget", response_preview: { text: "same truncated prefix" } }));
  assert.equal(plugin.analyze(input, compactedAuth, ctx).result.classifications[0].primary_stable, false, "compacted bodies cannot establish authorization-response stability from previews");
  const semanticTokenDifference = volatile.map((item) => ({ ...item }));
  semanticTokenDifference.find((item) => item.id === "shape-0-primary-0").response_preview.text = '{"avatar":"https://cdn.test/a?token=identity-one"}';
  semanticTokenDifference.find((item) => item.id === "shape-0-primary-1").response_preview.text = '{"avatar":"https://cdn.test/a?token=identity-two"}';
  assert.equal(plugin.analyze(input, semanticTokenDifference, ctx).result.classifications[0].primary_stable, false, "generic token query values remain semantic");

  const unstableAnonymous = plan.operations.map((op) => observation(op, 200, op.id, op.id.includes("anonymous") ? `public-${op.id}` : "same private body"));
  const unstableAnonymousResult = plugin.analyze(input, unstableAnonymous, ctx);
  assert.equal(unstableAnonymousResult.result.classifications[0].anonymous_outcome, "allowed");
  assert.equal(unstableAnonymousResult.result.classifications[0].protected_resource, null);
  assert.ok(unstableAnonymousResult.findings.some((finding) => /cross-user/i.test(finding.title) && finding.confidence === "tentative"));
  assert.ok(!unstableAnonymousResult.findings.some((finding) => /unauthenticated/i.test(finding.title)));

  const noAnonymousInput = { ...input, include_anonymous: false };
  const noAnonymousPlan = plugin.plan(noAnonymousInput, ctx);
  const noAnonymousResult = plugin.analyze(noAnonymousInput, noAnonymousPlan.operations.map((op) => observation(op, 200, "same", "same private body")), ctx);
  assert.equal(noAnonymousResult.result.classifications[0].anonymous_outcome, "not_tested");
  assert.equal(noAnonymousResult.result.classifications[0].anonymous_allowed, null);
  assert.equal(noAnonymousResult.result.classifications[0].protected_resource, null);

  const mixed = plan.operations.map((op) => observation(op, op.id === "shape-0-primary-1" ? 403 : 200, op.id, op.id === "shape-0-primary-1" ? "denied" : "same"));
  const mixedResult = plugin.analyze(input, mixed, ctx);
  assert.equal(mixedResult.result.classifications[0].primary_outcome, "inconclusive");
  assert.equal(mixedResult.result.classifications[0].primary_allowed, null);

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
  assert.equal(anonymousResult.result.classifications[0].evidence_exchange_ids.length, 2);
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
  const jwtManifest = JSON.parse(await readFile(new URL("jwt-analyzer/plugin.json", root), "utf8"));
  assert.equal(jwtManifest.version, "1.3.4");
  assert.equal(jwtManifest.actions[0].requires_base_exchange, true);
  assert.match(jwtManifest.actions[0].input_schema.properties.token.description, /override.*required saved base request/i);
  assert.match(jwtManifest.actions[0].input_schema.properties.target_url.description, /replay destination override/i);
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ sub: "1", exp: 4102444800 })}.signature`;
  const ctx = privilegedContext({ headers: [["Authorization", `Bearer ${token}`]] });
  const passivePlan = plugin.plan({}, ctx);
  assert.equal(passivePlan.operations.length, 0, "JWT analysis is passive unless active=true is explicit");
  assert.deepEqual(Array.from(passivePlan.result.active_variants), []);
  const input = { active: true, tests: ["none", "invalid_signature", "expired"] };
  const plan = plugin.plan(input, ctx);
  assert.equal(plan.operations.length, 8);
  assert.ok(plan.operations.every((op) => op.type === "http_request" && op.headers[0].name === "Authorization"));
  const observations = plan.operations.map((op) => observation(op, 200, "authenticated", "account"));
  const result = plugin.analyze(input, observations, ctx);
  assert.equal(result.findings.filter((finding) => /bypass/i.test(finding.title)).length, 3);
  const compactedJwt = observations.map((item) => ({ ...item, response_body_base64: null, response_body_omitted_reason: "analysis_budget", response_preview: { text: "same truncated prefix" } }));
  assert.equal(plugin.analyze(input, compactedJwt, ctx).findings.filter((finding) => /bypass/i.test(finding.title)).length, 0, "compacted bodies cannot prove a JWT bypass from matching previews");

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

  const rsaKey = await readFile(new URL("jwt-analyzer/resources/rsa-test-key.json", root), "utf8");
  const rsaJwks = await readFile(new URL("jwt-analyzer/resources/rsa-test-jwks.json", root), "utf8");
  const nativeContext = privilegedContext({ headers: [["Authorization", `Bearer ${token}`]] });
  nativeContext.resources = { "rsa-test-key": rsaKey, "rsa-test-jwks": rsaJwks, "hmac-secrets": "" };
  const nativeInput = { active: true, tests: ["embedded_jwk", "jku"], target_subject: "administrator", jku_url: "https://exploit.example.test/jwks.json" };
  const nativePlan = plugin.plan(nativeInput, nativeContext);
  assert.deepEqual(Array.from(nativePlan.result.active_variants), ["embedded_jwk", "jku"]);
  assert.equal(nativePlan.operations.length, 6);
  const publicJwk = JSON.parse(rsaJwks).keys[0];
  for (const operation of nativePlan.operations.filter((item) => item.id.endsWith("-0") && item.id.startsWith("variant-"))) {
    const signed = operation.headers[0].value.slice(7), pieces = signed.split("."), header = JSON.parse(Buffer.from(pieces[0], "base64url")), payload = JSON.parse(Buffer.from(pieces[1], "base64url"));
    assert.equal(payload.sub, "administrator");
    assert.ok(header.jwk || header.jku === nativeInput.jku_url);
    assert.equal(verifySignature("RSA-SHA256", Buffer.from(`${pieces[0]}.${pieces[1]}`), createPublicKey({ key: header.jwk || publicJwk, format: "jwk" }), Buffer.from(pieces[2], "base64url")), true);
  }
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
