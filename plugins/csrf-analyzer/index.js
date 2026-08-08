(function () {
  "use strict";
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function decode64(value) { var out = "", buffer = 0, bits = 0; String(value || "").replace(/=+$/, "").split("").forEach(function (c) { var i = alphabet.indexOf(c); if (i < 0) return; buffer = (buffer << 6) | i; bits += 6; if (bits >= 8) { bits -= 8; out += String.fromCharCode((buffer >> bits) & 255); } }); return out; }
  function base(context) {
    var value = context.base_exchange;
    if (!value || !value.exchange_id || !value.identity) throw new Error("CSRFAnalyzer requires identity.use access to a saved request");
    if (["GET", "HEAD", "OPTIONS"].indexOf(String(value.method).toUpperCase()) !== -1) throw new Error("CSRFAnalyzer requires a state-changing request shape");
    return value;
  }
  function raw(context) {
    var headers = {}, list = context.base_exchange.identity.request_headers || [];
    list.forEach(function (item) { headers[String(item.name).toLowerCase()] = decode64(item.value_base64); });
    return { headers: headers, body: decode64(context.base_exchange.identity.request_body_base64 || "") };
  }
  function tokenNames(input) { return (input.token_names && input.token_names.length ? input.token_names : ["csrf", "csrf_token", "_csrf", "xsrf", "_token", "authenticity_token"]).map(function (v) { return String(v); }); }
  function mutationList(input, context) {
    var exchange = base(context), data = raw(context), names = tokenNames(input), values = [], seen = {};
    function add(name, patch) { if (!seen[name]) { seen[name] = true; values.push({ name: name, patch: patch }); } }
    names.forEach(function (name) {
      var encoded = encodeURIComponent(name).replace(/%20/g, "+"), query = String(exchange.url).split("?")[1] || "";
      if (new RegExp("(?:^|&)" + encoded.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=", "i").test(query)) {
        add("query-remove:" + name, { query_params: [{ name: name, value: null }] });
        add("query-invalid:" + name, { query_params: [{ name: name, value: "huntproxy-invalid-csrf" }] });
      }
      if (Object.keys(data.headers).some(function (header) { return header.toLowerCase() === name.toLowerCase(); })) {
        add("header-remove:" + name, { header_tombstones: [name] });
        add("header-invalid:" + name, { headers: [{ name: name, value: "huntproxy-invalid-csrf" }] });
      }
    });
    var contentType = String(data.headers["content-type"] || "").toLowerCase(), bodyNames = [];
    if (contentType.indexOf("application/x-www-form-urlencoded") !== -1) data.body.split("&").forEach(function (pair) { bodyNames.push(decodeURIComponent((pair.split("=")[0] || "").replace(/\+/g, " "))); });
    if (contentType.indexOf("application/json") !== -1) { try { bodyNames = Object.keys(JSON.parse(data.body)); } catch (_) {} }
    names.forEach(function (name) { if (bodyNames.some(function (actual) { return actual.toLowerCase() === name.toLowerCase(); })) {
      add("body-remove:" + name, { body_params: [{ name: name, value: null }] });
      add("body-invalid:" + name, { body_params: [{ name: name, value: "huntproxy-invalid-csrf" }] });
    } });
    add("origin-remove", { header_tombstones: ["Origin", "Referer"] });
    add("origin-cross-site", { headers: [{ name: "Origin", value: "https://csrf.invalid" }, { name: "Referer", value: "https://csrf.invalid/huntproxy" }] });
    if (contentType.indexOf("application/json") !== -1 || contentType.indexOf("application/x-www-form-urlencoded") !== -1) add("content-type-text-plain", { headers: [{ name: "Content-Type", value: "text/plain" }] });
    return values.slice(0, Math.max(1, Math.min(Number(input.max_mutations || 30), 50)));
  }
  function operation(id, exchange, patch) {
    var op = { id: id, type: "http_request", base_exchange_id: exchange.exchange_id, method: exchange.method, protocol: "auto" };
    Object.keys(patch || {}).forEach(function (key) { op[key] = patch[key]; }); return op;
  }
  function plan(input, context) {
    if (input.allow_state_change !== true) throw new Error("CSRF testing repeats the state-changing request and requires allow_state_change=true");
    var exchange = base(context), operations = [], mutations = mutationList(input, context);
    for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("baseline-" + repeat, exchange, {}));
    mutations.forEach(function (mutation, index) { for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("mutation-" + index + "-" + repeat, exchange, mutation.patch)); });
    return { operations: operations, result: { mutations: mutations.map(function (item) { return item.name; }), repeated_state_changes: operations.length } };
  }
  function byId(items) { var map = {}; items.forEach(function (item) { map[item.id] = item; }); return map; }
  function preview(item) { return String(item && item.response_preview && item.response_preview.text || "").toLowerCase(); }
  function same(a, b) { return a && b && a.status_code === b.status_code && (a.response_body_hash && b.response_body_hash ? a.response_body_hash === b.response_body_hash : a.response_length === b.response_length); }
  function pair(map, prefix) { return same(map[prefix + "0"], map[prefix + "1"]) ? map[prefix + "0"] : null; }
  function rejected(item) { return !item || item.status_code === 401 || item.status_code === 403 || item.status_code === 419 || /csrf|forbidden|invalid token|origin mismatch/.test(preview(item)); }
  function analyze(input, observations, context) {
    var map = byId(observations), baseline = pair(map, "baseline-"), findings = [], outcomes = [], mutations = mutationList(input, context);
    mutations.forEach(function (mutation, index) {
      var result = pair(map, "mutation-" + index + "-"), accepted = baseline && result && !rejected(result) && result.status_code >= 200 && result.status_code < 400;
      outcomes.push({ mutation: mutation.name, reproducible: !!result, accepted: !!accepted });
      if (accepted && (same(baseline, result) || Math.floor(baseline.status_code / 100) === Math.floor(result.status_code / 100))) findings.push({
        title: "CSRF defense bypass using " + mutation.name, severity: mutation.name.indexOf("content-type") === 0 ? "medium" : "high", confidence: same(baseline, result) ? "firm" : "tentative",
        explanation: "The state-changing request remained successful across two repetitions after this CSRF defense mutation.",
        remediation: "Require an unpredictable session-bound CSRF token and validate Origin/Referer for every state-changing request; reject alternate content types.",
        evidence_exchange_ids: [baseline.exchange_id, result.exchange_id].filter(Boolean), metadata: { mutation: mutation.name }
      });
    });
    return { findings: findings, result: { baseline_stable: !!baseline, outcomes: outcomes, tested_operations: observations.length } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
