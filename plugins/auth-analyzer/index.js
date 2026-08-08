(function () {
  "use strict";

  function base(context) {
    if (!context.base_exchange || !context.base_exchange.exchange_id) throw new Error("AuthAnalyzer requires a saved base exchange");
    return context.base_exchange;
  }
  function host(url) {
    var match = String(url || "").match(/^https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase() : "";
  }
  function matches(value, pattern) {
    value = value.toLowerCase(); pattern = String(pattern).toLowerCase().replace(/\.$/, "");
    if (pattern.slice(0, 2) === "*.") return value.length > pattern.length - 1 && value.slice(-(pattern.length - 1)) === pattern.slice(1);
    return value === pattern;
  }
  function identityHeaders(identity) {
    var headers = (identity && identity.headers || []).map(function (item) { return { name: String(item.name), value: String(item.value) }; });
    if (identity && identity.cookie) headers.push({ name: "Cookie", value: String(identity.cookie) });
    return headers;
  }
  function shapes(input, context) {
    var all = [base(context)].concat(context.related_exchanges || []), seen = {}, domains = input.domains || [];
    return all.filter(function (shape) {
      var key = shape.exchange_id + "", method = String(shape.method || "GET").toUpperCase();
      if (seen[key] || !domains.some(function (pattern) { return matches(host(shape.url), pattern); })) return false;
      if (["GET", "HEAD", "OPTIONS"].indexOf(method) === -1 && input.allow_state_changes !== true) return false;
      seen[key] = true; return true;
    }).slice(0, Math.max(1, Math.min(Number(input.max_requests || 100), 500)));
  }
  function operation(id, shape, identity, anonymous) {
    var op = { id: id, type: "http_request", base_exchange_id: shape.exchange_id, method: shape.method, protocol: "auto" };
    op.header_tombstones = ["Cookie", "Authorization", "Proxy-Authorization"];
    if (!anonymous) op.headers = identityHeaders(identity);
    return op;
  }
  function plan(input, context) {
    if (!input.primary || !input.secondary) throw new Error("primary and secondary identities are required");
    if (!Array.isArray(input.domains) || !input.domains.length) throw new Error("at least one domain pattern is required");
    var operations = [], selected = shapes(input, context), includeAnonymous = input.include_anonymous !== false;
    selected.forEach(function (shape, index) {
      for (var repeat = 0; repeat < 2; repeat += 1) {
        operations.push(operation("shape-" + index + "-primary-" + repeat, shape, input.primary, false));
        operations.push(operation("shape-" + index + "-secondary-" + repeat, shape, input.secondary, false));
        if (includeAnonymous) operations.push(operation("shape-" + index + "-anonymous-" + repeat, shape, null, true));
      }
    });
    return { operations: operations, result: { request_shapes: selected.length, identities: includeAnonymous ? 3 : 2 } };
  }
  function mapById(items) { var map = {}; items.forEach(function (item) { map[item.id] = item; }); return map; }
  function text(item) { return String(item && item.response_preview && item.response_preview.text || "").toLowerCase(); }
  function same(a, b) {
    if (!a || !b || a.status_code !== b.status_code) return false;
    if (a.response_body_hash && b.response_body_hash) return a.response_body_hash === b.response_body_hash;
    return a.response_length === b.response_length && text(a) === text(b);
  }
  function pair(map, prefix) { var a = map[prefix + "0"], b = map[prefix + "1"]; return a && b && same(a, b) ? a : null; }
  function allowed(item) { return item && item.status_code >= 200 && item.status_code < 400; }
  function analyze(input, observations, context) {
    var map = mapById(observations), findings = [], classifications = [];
    shapes(input, context).forEach(function (shape, index) {
      var prefix = "shape-" + index + "-", primary = pair(map, prefix + "primary-"), secondary = pair(map, prefix + "secondary-");
      var anonymous = input.include_anonymous === false ? null : pair(map, prefix + "anonymous-");
      var crossIdentity = allowed(primary) && allowed(secondary) && same(primary, secondary);
      var protectedResource = !anonymous || !allowed(anonymous) || !same(primary, anonymous);
      classifications.push({ exchange_id: shape.exchange_id, primary_stable: !!primary, secondary_stable: !!secondary, anonymous_stable: !!anonymous, protected_resource: !!protectedResource, responses_equal: !!crossIdentity });
      if (primary && secondary && crossIdentity && protectedResource) {
        findings.push({
          title: "Possible cross-user authorization exposure",
          severity: "high", confidence: anonymous ? "firm" : "tentative",
          explanation: "The request shape returned the same reproducible allowed response for two distinct identities while the anonymous control was denied or materially different.",
          remediation: "Authorize every object and action against the authenticated principal, not only against possession of a valid session.",
          evidence_exchange_ids: [primary.exchange_id, secondary.exchange_id, anonymous && anonymous.exchange_id].filter(Boolean),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url }
        });
      }
    });
    return { findings: findings, result: { classifications: classifications, tested_operations: observations.length } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
