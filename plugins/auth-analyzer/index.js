(function () {
  "use strict";

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function decode64(value) {
    var output = "", buffer = 0, bits = 0;
    String(value || "").replace(/=+$/, "").split("").forEach(function (character) {
      var index = B64.indexOf(character); if (index < 0) return;
      buffer = (buffer << 6) | index; bits += 6;
      if (bits >= 8) { bits -= 8; output += String.fromCharCode((buffer >> bits) & 255); }
    });
    return output;
  }

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
  function identityKey(identity) {
    var headers = identityHeaders(identity).map(function (item) {
      return String(item.name).toLowerCase().trim() + ":" + String(item.value).trim();
    }).filter(function (item) { return item.split(":").slice(1).join(":").length > 0; });
    headers.sort();
    return headers.join("\n");
  }
  function validateComparisonIdentities(input) {
    if (!input.primary || !input.secondary) throw new Error("primary and secondary identities are required");
    var primary = identityKey(input.primary), secondary = identityKey(input.secondary);
    if (!primary || !secondary) throw new Error("primary and secondary identities must each contain a non-empty cookie or header");
    if (primary === secondary) throw new Error("primary and secondary identities must be distinct");
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
    if (!Array.isArray(input.domains) || !input.domains.length) throw new Error("at least one domain pattern is required");
    var operations = [], selected = shapes(input, context);
    if (context.action === "anonymous_audit") {
      if (input.confirm_expected_protected !== true) throw new Error("anonymous audit requires confirm_expected_protected=true");
      if (input.anonymous_context && !identityKey(input.anonymous_context)) throw new Error("anonymous_context must contain a non-empty cookie or header");
      selected.forEach(function (shape, index) {
        for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("shape-" + index + "-anonymous-" + repeat, shape, input.anonymous_context || null, !input.anonymous_context));
      });
      return { operations: operations, result: { request_shapes: selected.length, identities: ["anonymous"], mode: "anonymous_audit", anonymous_context_supplied: !!input.anonymous_context } };
    }
    validateComparisonIdentities(input);
    var includeAnonymous = input.include_anonymous !== false;
    selected.forEach(function (shape, index) {
      for (var repeat = 0; repeat < 2; repeat += 1) {
        operations.push(operation("shape-" + index + "-primary-" + repeat, shape, input.primary, false));
        operations.push(operation("shape-" + index + "-secondary-" + repeat, shape, input.secondary, false));
        if (includeAnonymous) operations.push(operation("shape-" + index + "-anonymous-" + repeat, shape, null, true));
      }
    });
    return { operations: operations, result: { request_shapes: selected.length, identities: includeAnonymous ? ["primary", "secondary", "anonymous"] : ["primary", "secondary"], mode: "identity_comparison" } };
  }
  function mapById(items) { var map = {}; items.forEach(function (item) { map[item.id] = item; }); return map; }
  function text(item) {
    if (item && item.response_body_base64) return decode64(item.response_body_base64);
    return String(item && item.response_preview && item.response_preview.text || "");
  }
  function normalize(value, input) {
    var output = String(value || "").toLowerCase();
    output = output
      .replace(/(<input\b[^>]*\bname=["']?(?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token)["']?[^>]*\bvalue=)["'][^"']*["']/gi, "$1\"<volatile>\"")
      .replace(/(["'](?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token|nonce|request_id|trace_id)["']\s*[:=]\s*)["'][^"']+["']/gi, "$1\"<volatile>\"")
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "<uuid>")
      .replace(/\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z\b/gi, "<timestamp>")
      .replace(/\s+/g, " ").trim();
    (input.ignore_patterns || []).forEach(function (pattern) {
      try { output = output.replace(new RegExp(String(pattern), "gi"), "<ignored>"); } catch (_) {}
    });
    return output;
  }
  function similarity(left, right) {
    if (left === right) return 1;
    if (!left || !right) return 0;
    var leftTokens = {}, rightTokens = {}, union = {}, common = 0, total = 0;
    left.split(/[^a-z0-9_]+/).filter(Boolean).forEach(function (token) { leftTokens[token] = true; union[token] = true; });
    right.split(/[^a-z0-9_]+/).filter(Boolean).forEach(function (token) { rightTokens[token] = true; union[token] = true; });
    Object.keys(union).forEach(function (token) { total += 1; if (leftTokens[token] && rightTokens[token]) common += 1; });
    return total ? common / total : 0;
  }
  function same(a, b, input) {
    if (!a || !b || a.error || b.error || a.status_code !== b.status_code) return false;
    var left = normalize(text(a), input), right = normalize(text(b), input);
    var threshold = Math.max(0.5, Math.min(Number(input.similarity_threshold == null ? 0.92 : input.similarity_threshold), 1));
    return similarity(left, right) >= threshold;
  }
  function pair(map, prefix, input) { var a = map[prefix + "0"], b = map[prefix + "1"]; return a && b && same(a, b, input) ? a : null; }
  function allowed(item) { return item && item.status_code >= 200 && item.status_code < 400; }
  function analyze(input, observations, context) {
    var map = mapById(observations), findings = [], classifications = [];
    if (context.action === "anonymous_audit") {
      shapes(input, context).forEach(function (shape, index) {
        var anonymous = pair(map, "shape-" + index + "-anonymous-", input), anonymousAllowed = allowed(anonymous);
        classifications.push({ exchange_id: shape.exchange_id, anonymous_stable: !!anonymous, anonymous_allowed: !!anonymousAllowed, mode: "anonymous_audit" });
        if (anonymousAllowed) findings.push({
          title: "Possible unauthenticated authorization exposure", severity: "high", confidence: "firm",
          explanation: "The caller identified this request shape as expected to be protected, but two anonymous requests reproducibly received an allowed response. Any caller-supplied anonymous session context was preserved without inheriting base credentials.",
          remediation: "Require authentication and authorize the requested object or action before returning protected content.",
          evidence_exchange_ids: [anonymous.exchange_id].filter(Boolean),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url, mode: "anonymous_audit" }
        });
      });
      return { findings: findings, result: { mode: "anonymous_audit", classifications: classifications, tested_operations: observations.length } };
    }
    validateComparisonIdentities(input);
    shapes(input, context).forEach(function (shape, index) {
      var prefix = "shape-" + index + "-", primary = pair(map, prefix + "primary-", input), secondary = pair(map, prefix + "secondary-", input);
      var anonymous = input.include_anonymous === false ? null : pair(map, prefix + "anonymous-", input);
      var primaryAllowed = allowed(primary), secondaryAllowed = allowed(secondary), anonymousAllowed = allowed(anonymous);
      var crossIdentity = primaryAllowed && secondaryAllowed && same(primary, secondary, input);
      var protectedResource = !anonymous || !anonymousAllowed || !same(primary, anonymous, input);
      classifications.push({ exchange_id: shape.exchange_id, primary_stable: !!primary, secondary_stable: !!secondary, anonymous_stable: !!anonymous, primary_allowed: !!primaryAllowed, secondary_allowed: !!secondaryAllowed, anonymous_allowed: !!anonymousAllowed, protected_resource: !!protectedResource, responses_equal: !!crossIdentity });
      if (primary && secondary && primaryAllowed !== secondaryAllowed) {
        var allowedIdentity = primaryAllowed ? "primary" : "secondary";
        findings.push({
          title: "Authorization outcome changes between supplied identities",
          severity: "high", confidence: "firm",
          explanation: "The " + allowedIdentity + " identity received a reproducible allowed response while the other supplied identity was denied. This is a privilege or identity boundary that requires review and is exploitable when the allowed identity is lower-privileged or attacker-controlled.",
          remediation: "Define the expected privilege of each test identity and enforce authorization for every object and action on the server.",
          evidence_exchange_ids: [primary.exchange_id, secondary.exchange_id].filter(Boolean),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url, allowed_identity: allowedIdentity, primary_status: primary.status_code, secondary_status: secondary.status_code }
        });
      }
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
      if (primary && anonymous && primaryAllowed && anonymousAllowed && same(primary, anonymous, input)) {
        findings.push({
          title: "Possible unauthenticated authorization exposure",
          severity: "high", confidence: "firm",
          explanation: "The anonymous control reproduced the authenticated response across repeated requests.",
          remediation: "Require authentication and authorize the requested object or action before returning protected content.",
          evidence_exchange_ids: [primary.exchange_id, anonymous.exchange_id].filter(Boolean),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url }
        });
      }
    });
    return { findings: findings, result: { mode: "identity_comparison", classifications: classifications, tested_operations: observations.length } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
