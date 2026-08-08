(function () {
  "use strict";

  function base(context) {
    if (!context.base_exchange || !context.base_exchange.exchange_id || !context.base_exchange.url) {
      throw new Error("403Bypasser requires a saved base exchange");
    }
    return context.base_exchange;
  }

  function splitUrl(url) {
    var match = String(url).match(/^(https?:\/\/[^/?#]+)([^?#]*)(\?[^#]*)?$/);
    if (!match) throw new Error("base exchange URL is not HTTP(S)");
    return { origin: match[1], path: match[2] || "/", query: match[3] || "" };
  }

  function pathVariants(url) {
    var parsed = splitUrl(url), path = parsed.path, variants = [], seen = {};
    function add(name, candidate) {
      var full = parsed.origin + candidate + parsed.query;
      if (full !== url && !seen[full]) { seen[full] = true; variants.push({ name: name, url: full }); }
    }
    add("trailing-slash", path.replace(/\/$/, "") + "/");
    add("double-slash", path.replace(/^\//, "//"));
    add("dot-segment", "/./" + path.replace(/^\//, ""));
    add("encoded-dot-segment", "/%2e/" + path.replace(/^\//, ""));
    add("semicolon", path + ";");
    add("path-parameter", path + ";huntproxy=1");
    add("encoded-trailing-slash", path.replace(/\/$/, "") + "%2f");
    add("static-extension", path.replace(/\/$/, "") + ".json");
    return variants;
  }

  function variants(baseExchange, input) {
    var parsed = splitUrl(baseExchange.url), path = parsed.path, values = [];
    pathVariants(baseExchange.url).forEach(function (entry) {
      values.push({ name: "path:" + entry.name, url: entry.url, method: baseExchange.method });
    });
    [
      ["x-original-url", "X-Original-URL", path],
      ["x-rewrite-url", "X-Rewrite-URL", path],
      ["x-forwarded-for", "X-Forwarded-For", "127.0.0.1"],
      ["x-real-ip", "X-Real-IP", "127.0.0.1"],
      ["forwarded", "Forwarded", "for=127.0.0.1;host=" + parsed.origin.replace(/^https?:\/\//, "")],
      ["x-forwarded-uri", "X-Forwarded-Uri", path]
    ].forEach(function (item) {
      values.push({ name: "header:" + item[0], method: baseExchange.method, headers: [{ name: item[1], value: item[2] }] });
    });
    ["GET", "HEAD", "OPTIONS"].forEach(function (method) {
      if (method !== String(baseExchange.method).toUpperCase()) values.push({ name: "method:" + method.toLowerCase(), method: method });
    });
    values.push({ name: "header:method-override-get", method: baseExchange.method, headers: [{ name: "X-HTTP-Method-Override", value: "GET" }] });
    if (input.allow_state_changes === true) {
      ["POST", "PUT", "PATCH"].forEach(function (method) {
        if (method !== String(baseExchange.method).toUpperCase()) values.push({ name: "unsafe-method:" + method.toLowerCase(), method: method });
      });
    }
    return values.slice(0, Math.max(1, Math.min(Number(input.max_variants || 50), 100)));
  }

  function plan(input, context) {
    var baseExchange = base(context), safe = ["GET", "HEAD", "OPTIONS"];
    if (safe.indexOf(String(baseExchange.method).toUpperCase()) === -1 && input.allow_state_changes !== true) {
      throw new Error("replaying this state-changing request requires allow_state_changes=true");
    }
    var operations = [0, 1].map(function (repeat) {
      return { id: "baseline-" + repeat, type: "http_request", base_exchange_id: baseExchange.exchange_id, method: baseExchange.method, protocol: "auto" };
    });
    variants(baseExchange, input).forEach(function (variant, index) {
      for (var repeat = 0; repeat < 2; repeat += 1) {
        var op = {
          id: "variant-" + index + "-" + repeat,
          type: "http_request",
          base_exchange_id: baseExchange.exchange_id,
          method: variant.method,
          protocol: "auto"
        };
        if (variant.url) op.url = variant.url;
        if (variant.headers) op.headers = variant.headers;
        operations.push(op);
      }
    });
    return { operations: operations, result: { variants: variants(baseExchange, input).map(function (item) { return item.name; }) } };
  }

  function mapById(observations) {
    var output = {};
    observations.forEach(function (item) { output[item.id] = item; });
    return output;
  }

  function sameResponse(a, b) {
    if (!a || !b || a.status_code !== b.status_code) return false;
    if (a.response_body_hash && b.response_body_hash) return a.response_body_hash === b.response_body_hash;
    return a.response_length === b.response_length;
  }

  function allowed(status) { return status >= 200 && status < 300; }

  function analyze(input, observations, context) {
    var baseExchange = base(context), map = mapById(observations), firstBase = map["baseline-0"], secondBase = map["baseline-1"];
    if (!firstBase || !secondBase) return { findings: [], result: { error: "baseline observations missing" } };
    var denied = firstBase.status_code === 401 || firstBase.status_code === 403 || (input.include_not_found === true && firstBase.status_code === 404);
    if (!denied) return { findings: [], result: { skipped: "base request was not an eligible denied response", status_code: firstBase.status_code } };
    var baselineStable = sameResponse(firstBase, secondBase), findings = [];
    variants(baseExchange, input).forEach(function (variant, index) {
      var first = map["variant-" + index + "-0"], repeat = map["variant-" + index + "-1"];
      if (first && repeat && allowed(first.status_code) && sameResponse(first, repeat)) {
        findings.push({
          title: "Access-control bypass using " + variant.name,
          severity: firstBase.status_code === 404 ? "medium" : "high",
          confidence: baselineStable ? "firm" : "tentative",
          explanation: "A denied control became an allowed response and the result was reproduced.",
          remediation: "Normalize paths and forwarding headers before authorization, and enforce access control after routing.",
          evidence_exchange_ids: [firstBase.exchange_id, secondBase.exchange_id, first.exchange_id, repeat.exchange_id].filter(Boolean),
          metadata: { variant: variant.name, baseline_status: firstBase.status_code, bypass_status: first.status_code }
        });
      }
    });
    return { findings: findings, result: { baseline_status: firstBase.status_code, baseline_stable: baselineStable, tested_variants: variants(baseExchange, input).length } };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
