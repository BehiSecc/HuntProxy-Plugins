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

  function formQueryParams(context) {
    var identity = context.base_exchange && context.base_exchange.identity;
    if (!identity || !identity.request_body_base64) return [];
    var contentType = "";
    (identity.request_headers || []).forEach(function (header) {
      if (String(header.name).toLowerCase() === "content-type") contentType = atob64(header.value_base64).toLowerCase();
    });
    if (contentType.indexOf("application/x-www-form-urlencoded") === -1) return [];
    return atob64(identity.request_body_base64).split("&").filter(Boolean).map(function (part) {
      var at = part.indexOf("="), name = at < 0 ? part : part.slice(0, at), value = at < 0 ? "" : part.slice(at + 1);
      try { name = decodeURIComponent(name.replace(/\+/g, " ")); } catch (_) {}
      try { value = decodeURIComponent(value.replace(/\+/g, " ")); } catch (_) {}
      return { name: name, value: value };
    }).filter(function (part) { return part.name.length > 0; });
  }

  function variants(baseExchange, input, context) {
    var parsed = splitUrl(baseExchange.url), path = parsed.path, values = [];
    pathVariants(baseExchange.url).forEach(function (entry) {
      values.push({ name: "path:" + entry.name, url: entry.url, method: baseExchange.method });
    });
    [
      ["x-original-url", "X-Original-URL"],
      ["x-rewrite-url", "X-Rewrite-URL"],
      ["x-forwarded-uri", "X-Forwarded-Uri"],
      ["x-original-uri", "X-Original-Uri"]
    ].forEach(function (item) {
      var headers = [{ name: item[1], value: path }];
      values.push({ name: "header:" + item[0] + ":direct", method: baseExchange.method, headers: headers });
      values.push({ name: "header:" + item[0] + ":root-carrier", method: baseExchange.method, url: parsed.origin + "/" + parsed.query, headers: headers });
    });
    [
      ["x-forwarded-for", "X-Forwarded-For", "127.0.0.1"],
      ["x-real-ip", "X-Real-IP", "127.0.0.1"],
      ["client-ip", "Client-IP", "127.0.0.1"],
      ["true-client-ip", "True-Client-IP", "127.0.0.1"],
      ["forwarded", "Forwarded", "for=127.0.0.1;host=" + parsed.origin.replace(/^https?:\/\//, "")]
    ].forEach(function (item) {
      values.push({ name: "header:" + item[0], method: baseExchange.method, headers: [{ name: item[1], value: item[2] }] });
    });
    ["GET", "HEAD", "OPTIONS"].forEach(function (method) {
      if (method !== String(baseExchange.method).toUpperCase()) {
        var variant = { name: "method:" + method.toLowerCase(), method: method };
        if (method === "GET") {
          var query = formQueryParams(context);
          if (query.length) { variant.query_params = query; variant.body_base64 = ""; variant.header_tombstones = ["Content-Type", "Content-Length"]; }
        }
        values.push(variant);
      }
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
    var parsed = splitUrl(baseExchange.url);
    for (var carrierRepeat = 0; carrierRepeat < 2; carrierRepeat += 1) operations.push({ id: "carrier-root-" + carrierRepeat, type: "http_request", base_exchange_id: baseExchange.exchange_id, method: baseExchange.method, url: parsed.origin + "/" + parsed.query, protocol: "auto" });
    variants(baseExchange, input, context).forEach(function (variant, index) {
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
        if (variant.query_params) op.query_params = variant.query_params;
        if (variant.body_base64 != null) op.body_base64 = variant.body_base64;
        if (variant.header_tombstones) op.header_tombstones = variant.header_tombstones;
        operations.push(op);
      }
    });
    return { operations: operations, result: { variants: variants(baseExchange, input, context).map(function (item) { return item.name; }), form_body_moved_to_query_for_get: formQueryParams(context).length > 0 } };
  }

  function mapById(observations) {
    var output = {};
    observations.forEach(function (item) { output[item.id] = item; });
    return output;
  }

  function sameResponse(a, b) {
    if (!a || !b || a.error || b.error || a.status_code !== b.status_code) return false;
    if (a.response_body_hash && b.response_body_hash) return a.response_body_hash === b.response_body_hash;
    return a.response_length === b.response_length;
  }

  function allowed(status) { return status >= 200 && status < 300; }
  function body(item) { return String(item && item.response_body_base64 ? atob64(item.response_body_base64) : item && item.response_preview && item.response_preview.text || "").toLowerCase(); }
  function atob64(value) {
    var alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",output="",buffer=0,bits=0;
    String(value||"").replace(/=+$/,"").split("").forEach(function(character){var index=alphabet.indexOf(character);if(index<0)return;buffer=(buffer<<6)|index;bits+=6;if(bits>=8){bits-=8;output+=String.fromCharCode((buffer>>bits)&255);}});return output;
  }
  function markersMatch(item, input) {
    var text=body(item), success=input.success_markers||[], failure=input.failure_markers||[];
    return (!success.length || success.some(function(marker){return text.indexOf(String(marker).toLowerCase())!==-1;})) && !failure.some(function(marker){return text.indexOf(String(marker).toLowerCase())!==-1;});
  }

  function analyze(input, observations, context) {
    var baseExchange = base(context), map = mapById(observations), firstBase = map["baseline-0"], secondBase = map["baseline-1"];
    if (!firstBase || !secondBase) return { findings: [], result: { error: "baseline observations missing" } };
    var denied = firstBase.status_code === 401 || firstBase.status_code === 403 || (input.include_not_found === true && firstBase.status_code === 404);
    if (!denied) return { findings: [], result: { skipped: "base request was not an eligible denied response", status_code: firstBase.status_code } };
    var baselineStable = sameResponse(firstBase, secondBase), findings = [], errors = [], carrierFirst=map["carrier-root-0"], carrierRepeat=map["carrier-root-1"], carrierStable=sameResponse(carrierFirst,carrierRepeat);
    variants(baseExchange, input, context).forEach(function (variant, index) {
      var first = map["variant-" + index + "-0"], repeat = map["variant-" + index + "-1"];
      if (first && first.error) errors.push({ variant: variant.name, repeat: 0, error: first.error });
      if (repeat && repeat.error) errors.push({ variant: variant.name, repeat: 1, error: repeat.error });
      var rootCarrier=/:root-carrier$/.test(variant.name), pathOnly=/^path:/.test(variant.name);
      var distinctFromCarrier=!rootCarrier || (carrierStable && !sameResponse(first,carrierFirst) && !sameResponse(repeat,carrierRepeat));
      var markerProof=markersMatch(first,input) && markersMatch(repeat,input);
      var explicitSuccess=(input.success_markers||[]).length>0 && markerProof;
      if (first && repeat && (allowed(first.status_code) || explicitSuccess) && sameResponse(first, repeat) && distinctFromCarrier && markerProof) {
        var stronglyConfirmed=(input.success_markers||[]).length>0 || !pathOnly;
        findings.push({
          title: (stronglyConfirmed ? "Access-control bypass using " : "Potential access-control bypass using ") + variant.name,
          severity: stronglyConfirmed && firstBase.status_code !== 404 ? "high" : "medium",
          confidence: stronglyConfirmed && baselineStable ? "firm" : "tentative",
          explanation: rootCarrier ? "A denied control became a reproducible allowed response that differs from the ordinary benign carrier response." : pathOnly && !stronglyConfirmed ? "A path mutation became reproducibly allowed, but no success marker was supplied to prove it reached the protected resource." : "A denied control became an allowed response and the result was reproduced on the same protected path.",
          remediation: "Normalize paths and forwarding headers before authorization, and enforce access control after routing.",
          evidence_exchange_ids: [firstBase.exchange_id, secondBase.exchange_id, first.exchange_id, repeat.exchange_id].filter(Boolean),
          metadata: { variant: variant.name, baseline_status: firstBase.status_code, bypass_status: first.status_code }
        });
      }
    });
    return { findings: findings, result: { baseline_status: firstBase.status_code, baseline_stable: baselineStable, carrier_stable: carrierStable, tested_variants: variants(baseExchange, input, context).length, operation_errors: errors } };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
