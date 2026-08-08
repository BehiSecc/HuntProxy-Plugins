(function () {
  "use strict";

  function base(context) {
    if (!context.base_exchange || !context.base_exchange.exchange_id || !context.base_exchange.url) {
      throw new Error("CacheAnalyzer requires a saved base exchange");
    }
    return context.base_exchange;
  }

  function marker(input) {
    var value = String(input.marker || "");
    if (!/^[a-z0-9]{8,40}$/i.test(value)) throw new Error("marker must be a unique 8-40 character alphanumeric value");
    return "hp" + value.toLowerCase();
  }

  function addQuery(url, name, value) {
    return url + (url.indexOf("?") === -1 ? "?" : "&") + encodeURIComponent(name) + "=" + encodeURIComponent(value);
  }

  function cacheBuster(token) {
    var value = 2166136261;
    for (var index = 0; index < token.length; index += 1) {
      value ^= token.charCodeAt(index);
      value = Math.imul(value, 16777619);
    }
    return "cb" + (value >>> 0).toString(16);
  }

  function splitUrl(url) {
    var match = String(url).match(/^(https?:\/\/[^/?#]+)([^?#]*)(\?[^#]*)?$/);
    if (!match) throw new Error("base exchange URL is not HTTP(S)");
    return { origin: match[1], path: match[2] || "/", query: match[3] || "" };
  }

  function poisonVariants(baseUrl, token) {
    var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token));
    var variants = [
      { name: "header:x-forwarded-host", poison_url: clean, clean_url: clean, headers: [{ name: "X-Forwarded-Host", value: token + ".invalid" }] },
      { name: "header:x-host", poison_url: clean, clean_url: clean, headers: [{ name: "X-Host", value: token + ".invalid" }] },
      { name: "header:x-original-url", poison_url: clean, clean_url: clean, headers: [{ name: "X-Original-URL", value: "/" + token + ".js" }] },
      { name: "header:x-rewrite-url", poison_url: clean, clean_url: clean, headers: [{ name: "X-Rewrite-URL", value: "/" + token + ".js" }] }
    ];
    ["utm_source", "utm_content", "ref", "callback"].forEach(function (name) {
      variants.push({ name: "query:" + name, poison_url: addQuery(clean, name, token), clean_url: clean, headers: [] });
    });
    return variants;
  }

  function deceptionVariants(baseUrl, token) {
    var parsed = splitUrl(baseUrl), path = parsed.path.replace(/\/$/, "");
    return [
      { name: "suffix-css", url: parsed.origin + path + "/" + token + ".css" + parsed.query },
      { name: "path-parameter-css", url: parsed.origin + path + ";" + token + ".css" + parsed.query },
      { name: "encoded-slash-css", url: parsed.origin + path + "%2f" + token + ".css" + parsed.query },
      { name: "delimiter-css", url: parsed.origin + path + ".css" + parsed.query }
    ];
  }

  function request(id, exchange, method, url, headers, anonymous) {
    var op = { id: id, type: "http_request", base_exchange_id: exchange, method: method, url: url, protocol: "auto" };
    if (headers && headers.length) op.headers = headers;
    if (anonymous) op.header_tombstones = ["Cookie", "Authorization", "Proxy-Authorization"];
    return op;
  }

  function plan(input, context) {
    if (input.allow_cache_side_effects !== true) throw new Error("cache testing requires allow_cache_side_effects=true");
    var exchange = base(context), token = marker(input), operations = [];
    operations.push(request("baseline-auth", exchange.exchange_id, exchange.method, addQuery(exchange.url, "hp_control", token), [], false));
    operations.push(request("baseline-anon", exchange.exchange_id, exchange.method, addQuery(exchange.url, "hp_control", token), [], true));
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    if (modes.indexOf("poisoning") !== -1) {
      poisonVariants(exchange.url, token).slice(0, Math.max(1, Math.min(Number(input.max_poison_variants || 8), 8))).forEach(function (variant, index) {
        operations.push(request("poison-" + index, exchange.exchange_id, exchange.method, variant.poison_url, variant.headers, false));
        operations.push(request("poison-clean-" + index, exchange.exchange_id, exchange.method, variant.clean_url, [], false));
        operations.push(request("poison-confirm-" + index, exchange.exchange_id, exchange.method, variant.clean_url, [], false));
      });
    }
    if (modes.indexOf("deception") !== -1) {
      deceptionVariants(exchange.url, token).forEach(function (variant, index) {
        operations.push(request("deception-auth-" + index, exchange.exchange_id, exchange.method, variant.url, [], false));
        operations.push(request("deception-anon-" + index, exchange.exchange_id, exchange.method, variant.url, [], true));
        operations.push(request("deception-confirm-" + index, exchange.exchange_id, exchange.method, variant.url, [], true));
      });
    }
    return { operations: operations, result: { marker: token, operation_count: operations.length, sequential_execution_required: true } };
  }

  function byId(observations) {
    var output = {};
    observations.forEach(function (item) { output[item.id] = item; });
    return output;
  }

  function preview(observation) {
    return String(observation && observation.response_preview && observation.response_preview.text || "").toLowerCase();
  }

  function decodeBase64(value) {
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", output = "", buffer = 0, bits = 0;
    String(value || "").replace(/=+$/, "").split("").forEach(function (character) {
      var index = alphabet.indexOf(character);
      if (index < 0) return;
      buffer = (buffer << 6) | index; bits += 6;
      if (bits >= 8) { bits -= 8; output += String.fromCharCode((buffer >> bits) & 255); }
    });
    return output;
  }

  function evidenceText(observation) {
    var text = preview(observation);
    (observation && observation.response_headers || []).forEach(function (header) {
      text += "\n" + String(header.name || "").toLowerCase() + ":" + decodeBase64(header.value_base64).toLowerCase();
    });
    return text;
  }

  function same(a, b) {
    if (!a || !b || a.status_code !== b.status_code) return false;
    if (a.response_body_hash && b.response_body_hash) return a.response_body_hash === b.response_body_hash;
    return a.response_length === b.response_length && preview(a) === preview(b);
  }

  function cacheEvidence(observation) {
    var names = {};
    (observation && observation.response_headers || []).forEach(function (header) { names[String(header.name).toLowerCase()] = true; });
    return names.age || names["x-cache"] || names["cf-cache-status"] || names["x-cache-hits"] || names["cache-status"];
  }

  function analyze(input, observations, context) {
    var exchange = base(context), token = marker(input), map = byId(observations), findings = [];
    var authBase = map["baseline-auth"], anonBase = map["baseline-anon"];
    var baseLooksPrivate = authBase && anonBase && !same(authBase, anonBase);
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    if (modes.indexOf("poisoning") !== -1) {
      poisonVariants(exchange.url, token).slice(0, Math.max(1, Math.min(Number(input.max_poison_variants || 8), 8))).forEach(function (variant, index) {
        var poison = map["poison-" + index], clean = map["poison-clean-" + index], confirm = map["poison-confirm-" + index];
        var persistedMarker = evidenceText(clean).indexOf(token) !== -1 && evidenceText(confirm).indexOf(token) !== -1;
        if (poison && clean && confirm && same(clean, confirm) && persistedMarker) {
          findings.push({
            title: "Web cache poisoning via " + variant.name,
            severity: "high",
            confidence: cacheEvidence(clean) || cacheEvidence(confirm) ? "firm" : "tentative",
            explanation: "A unique marker supplied only by the poisoning request persisted in two clean responses for the cache-busted URL.",
            remediation: "Include the input in the cache key or reject it, and prevent untrusted values from influencing cached responses.",
            evidence_exchange_ids: [poison.exchange_id, clean.exchange_id, confirm.exchange_id].filter(Boolean),
            metadata: { variant: variant.name, marker: token }
          });
        }
      });
    }
    if (modes.indexOf("deception") !== -1 && baseLooksPrivate) {
      deceptionVariants(exchange.url, token).forEach(function (variant, index) {
        var authenticated = map["deception-auth-" + index], anonymous = map["deception-anon-" + index], confirm = map["deception-confirm-" + index];
        if (authenticated && anonymous && confirm && authenticated.status_code >= 200 && authenticated.status_code < 300 && same(authenticated, anonymous) && same(anonymous, confirm)) {
          findings.push({
            title: "Web cache deception via " + variant.name,
            severity: "high",
            confidence: cacheEvidence(anonymous) || cacheEvidence(confirm) ? "firm" : "tentative",
            explanation: "A response that differs between authenticated and anonymous controls was reproduced anonymously at a cacheable-looking path.",
            remediation: "Do not cache personalized responses; normalize path ambiguities before cache rules and application routing.",
            evidence_exchange_ids: [authBase.exchange_id, anonBase.exchange_id, authenticated.exchange_id, anonymous.exchange_id, confirm.exchange_id].filter(Boolean),
            metadata: { variant: variant.name }
          });
        }
      });
    }
    return { findings: findings, result: { marker: token, base_appears_private: !!baseLooksPrivate, tested_operations: observations.length } };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
