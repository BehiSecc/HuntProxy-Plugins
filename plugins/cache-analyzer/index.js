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

  function addCloakedQuery(url, carrier, sharedValue, delimiter, target, markerValue) {
    return url + (url.indexOf("?") === -1 ? "?" : "&") + encodeURIComponent(carrier) + "=" + encodeURIComponent(sharedValue) + delimiter + encodeURIComponent(target) + "=" + encodeURIComponent(markerValue);
  }

  function encodeBase64(value) {
    var bytes = unescape(encodeURIComponent(String(value))), output = "", alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (var index = 0; index < bytes.length; index += 3) {
      var a = bytes.charCodeAt(index), b = index + 1 < bytes.length ? bytes.charCodeAt(index + 1) : 0, c = index + 2 < bytes.length ? bytes.charCodeAt(index + 2) : 0;
      output += alphabet[a >> 2] + alphabet[((a & 3) << 4) | (b >> 4)] + (index + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : "=") + (index + 2 < bytes.length ? alphabet[c & 63] : "=");
    }
    return output;
  }

  function rawRequest(id, baseUrl, path) {
    var parsed = splitUrl(baseUrl), authority = parsed.origin.replace(/^https?:\/\//, "");
    return {
      id: id, type: "raw_http1", target_url: parsed.origin + "/",
      request_base64: encodeBase64("GET " + path + " HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\n\r\n"),
      use_project_cookies: false,
      options: { response_mode: "until_idle", read_timeout_ms: 8000, idle_timeout_ms: 1000, half_close_write: false }
    };
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

  function familyEnabled(input, name) {
    return !input.oracle_families || !input.oracle_families.length || input.oracle_families.indexOf(name) !== -1;
  }

  function poisonVariants(baseUrl, token, input, context) {
    var variants = [], combinationVariants = [], shapeVariants = [], seen = {}, headerLimit = Math.max(1, Math.min(Number(input.max_header_candidates || 300), 500));
    var unsafe = { "content-length": 1, "transfer-encoding": 1, "connection": 1, "proxy-connection": 1, "cookie": 1, "set-cookie": 1 };
    var special = {
      "x-forwarded-scheme": "http", "x-forwarded-proto": "http", "x-forwarded-protocol": "http",
      "x-url-scheme": "http", "front-end-https": "off", "x-forwarded-ssl": "off",
      "x-http-method-override": "HEAD", "x-method-override": "HEAD", "x-http-method": "HEAD",
      "authorization": "HuntProxy " + token
    };
    function addHeader(value) {
      var pieces = String(value || "").trim().split("~"), name = pieces[0], key = name.toLowerCase();
      if (!name || unsafe[key] || seen[key] || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || variants.length >= headerLimit) return;
      seen[key] = true;
      var index = variants.length, markerValue = token + "h" + index;
      var headerValue = special[key] || pieces.slice(1).join("~") || markerValue + ".invalid";
      headerValue = headerValue.replace(/%s/g, markerValue).replace(/%h/g, "invalid");
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":" + key));
      variants.push({ name: "header:" + key, poison_url: clean, clean_url: clean, headers: [{ name: name, value: headerValue }], marker: markerValue });
    }
    function combinationHeader(value, markerValue) {
      var pieces = String(value || "").trim().split("~"), name = pieces[0], key = name.toLowerCase();
      if (!name || unsafe[key] || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) return null;
      var headerValue = special[key] || pieces.slice(1).join("~") || markerValue + ".invalid";
      return { name: name, value: headerValue.replace(/%s/g, markerValue).replace(/%h/g, "invalid") };
    }
    (familyEnabled(input, "headers") ? [
      "X-Forwarded-Host", "X-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Scheme",
      "X-Forwarded-Proto", "X-Forwarded-Port", "Forwarded", "X-HTTP-Method-Override", "X-Method-Override",
      "X-Original-Host", "X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Original-Uri", "X-Forwarded-Server",
      "X-Real-IP", "X-Forwarded-For", "True-Client-IP", "Client-IP", "Fastly-Host", "X-Cache-Key",
      "X-ProxyUser-IP", "X-Original-User-Agent", "X-Request-URI", "X-Accel-Redirect", "Authorization"
    ] : []).forEach(addHeader);
    if (familyEnabled(input, "headers")) (input.headers || []).forEach(addHeader);
    if (familyEnabled(input, "headers") && input.use_header_wordlist !== false && context.resources && typeof context.resources.headers === "string") context.resources.headers.split(/\r?\n/).forEach(addHeader);
    var combinations = input.header_combinations || [["X-Forwarded-Host~%s.invalid", "X-Forwarded-Scheme~http"]];
    (familyEnabled(input, "header-combinations") ? combinations : []).slice(0, Math.max(0, Math.min(Number(input.max_header_combinations == null ? 12 : input.max_header_combinations), 20))).forEach(function (combination, index) {
      var markerValue = token + "m" + index, headers = [], names = {}, valid = true;
      (combination || []).slice(0, 4).forEach(function (value) {
        var header = combinationHeader(value, markerValue), key = header && header.name.toLowerCase();
        if (!header || names[key]) { valid = false; return; }
        names[key] = true; headers.push(header);
      });
      if (!valid || headers.length < 2) return;
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":combination:" + index));
      combinationVariants.push({ name: "headers:" + headers.map(function (header) { return header.name.toLowerCase(); }).join("+"), poison_url: clean, clean_url: clean, headers: headers, marker: markerValue });
    });
    var cookieNames = [], cookieSeen = {}, cookieVariants = [];
    function addCookieName(value) {
      var name = String(value || "").trim(), key = name.toLowerCase();
      if (!name || cookieSeen[key] || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) return;
      if (/^(?:session|sessionid|sid|auth|authorization|token|jwt|csrf|xsrf|access[-_]?token|refresh[-_]?token)$/i.test(name) && input.allow_sensitive_cookie_mutation !== true) {
        throw new Error("sensitive cookie candidate " + name + " requires allow_sensitive_cookie_mutation=true");
      }
      cookieSeen[key] = true; cookieNames.push(name);
    }
    if (familyEnabled(input, "cookies")) (input.cookie_names || []).forEach(addCookieName);
    if (familyEnabled(input, "cookies") && input.use_cookie_wordlist === true && context.resources && typeof context.resources.cookies === "string") {
      context.resources.cookies.split(/\r?\n/).forEach(addCookieName);
    }
    cookieNames.slice(0, Math.max(1, Math.min(Number(input.max_cookie_candidates || 40), 100))).forEach(function (name) {
      var index = cookieVariants.length, markerValue = token + "c" + index;
      var cleanValue = "hpclean" + cacheBuster(token + ":cookie:" + name);
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":cookie-key:" + name));
      cookieVariants.push({
        name: "cookie:" + name.toLowerCase(), poison_url: clean, clean_url: clean, headers: [],
        poison_cookies: [{ name: name, value: markerValue }],
        clean_cookies: [{ name: name, value: cleanValue }], marker: markerValue
      });
    });
    (familyEnabled(input, "query-parameters") ? ["utm_source", "utm_content", "ref", "callback"] : []).forEach(function (name) {
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":query:" + name));
      variants.push({ name: "query:" + name, poison_url: addQuery(clean, name, token), clean_url: clean, headers: [], marker: token });
    });
    if (familyEnabled(input, "full-query") && input.full_query_oracle === true) {
      if (input.allow_shared_cache_key_tests !== true) throw new Error("full-query testing requires allow_shared_cache_key_tests=true");
      var parsed = splitUrl(baseUrl), shared = parsed.origin + parsed.path, fullMarker = token + "q0";
      shapeVariants.push({ name: "full-query", poison_url: shared + "?" + encodeURIComponent(fullMarker), clean_url: shared, headers: [], marker: fullMarker });
    }
    (familyEnabled(input, "parameter-cloaking") ? (input.parameter_cloaking || []) : []).slice(0, 20).forEach(function (entry, index) {
      var carrier = String(entry.carrier), target = String(entry.target), delimiter = String(entry.delimiter || ";"), markerValue = token + "p" + index;
      var sharedValue = token + "k" + index, clean = addQuery(baseUrl, carrier, sharedValue);
      shapeVariants.push({ name: "cloaking:" + carrier.toLowerCase() + delimiter + target.toLowerCase(), poison_url: addCloakedQuery(baseUrl, carrier, sharedValue, delimiter, target, markerValue), clean_url: clean, headers: [], marker: markerValue });
    });
    (familyEnabled(input, "fat-get") ? (input.fat_get_parameters || []) : []).slice(0, 20).forEach(function (name, index) {
      var markerValue = token + "f" + index, cleanValue = "hpclean" + cacheBuster(token + ":fat:" + name);
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":fat-key:" + name));
      shapeVariants.push({
        name: "fat-get:" + String(name).toLowerCase(), poison_url: clean, clean_url: clean,
        headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
        clean_headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
        poison_body_base64: encodeBase64(encodeURIComponent(String(name)) + "=" + encodeURIComponent(markerValue)),
        clean_body_base64: encodeBase64(encodeURIComponent(String(name)) + "=" + encodeURIComponent(cleanValue)), marker: markerValue
      });
    });
    return cookieVariants.concat(shapeVariants, combinationVariants, variants);
  }

  function deceptionVariants(baseUrl, token, input) {
    var parsed = splitUrl(baseUrl), path = parsed.path.replace(/\/$/, "");
    var extensions = input.static_extensions && input.static_extensions.length ? input.static_extensions : ["js", "css", "ico"];
    var delimiters = input.path_delimiters && input.path_delimiters.length ? input.path_delimiters : ["/", ";", "%3b", "%2f", "%3f", "%23", "%00", "%09"];
    var variants = [];
    extensions.slice(0, 10).forEach(function (extension) {
      delimiters.slice(0, 32).forEach(function (delimiter) {
        variants.push({ name: "delimiter:" + delimiter + ":" + extension, url: parsed.origin + path + delimiter + token + "." + extension + parsed.query });
      });
    });
    var dynamicPath = path.replace(/^\//, ""), staticDirectories = input.static_directories && input.static_directories.length ? input.static_directories : ["resources", "assets", "static"];
    staticDirectories.slice(0, 10).forEach(function (directory) {
      variants.push({ name: "origin-normalization:" + directory, url: parsed.origin + "/" + directory + "/..%2f" + dynamicPath + parsed.query });
      (input.normalization_delimiters && input.normalization_delimiters.length ? input.normalization_delimiters : ["%23", "%3f", ";"]).slice(0, 8).forEach(function (delimiter) {
        variants.push({ name: "cache-normalization:" + delimiter + ":" + directory, url: parsed.origin + path + delimiter + "%2f%2e%2e%2f" + directory + parsed.query });
      });
    });
    (input.exact_cache_files && input.exact_cache_files.length ? input.exact_cache_files : ["robots.txt", "favicon.ico", "index.html"]).slice(0, 10).forEach(function (file) {
      (input.normalization_delimiters && input.normalization_delimiters.length ? input.normalization_delimiters : ["%23", "%3f", ";"]).slice(0, 8).forEach(function (delimiter) {
        variants.push({ name: "exact-normalization:" + delimiter + ":" + file, url: parsed.origin + path + delimiter + "%2f%2e%2e%2f" + file + parsed.query });
      });
    });
    return variants.slice(0, Math.max(1, Math.min(Number(input.max_deception_variants || 40), 100)));
  }

  function request(id, exchange, method, url, headers, anonymous, cookieParams) {
    var op = { id: id, type: "http_request", base_exchange_id: exchange, method: method, url: url, protocol: "auto" };
    if (headers && headers.length) op.headers = headers;
    if (cookieParams && cookieParams.length) op.cookie_params = cookieParams;
    if (anonymous) op.header_tombstones = ["Cookie", "Authorization", "Proxy-Authorization"];
    return op;
  }

  function plan(input, context) {
    if (input.allow_cache_side_effects !== true) throw new Error("cache testing requires allow_cache_side_effects=true");
    var exchange = base(context), token = marker(input), operations = [], controlUrl = exchange.url;
    var isolatedShapeControls = (familyEnabled(input, "full-query") && input.full_query_oracle === true) ||
      (familyEnabled(input, "parameter-cloaking") && input.parameter_cloaking && input.parameter_cloaking.length) ||
      (familyEnabled(input, "fat-get") && input.fat_get_parameters && input.fat_get_parameters.length);
    if (isolatedShapeControls) {
      var controlParsed = splitUrl(exchange.url), controlPath = controlParsed.path.replace(/\/$/, "");
      controlUrl = controlParsed.origin + controlPath + "/.huntproxy-control-" + cacheBuster(token);
    }
    operations.push(request("baseline-auth", exchange.exchange_id, exchange.method, addQuery(controlUrl, "hp_cache_bust", cacheBuster(token + ":control")), [], false));
    operations.push(request("baseline-anon", exchange.exchange_id, exchange.method, addQuery(controlUrl, "hp_cache_bust", cacheBuster(token + ":control")), [], true));
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    if (modes.indexOf("poisoning") !== -1) {
      poisonVariants(exchange.url, token, input, context).slice(0, Math.max(1, Math.min(Number(input.max_poison_variants || 304), 504))).forEach(function (variant, index) {
        var poison = request("poison-" + index, exchange.exchange_id, exchange.method, variant.poison_url, variant.headers, false, variant.poison_cookies);
        var clean = request("poison-clean-" + index, exchange.exchange_id, exchange.method, variant.clean_url, variant.clean_headers || [], false, variant.clean_cookies);
        var confirm = request("poison-confirm-" + index, exchange.exchange_id, exchange.method, variant.clean_url, variant.clean_headers || [], false, variant.clean_cookies);
        if (variant.poison_body_base64 != null) poison.body_base64 = variant.poison_body_base64;
        if (variant.clean_body_base64 != null) { clean.body_base64 = variant.clean_body_base64; confirm.body_base64 = variant.clean_body_base64; }
        operations.push(poison); operations.push(clean); operations.push(confirm);
      });
      if (familyEnabled(input, "url-normalization") && input.url_normalization_oracle === true) {
        if (input.allow_shared_cache_key_tests !== true) throw new Error("URL-normalization testing requires allow_shared_cache_key_tests=true");
        for (var normalizationRepeat = 0; normalizationRepeat < 2; normalizationRepeat += 1) {
          var suffix = token + "n" + normalizationRepeat;
          operations.push(rawRequest("normalization-poison-" + normalizationRepeat, exchange.url, "/hp<" + suffix + ">"));
          operations.push(rawRequest("normalization-clean-" + normalizationRepeat, exchange.url, "/hp%3C" + suffix + "%3E"));
          operations.push(rawRequest("normalization-confirm-" + normalizationRepeat, exchange.url, "/hp%3C" + suffix + "%3E"));
        }
      }
    }
    if (modes.indexOf("deception") !== -1) {
      deceptionVariants(exchange.url, token, input).forEach(function (variant, index) {
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

  function comparisonText(observation) {
    var ignored = {
      "age": 1, "x-cache": 1, "cf-cache-status": 1, "x-cache-hits": 1, "cache-status": 1,
      "date": 1, "etag": 1, "last-modified": 1, "server-timing": 1, "via": 1,
      "cf-ray": 1, "request-id": 1, "x-request-id": 1, "set-cookie": 1
    };
    var text = preview(observation);
    (observation && observation.response_headers || []).forEach(function (header) {
      var name = String(header.name || "").toLowerCase();
      if (!ignored[name]) text += "\n" + name + ":" + decodeBase64(header.value_base64).toLowerCase();
    });
    return text;
  }

  function normalizeText(value) {
    return String(value || "").toLowerCase()
      .replace(/([?&]hp_(?:cache_bust|control)=)[^&\"'<> ]+/g, "$1<cachebuster>")
      .replace(/(<input\b[^>]*\bname=["']?(?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token)["']?[^>]*\bvalue=)["'][^"']*["']/gi, "$1\"<volatile>\"")
      .replace(/\s+/g, " ").trim();
  }

  function same(a, b) {
    if (!a || !b || a.status_code !== b.status_code) return false;
    return normalizeText(comparisonText(a)) === normalizeText(comparisonText(b));
  }

  function cacheEvidence(observation) {
    var names = {};
    (observation && observation.response_headers || []).forEach(function (header) { names[String(header.name).toLowerCase()] = true; });
    return names.age || names["x-cache"] || names["cf-cache-status"] || names["x-cache-hits"] || names["cache-status"];
  }

  function rawBody(observation) {
    var raw = observation && observation.raw, encoded = raw && (raw.response_transcript_base64 || raw.response_base64);
    if (!encoded) return "";
    var transcript = decodeBase64(encoded), response = raw.responses && raw.responses[0];
    if (response && response.length) transcript = transcript.slice(response.offset || 0, (response.offset || 0) + response.length);
    var boundary = transcript.indexOf("\r\n\r\n");
    return normalizeText(boundary === -1 ? transcript : transcript.slice(boundary + 4));
  }

  function rawEvidenceId(observation) { return observation && observation.raw && observation.raw.exchange_id; }

  function analyze(input, observations, context) {
    var exchange = base(context), token = marker(input), map = byId(observations), findings = [];
    var authBase = map["baseline-auth"], anonBase = map["baseline-anon"];
    var baseLooksPrivate = authBase && anonBase && !same(authBase, anonBase);
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    if (modes.indexOf("poisoning") !== -1) {
      poisonVariants(exchange.url, token, input, context).slice(0, Math.max(1, Math.min(Number(input.max_poison_variants || 304), 504))).forEach(function (variant, index) {
        var poison = map["poison-" + index], clean = map["poison-clean-" + index], confirm = map["poison-confirm-" + index];
        var expectedMarker = String(variant.marker || token).toLowerCase();
        var persistedMarker = evidenceText(clean).indexOf(expectedMarker) !== -1 && evidenceText(confirm).indexOf(expectedMarker) !== -1;
        var mutationComparable = /^(?:header:|headers:|query:)/.test(variant.name);
        var persistedMutation = mutationComparable && poison && clean && confirm && same(poison, clean) && same(clean, confirm) && authBase && !same(authBase, clean);
        if (poison && clean && confirm && same(clean, confirm) && (persistedMarker || persistedMutation)) {
          findings.push({
            title: "Web cache poisoning via " + variant.name,
            severity: "high",
            confidence: cacheEvidence(clean) || cacheEvidence(confirm) ? "firm" : "tentative",
            explanation: "A unique marker supplied only by the poisoning request persisted in two clean responses for the cache-busted URL.",
            remediation: "Include the input in the cache key or reject it, and prevent untrusted values from influencing cached responses.",
            evidence_exchange_ids: [poison.exchange_id, clean.exchange_id, confirm.exchange_id].filter(Boolean),
            metadata: { variant: variant.name, subtype: variant.name === "full-query" ? "full-query" : variant.name, marker: token }
          });
        }
      });
      if (familyEnabled(input, "url-normalization") && input.url_normalization_oracle === true) {
        var normalizationEvidence = [], normalizationConfirmed = true;
        for (var normalizationRepeat = 0; normalizationRepeat < 2; normalizationRepeat += 1) {
          var rawPoison = map["normalization-poison-" + normalizationRepeat], rawClean = map["normalization-clean-" + normalizationRepeat], rawConfirm = map["normalization-confirm-" + normalizationRepeat];
          var poisonBody = rawBody(rawPoison), cleanBody = rawBody(rawClean), confirmBody = rawBody(rawConfirm);
          if (!poisonBody || poisonBody !== cleanBody || cleanBody !== confirmBody || poisonBody.indexOf("<" + token + "n" + normalizationRepeat + ">") === -1) normalizationConfirmed = false;
          [rawPoison, rawClean, rawConfirm].forEach(function (item) { var id = rawEvidenceId(item); if (id) normalizationEvidence.push(id); });
        }
        if (normalizationConfirmed) findings.push({
          title: "Web cache poisoning via URL normalization", severity: "high", confidence: "firm",
          explanation: "Two unique raw paths containing harmless angle-bracket markers collided with their browser-encoded equivalents, and each encoded clean request reproduced the raw response twice.",
          remediation: "Canonicalize the request target once before cache-key construction and origin routing, and reject ambiguous raw paths.",
          evidence_exchange_ids: normalizationEvidence,
          metadata: { variant: "url-normalization", marker: token }
        });
      }
    }
    if (modes.indexOf("deception") !== -1 && baseLooksPrivate) {
      deceptionVariants(exchange.url, token, input).forEach(function (variant, index) {
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
