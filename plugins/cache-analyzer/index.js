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
    value = value.toLowerCase();
    return value.indexOf("hp") === 0 ? value : "hp" + value;
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

  function normalizePath(path) {
    var output = [];
    String(path || "/").split("/").forEach(function (part) {
      if (!part || part === ".") return;
      if (part === "..") { output.pop(); return; }
      output.push(part);
    });
    return "/" + output.join("/");
  }

  function sameOriginUrl(baseUrl, candidate) {
    var base = splitUrl(baseUrl), value = String(candidate || "").trim();
    if (!value || /[\s<>"']/.test(value) || /^(?:data|javascript|mailto):/i.test(value)) return null;
    value = value.split("#")[0];
    if (!value) return null;
    if (value.indexOf("//") === 0) value = base.origin.split(":")[0] + ":" + value;
    if (/^https?:\/\//i.test(value)) {
      var absolute;
      try { absolute = splitUrl(value); } catch (_) { return null; }
      if (absolute.origin.toLowerCase() !== base.origin.toLowerCase()) return null;
      return absolute.origin + normalizePath(absolute.path) + absolute.query;
    }
    if (value[0] === "/") {
      var direct = value.match(/^([^?]*)(\?.*)?$/); return base.origin + normalizePath(direct[1]) + (direct[2] || "");
    }
    var relative = value.match(/^([^?]*)(\?.*)?$/), directory = base.path.replace(/[^/]*$/, "");
    return base.origin + normalizePath(directory + relative[1]) + (relative[2] || "");
  }

  function discoveryTargets(input, context) {
    var exchange = base(context), baseUrl = scanUrl(input, exchange), maximum = boundedInteger(input.max_discovery_targets, 12, 1, 30);
    var discovery = exchange.page_discovery || {}, values = [], seen = {}, candidates = [];
    (discovery.targets || []).forEach(function (value) {
      var resolved = sameOriginUrl(baseUrl, value), key = resolved;
      if (!resolved || key === baseUrl || seen[key]) return;
      seen[key] = true; candidates.push(resolved);
    });
    candidates.sort(function (left, right) {
      function score(value) { return /\.js(?:[?#]|$)/i.test(value) ? 0 : /\.(?:css|json)(?:[?#]|$)/i.test(value) ? 1 : 2; }
      return score(left) - score(right) || left.localeCompare(right);
    });
    values.push(baseUrl);
    candidates.slice(0, maximum).forEach(function (value) { values.push(value); });
    return values;
  }

  function scanUrl(input, exchange) {
    if (!input.target_url) return exchange.url;
    var target = splitUrl(String(input.target_url)), original = splitUrl(exchange.url);
    if (target.origin.toLowerCase() !== original.origin.toLowerCase()) throw new Error("target_url must use the base exchange origin");
    return target.origin + target.path + target.query;
  }

  function familyEnabled(input, name) {
    return !input.oracle_families || !input.oracle_families.length || input.oracle_families.indexOf(name) !== -1;
  }

  var LIGHT_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Scheme",
    "Forwarded", "X-Original-URL", "X-Rewrite-URL", "X-Original-Host", "X-Forwarded-Port",
    "X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Original-Uri", "X-HTTP-Method-Override"
  ];

  var DEFAULT_PARAMETERS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "ref", "callback", "cb",
    "url", "redirect", "return", "next", "lang", "language", "country", "currency", "debug", "preview",
    "theme", "format", "output", "download", "file", "path", "page", "id", "q", "search", "sort", "filter"
  ];

  function uniqueLines(values, maximum, validator) {
    var output = [], seen = {};
    function add(value) {
      value = String(value || "").trim();
      var key = value.toLowerCase();
      if (!value || seen[key] || (validator && !validator(value)) || output.length >= maximum) return;
      seen[key] = true; output.push(value);
    }
    (values || []).forEach(add);
    return output;
  }

  function derivedNumber(value, minimum, span) {
    var hash = parseInt(cacheBuster(String(value)).slice(2), 16);
    return minimum + ((Number.isFinite(hash) ? hash : 0) % span);
  }

  function typedHeaderValue(name, supplied, markerValue) {
    var key = String(name).toLowerCase(), value, evidence;
    if (supplied) {
      value = String(supplied).replace(/%s/g, markerValue).replace(/%h/g, markerValue + ".invalid");
      evidence = value.indexOf(markerValue) !== -1 ? markerValue : null;
      return { value: value, marker: evidence };
    }
    if (key === "forwarded") {
      value = "for=\"[2001:db8::" + derivedNumber(markerValue, 1, 65534).toString(16) + "]\";host=\"" + markerValue + ".invalid\";proto=http";
      return { value: value, marker: markerValue };
    }
    if (/(?:forwarded-for|real-ip|client-ip|remote-addr|remote-ip|source-ip|connecting-ip|proxyuser-ip|cluster-client-ip)$/.test(key)) {
      value = "2001:db8::" + derivedNumber(markerValue, 1, 65534).toString(16);
      return { value: value, marker: value };
    }
    if (/(?:scheme|proto|protocol|front-end-https|forwarded-ssl)$/.test(key)) return { value: "http", marker: null, redirect_oracle: "http_scheme" };
    if (/(?:method|method-override)$/.test(key)) return { value: "HEAD", marker: null };
    if (/(?:port)$/.test(key)) {
      value = String(derivedNumber(markerValue, 20000, 40000)); return { value: value, marker: value };
    }
    if (/(?:url|uri|path|prefix|redirect|rewrite)$/.test(key)) return { value: "/" + markerValue, marker: markerValue };
    if (/(?:host|hostname|origin|server|domain|authority)$/.test(key)) return { value: markerValue + ".invalid", marker: markerValue };
    if (/(?:authorization|token|api-key|apikey|secret)$/.test(key)) return { value: "HuntProxy " + markerValue, marker: markerValue };
    return { value: markerValue, marker: markerValue };
  }

  function headerCandidates(input, context, token) {
    var mode = input.scan_mode === "light" ? "light" : "full";
    var maximum = boundedInteger(input.max_header_candidates, mode === "light" ? 40 : 5000, 1, 5000);
    var raw = [], seen = {}, output = [];
    (input.headers || []).forEach(function (value) { raw.push(value); });
    if (input.use_only_supplied_headers !== true) LIGHT_HEADERS.forEach(function (value) { raw.push(value); });
    if (mode === "full" && input.use_only_supplied_headers !== true && input.use_header_wordlist !== false && context.resources && typeof context.resources.headers === "string") {
      context.resources.headers.split(/\r?\n/).forEach(function (value) { raw.push(value); });
    }
    raw.some(function (entry) {
      var pieces = String(entry || "").trim().split("~"), name = pieces.shift(), key = String(name || "").toLowerCase();
      var unsafe = { "content-length": 1, "transfer-encoding": 1, "connection": 1, "proxy-connection": 1, "cookie": 1, "set-cookie": 1, "host": 1 };
      if (!name || unsafe[key] || seen[key] || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) return false;
      seen[key] = true;
      var markerValue = token + "h" + output.length.toString(36), typed = typedHeaderValue(name, pieces.join("~"), markerValue);
      output.push({ raw: String(entry), name: name, key: key, value: typed.value, marker: typed.marker, redirect_oracle: typed.redirect_oracle || null });
      return output.length >= maximum;
    });
    return output;
  }

  function parameterCandidates(input, context) {
    var values = [];
    (input.parameter_names || []).forEach(function (value) { values.push(value); });
    if (input.use_parameter_wordlist !== false) {
      DEFAULT_PARAMETERS.forEach(function (value) { values.push(value); });
      if (context.resources && typeof context.resources.parameters === "string") context.resources.parameters.split(/\r?\n/).forEach(function (value) { values.push(value); });
    }
    return uniqueLines(values, boundedInteger(input.max_parameter_candidates, 1000, 1, 1000), function (value) { return /^[A-Za-z0-9_.-]{1,80}$/.test(value); });
  }

  function queryParameterNames(url) {
    var query = splitUrl(url).query.replace(/^\?/, ""), output = [];
    query.split("&").forEach(function (part) {
      if (!part) return;
      var name = part.split("=")[0];
      try { name = decodeURIComponent(name); } catch (_) { return; }
      if (/^[A-Za-z0-9_.-]{1,80}$/.test(name)) output.push(name);
    });
    return output;
  }

  function automaticCloaking(input, targetUrl, confirmedParameters) {
    var carriers = uniqueLines(confirmedParameters || [], 8, function (value) { return /^[A-Za-z0-9_.-]{1,80}$/.test(value); });
    var targets = uniqueLines(queryParameterNames(targetUrl).concat(DEFAULT_PARAMETERS, input.parameter_names || []), 12, function (value) { return /^[A-Za-z0-9_.-]{1,80}$/.test(value); });
    var output = [];
    carriers.forEach(function (carrier) {
      targets.forEach(function (target) {
        if (target.toLowerCase() === carrier.toLowerCase()) return;
        [";", "%3b"].forEach(function (delimiter) { output.push({ carrier: carrier, target: target, delimiter: delimiter }); });
      });
    });
    return output;
  }

  function poisonVariants(baseUrl, token, input, context, includeHeaders) {
    var variants = [], combinationVariants = [], shapeVariants = [];
    var unsafe = { "content-length": 1, "transfer-encoding": 1, "connection": 1, "proxy-connection": 1, "cookie": 1, "set-cookie": 1 };
    function combinationHeader(value, markerValue) {
      var pieces = String(value || "").trim().split("~"), name = pieces[0], key = name.toLowerCase();
      if (!name || unsafe[key] || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) return null;
      var typed = typedHeaderValue(name, pieces.slice(1).join("~"), markerValue);
      return { name: name, value: typed.value, marker: typed.marker };
    }
    if (includeHeaders && familyEnabled(input, "headers")) headerCandidates(input, context, token).forEach(function (candidate) {
      var shared = input.shared_header_cache_key_oracle === true, trials = candidate.redirect_oracle && !shared ? 2 : 1;
      for (var trial = 0; trial < trials; trial += 1) {
        var clean = shared ? baseUrl : addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":" + candidate.key + ":" + trial));
        var headers = [{ name: candidate.name, value: candidate.value }]; if (shared) headers.push({ name: "Cache-Control", value: "no-cache" });
        variants.push({ family: "headers", name: "header:" + candidate.key, cache_key_mode: shared ? "shared" : "isolated", poison_url: clean, clean_url: clean, headers: headers, marker: candidate.marker, redirect_oracle: candidate.redirect_oracle || null, redirect_trial: trial, raw: candidate.raw });
      }
    });
    var combinations = input.header_combinations || [["X-Forwarded-Host~%s.invalid", "X-Forwarded-Scheme~http"]];
    (familyEnabled(input, "header-combinations") ? combinations : []).slice(0, Math.max(0, Math.min(Number(input.max_header_combinations == null ? 12 : input.max_header_combinations), 20))).forEach(function (combination, index) {
      var markerValue = token + "m" + index, headers = [], names = {}, valid = true;
      (combination || []).slice(0, 4).forEach(function (value) {
        var header = combinationHeader(value, markerValue), key = header && header.name.toLowerCase();
        if (!header || names[key]) { valid = false; return; }
        names[key] = true; headers.push(header);
      });
      if (!valid || headers.length < 2) return;
      var combinationName = "headers:" + headers.map(function (header) { return header.name.toLowerCase(); }).join("+");
      var clean = input.shared_header_cache_key_oracle === true ? baseUrl : addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":combination:" + index));
      if (input.shared_header_cache_key_oracle === true) headers.push({ name: "Cache-Control", value: "no-cache", marker: null });
      combinationVariants.push({ family: "header-combinations", name: combinationName, cache_key_mode: input.shared_header_cache_key_oracle === true ? "shared" : "isolated", poison_url: clean, clean_url: clean, headers: headers.map(function (header) { return { name: header.name, value: header.value }; }), marker: headers.some(function (header) { return header.marker === markerValue; }) ? markerValue : null });
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
        family: "cookies", name: "cookie:" + name.toLowerCase(), cache_key_mode: "isolated", poison_url: clean, clean_url: clean, headers: [],
        poison_cookies: [{ name: name, value: markerValue }],
        clean_cookies: [{ name: name, value: cleanValue }], marker: markerValue
      });
    });
    (familyEnabled(input, "query-parameters") ? parameterCandidates(input, context) : []).forEach(function (name, index) {
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":query:" + name));
      var markerValue = token + "q" + index.toString(36);
      variants.push({ family: "query-parameters", name: "query:" + name.toLowerCase(), cache_key_mode: "isolated", poison_url: addQuery(clean, name, markerValue), clean_url: clean, headers: [], marker: markerValue });
    });
    if (familyEnabled(input, "full-query") && input.full_query_oracle === true) {
      if (input.allow_shared_cache_key_tests !== true) throw new Error("full-query testing requires allow_shared_cache_key_tests=true");
      var parsed = splitUrl(baseUrl), shared = parsed.origin + parsed.path, fullMarker = token + "q0";
      shapeVariants.push({ family: "full-query", name: "full-query", cache_key_mode: "shared", poison_url: shared + "?" + encodeURIComponent(fullMarker), clean_url: shared, headers: [{ name: "Cache-Control", value: "no-cache" }], marker: fullMarker });
    }
    (familyEnabled(input, "parameter-cloaking") ? (input.parameter_cloaking || []) : []).slice(0, 20).forEach(function (entry, index) {
      var carrier = String(entry.carrier), target = String(entry.target), delimiter = String(entry.delimiter || ";"), markerValue = token + "p" + index;
      var sharedValue = token + "k" + index, isolatedBase = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":cloaking:" + index)), clean = addQuery(isolatedBase, carrier, sharedValue);
      shapeVariants.push({ family: "parameter-cloaking", name: "cloaking:" + carrier.toLowerCase() + delimiter + target.toLowerCase(), cache_key_mode: "isolated", poison_url: addCloakedQuery(isolatedBase, carrier, sharedValue, delimiter, target, markerValue), clean_url: clean, headers: [{ name: "Cache-Control", value: "no-cache" }], marker: markerValue });
    });
    (familyEnabled(input, "fat-get") ? (input.fat_get_parameters || []) : []).slice(0, 1000).forEach(function (name, index) {
      var markerValue = token + "f" + index, cleanValue = "hpclean" + cacheBuster(token + ":fat:" + name);
      var clean = addQuery(baseUrl, "hp_cache_bust", cacheBuster(token + ":fat-key:" + name));
      shapeVariants.push({
        family: "fat-get", name: "fat-get:" + String(name).toLowerCase(), cache_key_mode: "isolated", poison_url: clean, clean_url: clean,
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
    var op = { id: id, type: "http_request", base_exchange_id: exchange, method: method, url: url, protocol: "auto", credential_mode: anonymous ? "without_project_credentials" : "with_project_credentials" };
    if (headers && headers.length) op.headers = headers;
    if (cookieParams && cookieParams.length) op.cookie_params = cookieParams;
    op.header_tombstones = ["If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range", "Range"];
    if (anonymous) op.header_tombstones = op.header_tombstones.concat(["Cookie", "Authorization", "Proxy-Authorization"]);
    return op;
  }

  function poisonAttemptObservations(map, index, attempts) {
    var output = [];
    for (var attempt = 0; attempt < attempts; attempt += 1) {
      var id = attempt === 0 ? "poison-" + index : "poison-" + index + "-retry-" + attempt;
      if (map[id]) output.push({ attempt: attempt, observation: map[id] });
    }
    return output;
  }

  function boundedInteger(value, fallback, minimum, maximum) {
    var number = Number(value == null ? fallback : value);
    if (!Number.isFinite(number)) number = fallback;
    return Math.max(minimum, Math.min(Math.floor(number), maximum));
  }

  function delayBoundedVariantLimit(requested, attempts, interval) {
    var delayPerVariant = Math.max(0, attempts - 1) * interval;
    if (!delayPerVariant) return requested;
    return Math.max(1, Math.min(requested, Math.floor(600000 / delayPerVariant)));
  }

  function cloneInput(input) {
    var output = {};
    Object.keys(input).forEach(function (key) { output[key] = input[key]; });
    return output;
  }

  function requestedPhase(input, context) {
    if (["discover", "screen", "confirm", "advanced"].indexOf(input.phase) !== -1) return input.phase;
    if (!input.target_url && discoveryTargets(input, context).length > 1) return "discover";
    return input.scan_mode === "light" ? "confirm" : "screen";
  }

  function profileOperations(exchange, targetUrl, token) {
    var baselineWith = addQuery(targetUrl, "hp_cache_bust", cacheBuster(token + ":credentials:with"));
    var baselineWithout = addQuery(targetUrl, "hp_cache_bust", cacheBuster(token + ":credentials:without"));
    var profileA = addQuery(targetUrl, "hp_cache_bust", cacheBuster(token + ":profile:a"));
    var profileB = addQuery(targetUrl, "hp_cache_bust", cacheBuster(token + ":profile:b"));
    return [
      request("baseline-with-project-credentials-1", exchange.exchange_id, "GET", baselineWith, [], false),
      request("baseline-with-project-credentials-2", exchange.exchange_id, "GET", baselineWith, [], false),
      request("baseline-without-project-credentials-1", exchange.exchange_id, "GET", baselineWithout, [], true),
      request("baseline-without-project-credentials-2", exchange.exchange_id, "GET", baselineWithout, [], true),
      request("cache-profile-a-prime", exchange.exchange_id, "GET", profileA, [], false),
      request("cache-profile-a-repeat", exchange.exchange_id, "GET", profileA, [], false),
      request("cache-profile-b-prime", exchange.exchange_id, "GET", profileB, [], false),
      request("cache-profile-b-repeat", exchange.exchange_id, "GET", profileB, [], false)
    ];
  }

  function fairSelect(variants, maximumCost, perVariantCost, maximumVariants) {
    var families = {}, order = [], output = [], used = 0;
    variants.forEach(function (variant) {
      if (!families[variant.family]) { families[variant.family] = []; order.push(variant.family); }
      families[variant.family].push(variant);
    });
    var cursor = 0, progressed = true;
    while (progressed && output.length < maximumVariants) {
      progressed = false;
      for (var familyIndex = 0; familyIndex < order.length && output.length < maximumVariants; familyIndex += 1) {
        var values = families[order[familyIndex]], variant = values[cursor];
        if (!variant) continue;
        if (used + perVariantCost > maximumCost) return output;
        output.push(variant); used += perVariantCost; progressed = true;
      }
      cursor += 1;
    }
    return output;
  }

  function coverageFor(generated, selected, phase, headerTotal, screenedHeaders) {
    var names = ["headers", "header-combinations", "cookies", "query-parameters", "full-query", "parameter-cloaking", "fat-get", "url-normalization", "deception"], output = {};
    names.forEach(function (name) { output[name] = { generated: 0, tested: 0, deferred: 0, skipped: 0 }; });
    generated.forEach(function (variant) { if (output[variant.family]) output[variant.family].generated += 1; });
    selected.forEach(function (variant) { if (output[variant.family]) output[variant.family].tested += 1; });
    if (phase === "screen") { output.headers.generated = headerTotal; output.headers.tested = screenedHeaders; }
    names.forEach(function (name) { output[name].deferred = Math.max(0, output[name].generated - output[name].tested); });
    return output;
  }

  function plan(input, context) {
    if (input.allow_cache_side_effects !== true) throw new Error("cache testing requires allow_cache_side_effects=true");
    if (input.shared_header_cache_key_oracle === true && input.allow_shared_cache_key_tests !== true) throw new Error("shared header cache-key testing requires allow_shared_cache_key_tests=true");
    var exchange = base(context), token = marker(input), targetUrl = scanUrl(input, exchange), operations = [];
    var deceptionBaseUrl = input.deception_base_url ? sameOriginUrl(exchange.url, input.deception_base_url) : targetUrl;
    if (!deceptionBaseUrl) throw new Error("deception_base_url must use the base exchange origin");
    if (["GET", "HEAD"].indexOf(String(exchange.method || "GET").toUpperCase()) === -1) throw new Error("cache testing requires a saved GET or HEAD exchange");
    var scanMode = input.scan_mode === "light" ? "light" : "full", phase = requestedPhase(input, context);
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    if (phase === "screen" && modes.indexOf("poisoning") === -1) phase = "advanced";
    if (phase === "discover") {
      var targets = discoveryTargets(input, context), discoveryOperations = [];
      targets.forEach(function (url, index) {
        var profileA = addQuery(url, "hp_cache_bust", cacheBuster(token + ":discovery:a:" + index));
        var profileB = addQuery(url, "hp_cache_bust", cacheBuster(token + ":discovery:b:" + index));
        discoveryOperations.push(request("discover-isolated-a-prime-" + index, exchange.exchange_id, "GET", profileA, [], true));
        discoveryOperations.push(request("discover-isolated-a-repeat-" + index, exchange.exchange_id, "GET", profileA, [], true));
        discoveryOperations.push(request("discover-isolated-b-prime-" + index, exchange.exchange_id, "GET", profileB, [], true));
        discoveryOperations.push(request("discover-isolated-b-repeat-" + index, exchange.exchange_id, "GET", profileB, [], true));
        if (input.allow_shared_cache_key_tests === true) {
          discoveryOperations.push(request("discover-exact-prime-" + index, exchange.exchange_id, "GET", url, [], true));
          discoveryOperations.push(request("discover-exact-repeat-" + index, exchange.exchange_id, "GET", url, [], true));
        }
      });
      return { execution: "sequential", operations: discoveryOperations, preview: { stage: phase, scope: "current_stage", follow_up_expected: true, candidate_count: targets.length, candidate_unit: "target_urls", candidate_breakdown: { discovery_targets: targets.length }, selected_mode: scanMode, supported_modes: ["light", "full"], recommended_mode: "full", recommendation: scanMode === "light" ? "Light profiles one cacheable target; Full can continue through up to three targets and complete advanced families." : "Full provides complete staged cache-key and advanced-family coverage." }, result: { marker: token, scan_mode: scanMode, phase: phase, operation_count: discoveryOperations.length, discovery_targets: targets, discovery_target_count: targets.length, discovery_target_limit: boundedInteger(input.max_discovery_targets, 12, 1, 30), sequential_execution_required: true } };
    }
    var poisonAttempts = boundedInteger(input.poison_attempts, 1, 1, 20);
    var poisonInterval = boundedInteger(input.poison_interval_ms, 0, 0, 30000);
    var requestedPoisonLimit = boundedInteger(input.max_poison_variants, 500, 1, 1000);
    var effectivePoisonLimit = delayBoundedVariantLimit(requestedPoisonLimit, poisonAttempts, poisonInterval);
    var runDeception = modes.indexOf("deception") !== -1 && (scanMode === "light" || phase === "advanced");
    var deceptionSet = runDeception ? deceptionVariants(deceptionBaseUrl, token, input) : [];
    var normalizationEnabled = modes.indexOf("poisoning") !== -1 && familyEnabled(input, "url-normalization") && (input.url_normalization_oracle === true || (scanMode === "full" && phase === "advanced" && input.allow_shared_cache_key_tests === true && input.url_normalization_oracle == null));
    if (normalizationEnabled && input.allow_shared_cache_key_tests !== true) throw new Error("URL-normalization testing requires allow_shared_cache_key_tests=true");
    var reservedOperations = 8 + deceptionSet.length * 3 + (normalizationEnabled && phase === "advanced" ? 6 : 0);
    var generatedPoisonVariants = [], selectedPoisonVariants = [], headerSet = [], parameterSet = [], screenGroups = [], selectedScreenGroups = [], screenCursor = boundedInteger(input.screen_cursor, 0, 0, 100000);
    operations = profileOperations(exchange, targetUrl, token + ":" + phase + ":" + screenCursor);
    if (modes.indexOf("poisoning") !== -1) {
      if (phase === "screen") {
        headerSet = familyEnabled(input, "headers") ? headerCandidates(input, context, token) : [];
        parameterSet = familyEnabled(input, "query-parameters") ? parameterCandidates(input, context) : [];
        var headerBucketSize = boundedInteger(input.header_bucket_size, 8, 2, 32), parameterBucketSize = boundedInteger(input.parameter_bucket_size, 6, 2, 12);
        var headerGroups = [], parameterGroups = [];
        for (var headerStart = 0, headerBucket = 0; headerStart < headerSet.length; headerStart += headerBucketSize, headerBucket += 1) headerGroups.push({ family: "headers", index: headerBucket, candidates: headerSet.slice(headerStart, headerStart + headerBucketSize) });
        for (var parameterStart = 0, parameterBucket = 0; parameterStart < parameterSet.length; parameterStart += parameterBucketSize, parameterBucket += 1) {
          parameterGroups.push({ family: "query-parameters", index: parameterBucket, candidates: parameterSet.slice(parameterStart, parameterStart + parameterBucketSize).map(function (name, offset) {
            var absolute = parameterStart + offset; return { name: name, key: name.toLowerCase(), raw: name, value: token + "sq" + absolute.toString(36), marker: token + "sq" + absolute.toString(36) };
          }) });
        }
        for (var groupIndex = 0; groupIndex < Math.max(headerGroups.length, parameterGroups.length); groupIndex += 1) {
          if (headerGroups[groupIndex]) screenGroups.push(headerGroups[groupIndex]);
          if (parameterGroups[groupIndex]) screenGroups.push(parameterGroups[groupIndex]);
        }
        for (var selectedIndex = screenCursor; selectedIndex < screenGroups.length && operations.length + 2 <= 2000; selectedIndex += 1) {
          var group = screenGroups[selectedIndex], screenUrl = input.shared_header_cache_key_oracle === true && group.family === "headers" ? targetUrl : addQuery(targetUrl, "hp_cache_bust", cacheBuster(token + ":screen:" + group.family + ":" + group.index));
          var screenHeaders = group.family === "headers" ? group.candidates.map(function (candidate) { return { name: candidate.name, value: candidate.value }; }) : [];
          if (group.family === "headers" && input.shared_header_cache_key_oracle === true) screenHeaders.push({ name: "Cache-Control", value: "no-cache" });
          var screenMethod = input.target_url ? "GET" : exchange.method;
          var poisonScreen = request("screen-" + group.family + "-poison-" + group.index, exchange.exchange_id, screenMethod, screenUrl, screenHeaders, false);
          if (group.family === "query-parameters") poisonScreen.query_params = group.candidates.map(function (candidate) { return { name: candidate.name, value: candidate.value }; });
          operations.push(poisonScreen);
          operations.push(request("screen-" + group.family + "-clean-" + group.index, exchange.exchange_id, screenMethod, screenUrl, [], false));
          selectedScreenGroups.push(group);
        }
      } else {
        var includeHeaders = phase === "confirm";
        var scopedInput = cloneInput(input);
        if (scanMode === "light" && phase === "confirm" && (!input.oracle_families || !input.oracle_families.length)) scopedInput.oracle_families = ["headers", "header-combinations"];
        if (phase === "advanced") {
          scopedInput.oracle_families = input.oracle_families && input.oracle_families.length ? input.oracle_families.filter(function (name) { return name !== "headers"; }) : ["header-combinations", "cookies", "query-parameters", "full-query", "parameter-cloaking", "fat-get"];
          if (scopedInput.use_cookie_wordlist == null) scopedInput.use_cookie_wordlist = true;
          if (input.allow_shared_cache_key_tests === true && scopedInput.full_query_oracle == null) scopedInput.full_query_oracle = true;
          var confirmedParameters = scopedInput.confirmed_query_parameters || [];
          if (familyEnabled(scopedInput, "fat-get")) {
            scopedInput.fat_get_parameters = uniqueLines((scopedInput.fat_get_parameters || []).concat(confirmedParameters, input.parameter_names || []), 1000, function (value) { return /^[A-Za-z0-9_.-]{1,80}$/.test(value); });
          }
          if ((!scopedInput.parameter_cloaking || !scopedInput.parameter_cloaking.length) && familyEnabled(scopedInput, "parameter-cloaking")) {
            scopedInput.parameter_cloaking = automaticCloaking(input, targetUrl, confirmedParameters.concat(input.parameter_names || []));
          }
        }
        generatedPoisonVariants = poisonVariants(targetUrl, token, scopedInput, context, includeHeaders);
        var availablePoisonOperations = Math.max(0, 2000 - reservedOperations), perVariantCost = poisonAttempts + 2;
        selectedPoisonVariants = fairSelect(generatedPoisonVariants, availablePoisonOperations, perVariantCost, effectivePoisonLimit);
      }
      selectedPoisonVariants.forEach(function (variant, index) {
        var variantMethod = variant.family === "fat-get" || input.target_url ? "GET" : exchange.method;
        var clean = request("poison-clean-" + index, exchange.exchange_id, variantMethod, variant.clean_url, variant.clean_headers || [], false, variant.clean_cookies);
        var confirm = request("poison-confirm-" + index, exchange.exchange_id, variantMethod, variant.clean_url, variant.clean_headers || [], false, variant.clean_cookies);
        for (var attempt = 0; attempt < poisonAttempts; attempt += 1) {
          var poisonId = attempt === 0 ? "poison-" + index : "poison-" + index + "-retry-" + attempt;
          var poison = request(poisonId, exchange.exchange_id, variantMethod, variant.poison_url, variant.headers, false, variant.poison_cookies);
          if (variant.poison_body_base64 != null) poison.body_base64 = variant.poison_body_base64;
          if (attempt > 0 && poisonInterval > 0) poison.delay_before_ms = poisonInterval;
          operations.push(poison);
        }
        if (variant.clean_body_base64 != null) { clean.body_base64 = variant.clean_body_base64; confirm.body_base64 = variant.clean_body_base64; }
        operations.push(clean); operations.push(confirm);
      });
      if (normalizationEnabled && phase === "advanced") {
        for (var normalizationRepeat = 0; normalizationRepeat < 2; normalizationRepeat += 1) {
          var suffix = token + "n" + normalizationRepeat;
          operations.push(rawRequest("normalization-poison-" + normalizationRepeat, exchange.url, "/hp<" + suffix + ">"));
          operations.push(rawRequest("normalization-clean-" + normalizationRepeat, exchange.url, "/hp%3C" + suffix + "%3E"));
          operations.push(rawRequest("normalization-confirm-" + normalizationRepeat, exchange.url, "/hp%3C" + suffix + "%3E"));
        }
      }
    }
    if (modes.indexOf("deception") !== -1) {
      deceptionSet.forEach(function (variant, index) {
        operations.push(request("deception-with-project-credentials-" + index, exchange.exchange_id, exchange.method, variant.url, [], false));
        operations.push(request("deception-without-project-credentials-" + index, exchange.exchange_id, exchange.method, variant.url, [], true));
        operations.push(request("deception-confirm-" + index, exchange.exchange_id, exchange.method, variant.url, [], true));
      });
    }
    var completedScreenGroups = phase === "screen" ? screenGroups.slice(0, screenCursor + selectedScreenGroups.length) : [];
    var screenedHeaders = completedScreenGroups.filter(function (group) { return group.family === "headers"; }).reduce(function (count, group) { return count + group.candidates.length; }, 0);
    var coverage = coverageFor(generatedPoisonVariants, selectedPoisonVariants, phase, headerSet.length, screenedHeaders);
    if (phase === "screen") {
      coverage["query-parameters"].generated = parameterSet.length;
      coverage["query-parameters"].tested = completedScreenGroups.filter(function (group) { return group.family === "query-parameters"; }).reduce(function (count, group) { return count + group.candidates.length; }, 0);
      coverage["query-parameters"].deferred = Math.max(0, parameterSet.length - coverage["query-parameters"].tested);
      coverage["header-combinations"].generated = familyEnabled(input, "header-combinations") ? Math.min((input.header_combinations || [["X-Forwarded-Host", "X-Forwarded-Scheme"]]).length, boundedInteger(input.max_header_combinations, 12, 0, 20)) : 0;
      coverage["header-combinations"].deferred = coverage["header-combinations"].generated;
      coverage.cookies.generated = familyEnabled(input, "cookies") && context.resources && typeof context.resources.cookies === "string" ? uniqueLines(context.resources.cookies.split(/\r?\n/), boundedInteger(input.max_cookie_candidates, 40, 1, 100), function (value) { return /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value); }).length : 0;
      coverage.cookies.deferred = coverage.cookies.generated;
      coverage["full-query"].generated = familyEnabled(input, "full-query") ? 1 : 0;
      coverage["full-query"].deferred = input.allow_shared_cache_key_tests === true ? coverage["full-query"].generated : 0;
      coverage["full-query"].skipped = input.allow_shared_cache_key_tests === true ? 0 : coverage["full-query"].generated;
      coverage["parameter-cloaking"].skipped = familyEnabled(input, "parameter-cloaking") ? 1 : 0;
      coverage["fat-get"].skipped = familyEnabled(input, "fat-get") ? 1 : 0;
      coverage["url-normalization"].generated = familyEnabled(input, "url-normalization") ? 1 : 0;
      coverage["url-normalization"].deferred = input.allow_shared_cache_key_tests === true ? coverage["url-normalization"].generated : 0;
      coverage["url-normalization"].skipped = input.allow_shared_cache_key_tests === true ? 0 : coverage["url-normalization"].generated;
      coverage.deception.generated = modes.indexOf("deception") !== -1 ? deceptionVariants(deceptionBaseUrl, token, input).length : 0;
      coverage.deception.deferred = coverage.deception.generated;
    } else if (phase === "advanced") {
      if (familyEnabled(input, "fat-get") && coverage["fat-get"].generated === 0) coverage["fat-get"].skipped = 1;
      if (familyEnabled(input, "parameter-cloaking") && coverage["parameter-cloaking"].generated === 0) coverage["parameter-cloaking"].skipped = 1;
      if (familyEnabled(input, "full-query") && input.allow_shared_cache_key_tests !== true) coverage["full-query"].skipped = 1;
      if (familyEnabled(input, "url-normalization") && input.allow_shared_cache_key_tests !== true) coverage["url-normalization"].skipped = 1;
    }
    if (phase !== "screen") {
      coverage.deception.generated = deceptionSet.length; coverage.deception.tested = deceptionSet.length;
      coverage["url-normalization"].generated = normalizationEnabled ? 1 : 0; coverage["url-normalization"].tested = normalizationEnabled && phase === "advanced" ? 1 : 0; coverage["url-normalization"].deferred = coverage["url-normalization"].generated - coverage["url-normalization"].tested;
    }
    var candidateBreakdown = {}, candidateTotal = 0; Object.keys(coverage).forEach(function (family) { var count = Number(coverage[family].generated || 0); if (count) { candidateBreakdown[family] = count; candidateTotal += count; } });
    var followExpected = scanMode === "full" && phase !== "advanced";
    return { execution: "sequential", operations: operations, preview: { stage: phase, scope: "current_stage", follow_up_expected: followExpected, candidate_count: candidateTotal, candidate_unit: "candidate_inputs", candidate_breakdown: candidateBreakdown, selected_mode: scanMode, supported_modes: ["light", "full"], recommended_mode: "full", recommendation: scanMode === "light" ? "Light is the quick high-yield option; Full adds complete wordlists, cookies, request-shape, and deception families." : "Full provides complete staged cache-key and advanced-family coverage." }, result: { marker: token, scan_mode: scanMode, phase: phase, operation_count: operations.length, poison_attempts: poisonAttempts, poison_interval_ms: poisonInterval, cumulative_delay_budget_ms: 600000, poison_variants: selectedPoisonVariants.length, screened_groups: selectedScreenGroups.length, screen_cursor: screenCursor, screen_next_cursor: phase === "screen" && screenCursor + selectedScreenGroups.length < screenGroups.length ? screenCursor + selectedScreenGroups.length : null, screen_total_groups: screenGroups.length, coverage: coverage, coverage_unit: "candidate_inputs", poison_variant_limit_applied: selectedPoisonVariants.length < Math.min(requestedPoisonLimit, generatedPoisonVariants.length), operation_budget: 2000, sequential_execution_required: true } };
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
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    value = String(value || "").replace(/\s+/g, "");
    var padding = /==$/.test(value) ? 2 : /=$/.test(value) ? 1 : 0;
    var bytes = new Uint8Array(Math.max(0, Math.floor(value.length * 3 / 4) - padding)), written = 0;
    for (var offset = 0; offset < value.length; offset += 4) {
      var a = alphabet.indexOf(value.charAt(offset)), b = alphabet.indexOf(value.charAt(offset + 1));
      var c = alphabet.indexOf(value.charAt(offset + 2)), d = alphabet.indexOf(value.charAt(offset + 3));
      if (a < 0 || b < 0) break;
      bytes[written++] = (a << 2) | (b >> 4);
      if (c >= 0) bytes[written++] = ((b & 15) << 4) | (c >> 2);
      if (d >= 0) bytes[written++] = ((c & 3) << 6) | d;
    }
    var output = "";
    for (var start = 0; start < written; start += 8192) {
      output += String.fromCharCode.apply(null, bytes.subarray(start, Math.min(written, start + 8192)));
    }
    return output;
  }

  function normalizeText(value) {
    return String(value || "").toLowerCase()
      .replace(/((?:[?&]|&amp;|&#0*38;|&#x0*26;)hp_(?:cache_bust|control)=)[^&\"'<> ]+/g, "$1<cachebuster>")
      .replace(/(<input\b[^>]*\bname=["']?(?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token)["']?[^>]*\bvalue=)["'][^"']*["']/gi, "$1\"<volatile>\"")
      .replace(/\s+/g, " ").trim();
  }

  var preparedMemo = null;
  function classifyCache(headers) {
    var hit = [], miss = [], uncacheable = [];
    headers.forEach(function (header) {
      var name = header.name, value = header.value;
      if (name === "age") {
        var age = Number(value.trim()); if (Number.isFinite(age) && age > 0) hit.push("age: " + value);
      } else if (name === "x-cache") {
        var cacheParts = value.split(",").map(function (part) { return part.trim(); });
        if (cacheParts.some(function (part) {
          if (/hit[-_ ]?for[-_ ]?pass/i.test(part)) return false;
          part = part.trim();
          return /\btcp(?:_[a-z]+)*_hit\b/i.test(part) || /^hit(?:\s+from\b.*)?$/i.test(part);
        })) hit.push("x-cache: " + value);
        else if (cacheParts.some(function (part) { return /hit[-_ ]?for[-_ ]?pass|miss|bypass|dynamic|pass/i.test(part); })) miss.push("x-cache: " + value);
      } else if (name === "cf-cache-status") {
        if (/^\s*hit\s*$/i.test(value)) hit.push("cf-cache-status: " + value); else if (/miss|bypass|dynamic|expired/i.test(value)) miss.push("cf-cache-status: " + value);
      } else if (name === "cache-status") {
        if (/;\s*hit(?:\s|[;,]|$)/i.test(value)) hit.push("cache-status: " + value); else if (/\bfwd\s*=|miss|bypass/i.test(value)) miss.push("cache-status: " + value);
      } else if (name === "x-cache-hits") {
        var hitCounts = value.split(",").map(function (part) { return part.trim(); }).filter(Boolean).map(Number).filter(function (number) { return Number.isFinite(number); });
        if (hitCounts.some(function (number) { return number > 0; })) hit.push("x-cache-hits: " + value);
        else if (hitCounts.length) miss.push("x-cache-hits: " + value);
      } else if (name === "cache-control") {
        if (/(?:^|,)\s*(?:no-store|private)(?:\s*(?:=|,|$))/i.test(value)) uncacheable.push("cache-control: " + value);
      } else if (name === "vary" && /(?:^|,)\s*\*(?:\s*(?:,|$))/i.test(value)) uncacheable.push("vary: " + value);
    });
    var state = hit.length ? "hit" : uncacheable.length ? "uncacheable" : miss.length ? "miss" : "unknown";
    return { state: state, evidence: hit.concat(uncacheable, miss).slice(0, 8) };
  }

  function prepared(observation) {
    if (!observation) return { headerSearchText: "", markerMatches: {}, normalizedComparison: "", cache: { state: "unknown", evidence: [] } };
    var key = String(observation.id || observation.exchange_id || "");
    if (key && preparedMemo && preparedMemo[key]) return preparedMemo[key];
    var ignored = {
      "age": 1, "x-cache": 1, "cf-cache-status": 1, "x-cache-hits": 1, "cache-status": 1,
      "date": 1, "etag": 1, "last-modified": 1, "server-timing": 1, "via": 1,
      "cf-ray": 1, "request-id": 1, "x-request-id": 1, "set-cookie": 1
    };
    var previewText = preview(observation), headerSearchText = "", semanticHeaderText = "", comparison = previewText, headers = [];
    (observation.response_headers || []).forEach(function (header) {
      var name = String(header.name || "").toLowerCase(), value = decodeBase64(header.value_base64).toLowerCase();
      headers.push({ name: name, value: value });
      headerSearchText += "\n" + name + ":" + value;
      if (!ignored[name]) { semanticHeaderText += "\n" + name + ":" + value; comparison += "\n" + name + ":" + value; }
    });
    var result = { headerSearchText: headerSearchText, semanticHeaderText: semanticHeaderText, bodySearchText: null, normalizedBody: null, markerMatches: {}, normalizedComparison: normalizeText(comparison), cache: classifyCache(headers) };
    if (key && preparedMemo) preparedMemo[key] = result;
    return result;
  }

  function containsMarker(observation, value) {
    if (!observation || !value) return false;
    var preparedObservation = prepared(observation), key = String(value || "").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(preparedObservation.markerMatches, key)) return preparedObservation.markerMatches[key];
    if (preparedObservation.headerSearchText.indexOf(key) !== -1) {
      preparedObservation.markerMatches[key] = true; return true;
    }
    if (preparedObservation.bodySearchText == null) {
      preparedObservation.bodySearchText = observation.response_body_base64 ? decodeBase64(observation.response_body_base64).toLowerCase() : preview(observation);
    }
    var matched = preparedObservation.bodySearchText.indexOf(key) !== -1;
    preparedObservation.markerMatches[key] = matched;
    return matched;
  }

  function usableResponse(observation) {
    if (!observation || observation.error || observation.timed_out || observation.status_code == null) return false;
    var status = Number(observation.status_code);
    return Number.isFinite(status) && status >= 100 && [408, 425, 429, 499].indexOf(status) === -1 && status < 500;
  }

  function same(a, b) {
    if (!usableResponse(a) || !usableResponse(b) || Number(a.status_code) !== Number(b.status_code)) return false;
    var preparedA = prepared(a), preparedB = prepared(b);
    if (preparedA.semanticHeaderText !== preparedB.semanticHeaderText) return false;
    var hashA = String(a.response_body_hash || ""), hashB = String(b.response_body_hash || "");
    if (hashA && hashB && hashA === hashB) return true;
    if ((a.response_body_truncated || b.response_body_truncated) && hashA && hashB) return false;
    function normalizedBody(observation, preparedObservation) {
      if (preparedObservation.normalizedBody != null) return preparedObservation.normalizedBody;
      preparedObservation.normalizedBody = normalizeText(observation.response_body_base64 ? decodeBase64(observation.response_body_base64) : preview(observation));
      return preparedObservation.normalizedBody;
    }
    if (a.response_body_base64 || b.response_body_base64) return normalizedBody(a, preparedA) === normalizedBody(b, preparedB);
    if (hashA && hashB) return false;
    return preparedA.normalizedComparison === preparedB.normalizedComparison;
  }

  function cacheEvidence(observation) { return prepared(observation).cache; }

  function responseHeader(observation, expectedName) {
    var value = "";
    (observation && observation.response_headers || []).some(function (header) {
      if (String(header.name || "").toLowerCase() !== String(expectedName).toLowerCase()) return false;
      value = decodeBase64(header.value_base64); return true;
    });
    return value;
  }

  function redirectOracle(observation, oracle) {
    var status = Number(observation && observation.status_code || 0), location = responseHeader(observation, "location");
    if (!oracle || [301, 302, 307, 308].indexOf(status) === -1 || !location) return null;
    if (oracle === "http_scheme") {
      return /^http:\/\//i.test(location) ? location : null;
    }
    return null;
  }
  function normalizedRedirectLocation(location) {
    return String(location || "").replace(/([?&](?:amp;|#38;)?hp_cache_bust=)[^&#\s]*/gi, "$1<buster>");
  }
  function redirectTargetWithoutScheme(location, targetUrl) {
    var normalized = normalizedRedirectLocation(location).replace(/([?&])(?:amp;|#38;)?hp_cache_bust=<buster>(?:&)?/gi, function (match, separator) { return separator === "?" && /&$/.test(match) ? "?" : ""; }).replace(/[?&]$/, ""), authority = String(targetUrl || "").match(/^https?:\/\/([^/]+)/i);
    if (/^https?:\/\//i.test(normalized)) return normalized.replace(/^https?:\/\//i, "//");
    if (/^\/\//.test(normalized)) return normalized;
    if (/^\//.test(normalized) && authority) return "//" + authority[1].toLowerCase() + normalized;
    return null;
  }
  function pairedCacheEvidence(first, second) {
    var a = cacheEvidence(first), b = cacheEvidence(second), state = a.state === "hit" || b.state === "hit" ? "hit" : a.state === "uncacheable" || b.state === "uncacheable" ? "uncacheable" : a.state === "miss" || b.state === "miss" ? "miss" : "unknown";
    var seen = {}, evidence = [];
    a.evidence.concat(b.evidence).forEach(function (value) { if (!seen[value]) { seen[value] = true; evidence.push(value); } });
    return { state: state, evidence: evidence.slice(0, 8) };
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

  function rawCacheEvidence(observation) {
    var raw = observation && observation.raw, encoded = raw && (raw.response_transcript_base64 || raw.response_base64);
    if (!encoded) return { state: "unknown", evidence: [] };
    var transcript = decodeBase64(encoded), boundary = transcript.indexOf("\r\n\r\n"), head = boundary === -1 ? transcript : transcript.slice(0, boundary), headers = [];
    head.split(/\r?\n/).slice(1).forEach(function (line) {
      var separator = line.indexOf(":"); if (separator <= 0) return;
      headers.push({ name: line.slice(0, separator).trim().toLowerCase(), value: line.slice(separator + 1).trim().toLowerCase() });
    });
    return classifyCache(headers);
  }

  function cacheProfile(map) {
    var aPrime = map["cache-profile-a-prime"], aRepeat = map["cache-profile-a-repeat"], bPrime = map["cache-profile-b-prime"], bRepeat = map["cache-profile-b-repeat"];
    var aPrimeCache = cacheEvidence(aPrime), aRepeatCache = cacheEvidence(aRepeat), bPrimeCache = cacheEvidence(bPrime), bRepeatCache = cacheEvidence(bRepeat);
    var aStable = usableResponse(aPrime) && usableResponse(aRepeat) && same(aPrime, aRepeat);
    var bStable = usableResponse(bPrime) && usableResponse(bRepeat) && same(bPrime, bRepeat);
    var isolation = aStable && bStable && aRepeatCache.state === "hit" && bPrimeCache.state !== "hit" && bRepeatCache.state === "hit";
    return {
      cacheable: !!(aStable && aRepeatCache.state === "hit"), stable: !!(aStable && bStable), isolation_verified: !!isolation,
      key_a: { prime: aPrimeCache, repeat: aRepeatCache, stable: !!aStable },
      key_b: { prime: bPrimeCache, repeat: bRepeatCache, stable: !!bStable },
      explicit_hit: aRepeatCache.state === "hit" || bRepeatCache.state === "hit"
    };
  }

  function copyFollowUp(input, phase) {
    var output = cloneInput(input);
    output.phase = phase; output.scan_mode = input.scan_mode === "light" ? "light" : "full";
    return output;
  }

  function queuedTargetFollowUp(input, phase) {
    var queue = input.target_queue || [];
    if (!queue.length) return null;
    var next = queue[0], output = copyFollowUp(input, phase);
    output.target_url = next.url; output.target_key_mode = next.cache_key_mode; output.target_queue = queue.slice(1);
    delete output.headers; delete output.use_only_supplied_headers; delete output.oracle_families;
    delete output.parameter_names; delete output.confirmed_query_parameters; delete output.fat_get_parameters; delete output.parameter_cloaking; delete output.prior_candidate_headers;
    output.use_header_wordlist = true; output.use_parameter_wordlist = true;
    if (next.cache_key_mode === "shared") output.shared_header_cache_key_oracle = true;
    else delete output.shared_header_cache_key_oracle;
    return output;
  }

  function effectFingerprint(observation, markerValue) {
    var preparedObservation = prepared(observation);
    var value = observation && observation.response_body_base64 ? normalizeText(decodeBase64(observation.response_body_base64) + preparedObservation.semanticHeaderText) : preparedObservation.normalizedComparison;
    if (markerValue) value = value.split(String(markerValue).toLowerCase()).join("<marker>");
    return cacheBuster(String(observation && observation.status_code || "unknown") + ":" + value);
  }

  function endpointIdentity(url) {
    var parsed = splitUrl(url); return (parsed.origin + parsed.path).toLowerCase();
  }

  function endpointRoot(url) {
    return cacheBuster(endpointIdentity(url));
  }

  function deduplicateFindings(findings) {
    var byRoot = {}, order = [];
    findings.forEach(function (finding) {
      var metadata = finding.metadata || {}, key = String(metadata.root_cause || metadata.variant || finding.title).toLowerCase();
      if (!byRoot[key]) { byRoot[key] = finding; order.push(key); return; }
      var existing = byRoot[key], ids = {}, merged = [];
      (existing.evidence_exchange_ids || []).concat(finding.evidence_exchange_ids || []).forEach(function (id) { if (!ids[id]) { ids[id] = true; merged.push(id); } });
      existing.evidence_exchange_ids = merged;
      var variants = (existing.metadata.supporting_variants || [existing.metadata.variant]).concat(finding.metadata.supporting_variants || [finding.metadata.variant]), variantSeen = {};
      existing.metadata.supporting_variants = variants.filter(function (variant) { var variantKey = String(variant).toLowerCase(); if (variantSeen[variantKey]) return false; variantSeen[variantKey] = true; return true; }).slice(0, 50);
      existing.metadata.variant_count = existing.metadata.supporting_variants.length;
      if (existing.metadata.variant_count > 1) existing.title = existing.metadata.finding_type === "cache_deception" ? "Web cache deception via " + existing.metadata.variant_count + " equivalent path variants" : "Web cache poisoning via " + existing.metadata.variant_count + " equivalent inputs";
      existing.evidence_exchange_ids = existing.evidence_exchange_ids.slice(0, 20);
    });
    return order.map(function (key) { return byRoot[key]; });
  }

  function analyzeDiscovery(input, context, token, map, observations) {
    var targets = discoveryTargets(input, context), examined = [], eligible = [];
    function assessPair(prime, repeat, mode) {
      var stable = usableResponse(prime) && usableResponse(repeat) && same(prime, repeat);
      var status = Number(repeat && repeat.status_code || 0), nonempty = Number(repeat && repeat.response_length || 0) > 0;
      var redirect = [301, 302, 307, 308].indexOf(status) !== -1 && !!responseHeader(repeat, "location");
      var usableTarget = (status >= 200 && status < 300 && status !== 204 && nonempty) || redirect;
      var cache = pairedCacheEvidence(prime, repeat), accepted = stable && usableTarget && cache.state === "hit";
      return { mode: mode, stable: !!stable, usable_target_response: !!usableTarget, cache: cache, eligible: !!accepted };
    }
    targets.forEach(function (url, index) {
      var isolatedA = assessPair(map["discover-isolated-a-prime-" + index], map["discover-isolated-a-repeat-" + index], "isolated");
      var isolatedB = assessPair(map["discover-isolated-b-prime-" + index], map["discover-isolated-b-repeat-" + index], "isolated");
      var isolatedBPrime = cacheEvidence(map["discover-isolated-b-prime-" + index]);
      var isolated = { mode: "isolated", stable: isolatedA.stable && isolatedB.stable, usable_target_response: isolatedA.usable_target_response && isolatedB.usable_target_response, cache: pairedCacheEvidence(map["discover-isolated-a-repeat-" + index], map["discover-isolated-b-repeat-" + index]), key_b_prime: isolatedBPrime, eligible: isolatedA.eligible && isolatedB.eligible && isolatedBPrime.state !== "hit" };
      var exact = input.allow_shared_cache_key_tests === true ? assessPair(map["discover-exact-prime-" + index], map["discover-exact-repeat-" + index], "shared") : null;
      var selectedProfile = isolated.eligible ? isolated : exact && exact.eligible ? exact : null;
      var entry = { url: url, isolated: isolated, exact: exact, eligible: !!selectedProfile, cache_key_mode: selectedProfile && selectedProfile.mode, selected: false };
      if (selectedProfile) eligible.push(entry);
      examined.push(entry);
    });
    var scanMode = input.scan_mode === "light" ? "light" : "full", selectedTargets = eligible.slice(0, scanMode === "light" ? 1 : 3);
    selectedTargets.forEach(function (entry) { entry.selected = true; });
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    var nextPhase = scanMode === "light" ? "confirm" : modes.indexOf("poisoning") === -1 ? "advanced" : "screen", follow = null;
    if (selectedTargets.length) {
      follow = copyFollowUp(input, nextPhase); follow.target_url = selectedTargets[0].url;
      follow.target_key_mode = selectedTargets[0].cache_key_mode;
      follow.target_queue = selectedTargets.slice(1).map(function (entry) { return { url: entry.url, cache_key_mode: entry.cache_key_mode }; });
      follow.deception_base_url = scanUrl(input, base(context));
      if (selectedTargets[0].cache_key_mode === "shared") follow.shared_header_cache_key_oracle = true;
      else delete follow.shared_header_cache_key_oracle;
    }
    var discovery = base(context).page_discovery || {};
    return { findings: [], result: { marker: token, scan_mode: scanMode, phase: "discover", tested_operations: observations.length, discovery_targets: examined, eligible_target_count: eligible.length, selected_target_count: selectedTargets.length, discovery_source_total: Number(discovery.total || targets.length - 1), discovery_source_truncated: !!discovery.truncated, selection_reason: selectedTargets.length ? "stable_cacheable_http_response_explicit_hit" : "no_cacheable_target_found", follow_up: follow } };
  }

  function analyzeScreen(input, context, token, targetUrl, map, observations) {
    var candidates = headerCandidates(input, context, token), parameters = parameterCandidates(input, context);
    var headerBucketSize = boundedInteger(input.header_bucket_size, 8, 2, 32), parameterBucketSize = boundedInteger(input.parameter_bucket_size, 6, 2, 12);
    var selectedHeaders = (input.screen_candidate_headers || []).slice(), selectedParameters = (input.screen_candidate_parameters || []).slice(), selectedSeen = {}, parameterSeen = {}, mutations = [], mutationTotal = 0, reflected = [];
    selectedHeaders.forEach(function (value) { selectedSeen[String(value).split("~")[0].toLowerCase()] = true; });
    selectedParameters.forEach(function (value) { parameterSeen[String(value).toLowerCase()] = true; });
    var profile = cacheProfile(map), profilePrime = map["cache-profile-a-prime"];
    var withCredentials = map["baseline-with-project-credentials-1"], withCredentialsRepeat = map["baseline-with-project-credentials-2"];
    var withoutCredentials = map["baseline-without-project-credentials-1"], withoutCredentialsRepeat = map["baseline-without-project-credentials-2"];
    var withStable = usableResponse(withCredentials) && usableResponse(withCredentialsRepeat) && same(withCredentials, withCredentialsRepeat);
    var withoutStable = usableResponse(withoutCredentials) && usableResponse(withoutCredentialsRepeat) && same(withoutCredentials, withoutCredentialsRepeat);
    function inspect(family, bucket, bucketIndex) {
      var poison = map["screen-" + family + "-poison-" + bucketIndex], clean = map["screen-" + family + "-clean-" + bucketIndex];
      if (!poison) return;
      var attributed = [];
      bucket.forEach(function (candidate) {
        if (!candidate.marker || !containsMarker(poison, candidate.marker)) return;
        attributed.push(candidate.key); reflected.push({ family: family, candidate: candidate.key, marker: candidate.marker, persisted_to_clean: containsMarker(clean, candidate.marker), cache: cacheEvidence(clean) });
        if (family === "headers" && !selectedSeen[candidate.key]) { selectedSeen[candidate.key] = true; selectedHeaders.push(candidate.raw); }
        if (family === "query-parameters" && !parameterSeen[candidate.key]) { parameterSeen[candidate.key] = true; selectedParameters.push(candidate.raw); }
      });
      if (!attributed.length && profile.stable && profilePrime && cacheEvidence(clean).state === "hit" && same(poison, clean) && !same(profilePrime, clean)) {
        mutationTotal += 1;
        if (mutations.length < 20) mutations.push({ family: family, bucket: bucketIndex, candidates: bucket.map(function (candidate) { return candidate.key; }), classification: "inconclusive_mutation_only", reason: "A marker-free response similarity cannot establish cache-key omission or causality." });
      }
    }
    for (var start = 0, bucketIndex = 0; start < candidates.length; start += headerBucketSize, bucketIndex += 1) inspect("headers", candidates.slice(start, start + headerBucketSize), bucketIndex);
    for (var parameterStart = 0, parameterBucket = 0; parameterStart < parameters.length; parameterStart += parameterBucketSize, parameterBucket += 1) {
      inspect("query-parameters", parameters.slice(parameterStart, parameterStart + parameterBucketSize).map(function (name, offset) {
        var absolute = parameterStart + offset, value = token + "sq" + absolute.toString(36); return { name: name, key: name.toLowerCase(), raw: name, value: value, marker: value };
      }), parameterBucket);
    }
    var planSummary = plan(input, context).result, follow;
    if (planSummary.screen_next_cursor != null) {
      follow = copyFollowUp(input, "screen"); follow.screen_cursor = planSummary.screen_next_cursor;
      follow.screen_candidate_headers = selectedHeaders; follow.screen_candidate_parameters = selectedParameters;
    } else {
      follow = copyFollowUp(input, "confirm");
      follow.headers = selectedHeaders; follow.use_only_supplied_headers = true; follow.use_header_wordlist = false;
      follow.parameter_names = selectedParameters; follow.use_parameter_wordlist = false;
      follow.oracle_families = ["headers", "query-parameters"];
      delete follow.screen_cursor; delete follow.screen_candidate_headers; delete follow.screen_candidate_parameters;
    }
    return {
      findings: [], result: {
        marker: token, scan_mode: "full", phase: "screen", tested_operations: observations.length,
        credential_mode: { baseline_with_project_credentials: "with_project_credentials", baseline_without_project_credentials: "without_project_credentials" },
        credential_baselines: { with_project_credentials: { stable: !!withStable, first: cacheEvidence(withCredentials), repeat: cacheEvidence(withCredentialsRepeat) }, without_project_credentials: { stable: !!withoutStable, first: cacheEvidence(withoutCredentials), repeat: cacheEvidence(withoutCredentialsRepeat) } },
        cache_profile: profile, candidate_headers: selectedHeaders, candidate_parameters: selectedParameters, reflected_candidates: reflected, mutation_diagnostics: mutations, mutation_diagnostics_total: mutationTotal, mutation_diagnostics_truncated: mutationTotal > mutations.length,
        follow_up: follow,
        screen_next_cursor: planSummary.screen_next_cursor, coverage: planSummary.coverage, coverage_unit: planSummary.coverage_unit
      }
    };
  }

  function analyze(input, observations, context) {
    preparedMemo = {};
    var exchange = base(context), token = marker(input), targetUrl = scanUrl(input, exchange), map = byId(observations), findings = [], diagnostics = [], diagnosticTotal = 0;
    var deceptionBaseUrl = input.deception_base_url ? sameOriginUrl(exchange.url, input.deception_base_url) : targetUrl;
    if (!deceptionBaseUrl) throw new Error("deception_base_url must use the base exchange origin");
    var phase = requestedPhase(input, context), scanMode = input.scan_mode === "light" ? "light" : "full";
    var modes = input.modes && input.modes.length ? input.modes : ["poisoning", "deception"];
    if (phase === "screen" && modes.indexOf("poisoning") === -1) phase = "advanced";
    function addDiagnostic(value) { diagnosticTotal += 1; if (diagnostics.length < 50) diagnostics.push(value); }
    if (phase === "discover") {
      var discoveryResult = analyzeDiscovery(input, context, token, map, observations); preparedMemo = null; return discoveryResult;
    }
    if (phase === "screen") {
      var screenResult = analyzeScreen(input, context, token, targetUrl, map, observations); preparedMemo = null; return screenResult;
    }
    var withCredentials = map["baseline-with-project-credentials-1"], withCredentialsRepeat = map["baseline-with-project-credentials-2"];
    var withoutCredentials = map["baseline-without-project-credentials-1"], withoutCredentialsRepeat = map["baseline-without-project-credentials-2"];
    var withStable = usableResponse(withCredentials) && usableResponse(withCredentialsRepeat) && same(withCredentials, withCredentialsRepeat);
    var withoutStable = usableResponse(withoutCredentials) && usableResponse(withoutCredentialsRepeat) && same(withoutCredentials, withoutCredentialsRepeat);
    var baseLooksPrivate = withStable && withoutStable && !same(withCredentials, withoutCredentials);
    var profile = cacheProfile(map);
    var redirectTrials = {};
    if (modes.indexOf("poisoning") !== -1) {
      var poisonAttempts = boundedInteger(input.poison_attempts, 1, 1, 20);
      var poisonInterval = boundedInteger(input.poison_interval_ms, 0, 0, 30000);
      var effectivePoisonLimit = delayBoundedVariantLimit(boundedInteger(input.max_poison_variants, 500, 1, 1000), poisonAttempts, poisonInterval);
      var observedPoisonVariants = 0;
      while (map["poison-clean-" + observedPoisonVariants]) observedPoisonVariants += 1;
      var scopedInput = cloneInput(input);
      if (scanMode === "light" && phase === "confirm" && (!input.oracle_families || !input.oracle_families.length)) scopedInput.oracle_families = ["headers", "header-combinations"];
      if (phase === "advanced") {
        scopedInput.oracle_families = input.oracle_families && input.oracle_families.length ? input.oracle_families.filter(function (name) { return name !== "headers"; }) : ["header-combinations", "cookies", "query-parameters", "full-query", "parameter-cloaking", "fat-get"];
        if (scopedInput.use_cookie_wordlist == null) scopedInput.use_cookie_wordlist = true;
        if (input.allow_shared_cache_key_tests === true && scopedInput.full_query_oracle == null) scopedInput.full_query_oracle = true;
        var confirmedParameters = scopedInput.confirmed_query_parameters || [];
        if (familyEnabled(scopedInput, "fat-get")) {
          scopedInput.fat_get_parameters = uniqueLines((scopedInput.fat_get_parameters || []).concat(confirmedParameters, input.parameter_names || []), 1000, function (value) { return /^[A-Za-z0-9_.-]{1,80}$/.test(value); });
        }
        if ((!scopedInput.parameter_cloaking || !scopedInput.parameter_cloaking.length) && familyEnabled(scopedInput, "parameter-cloaking")) {
          scopedInput.parameter_cloaking = automaticCloaking(input, targetUrl, confirmedParameters.concat(input.parameter_names || []));
        }
      }
      var generated = poisonVariants(targetUrl, token, scopedInput, context, phase === "confirm");
      var selected = fairSelect(generated, 1995, poisonAttempts + 2, effectivePoisonLimit).slice(0, observedPoisonVariants);
      selected.forEach(function (variant, index) {
        var attempts = poisonAttemptObservations(map, index, poisonAttempts), clean = map["poison-clean-" + index], confirm = map["poison-confirm-" + index];
        var expectedMarker = variant.marker && String(variant.marker).toLowerCase();
        var usableAttempts = attempts.filter(function (item) { return usableResponse(item.observation); });
        var markerAttempt = expectedMarker && usableAttempts.find(function (item) { return containsMarker(item.observation, expectedMarker); });
        var persistedMarker = !!(markerAttempt && containsMarker(clean, expectedMarker) && containsMarker(confirm, expectedMarker));
        var redirectAttempt = !expectedMarker && variant.redirect_oracle && usableAttempts.find(function (item) { return !!redirectOracle(item.observation, variant.redirect_oracle); });
        var expectedCleanLocation = redirectAttempt && redirectOracle(redirectAttempt.observation, variant.redirect_oracle);
        var baselineLocations = [withCredentials, withCredentialsRepeat, withoutCredentials, withoutCredentialsRepeat, map["cache-profile-a-prime"], map["cache-profile-a-repeat"], map["cache-profile-b-prime"], map["cache-profile-b-repeat"]].map(function (item) { return responseHeader(item, "location"); }).filter(Boolean);
        var normalizedPoisonLocation = normalizedRedirectLocation(expectedCleanLocation), normalizedCleanLocation = normalizedRedirectLocation(responseHeader(clean, "location")), normalizedConfirmLocation = normalizedRedirectLocation(responseHeader(confirm, "location"));
        var poisonTarget = redirectTargetWithoutScheme(expectedCleanLocation, targetUrl);
        var sameRedirectTarget = !baselineLocations.length || baselineLocations.some(function (location) { return redirectTargetWithoutScheme(location, targetUrl) === poisonTarget; });
        var persistedRedirect = !!(redirectAttempt && expectedCleanLocation && poisonTarget && sameRedirectTarget && baselineLocations.every(function (location) { return normalizedRedirectLocation(location) !== normalizedPoisonLocation; }) && normalizedCleanLocation === normalizedPoisonLocation && normalizedConfirmLocation === normalizedPoisonLocation && Number(clean && clean.status_code) === Number(redirectAttempt.observation.status_code) && Number(confirm && confirm.status_code) === Number(redirectAttempt.observation.status_code));
        var cache = pairedCacheEvidence(clean, confirm), exactHit = cache.state === "hit";
        var proofAttempt = markerAttempt || redirectAttempt;
        var poisonCache = proofAttempt ? cacheEvidence(proofAttempt.observation) : { state: "unknown", evidence: [] };
        var sharedAcknowledged = variant.cache_key_mode === "shared" && input.allow_shared_cache_key_tests === true;
        var isolationAccepted = sharedAcknowledged || profile.isolation_verified;
        var poisonWasFresh = !!(proofAttempt && poisonCache.state !== "hit" && (sharedAcknowledged || poisonCache.state === "miss" || profile.isolation_verified));
        var redirectProofComplete = false, redirectProofEvidence = [];
        if (persistedRedirect && exactHit && isolationAccepted && poisonWasFresh) {
          var redirectKey = variant.name + ":" + normalizedPoisonLocation, redirectTrial = redirectTrials[redirectKey] || { count: 0, evidence: [] };
          redirectTrial.count += 1; [proofAttempt.observation, clean, confirm].forEach(function (item) { if (item) redirectTrial.evidence.push(item); }); redirectTrials[redirectKey] = redirectTrial;
          redirectProofComplete = redirectTrial.count >= 2; redirectProofEvidence = redirectTrial.evidence;
        }
        if ((persistedMarker || redirectProofComplete) && exactHit && isolationAccepted && poisonWasFresh) {
          var evidenceItems = persistedRedirect ? redirectProofEvidence : [proofAttempt.observation, clean, confirm].filter(Boolean);
          var proofValue = expectedMarker || expectedCleanLocation, fingerprint = effectFingerprint(clean, proofValue), rootCause = "cache-poisoning:" + endpointRoot(targetUrl) + ":" + fingerprint;
          findings.push({
            title: "Web cache poisoning via " + variant.name,
            severity: "high",
            confidence: "firm",
            explanation: persistedRedirect ? "A scheme header caused a deterministic HTTP redirect that was absent from clean baselines and persisted unchanged in two same-key clean cache HIT responses." : "A candidate-specific marker from the poisoning request was returned by two same-key clean requests, with an explicit cache HIT signal on the clean responses.",
            evidence_exchange_ids: evidenceItems.map(function (item) { return item.exchange_id; }).filter(Boolean),
            metadata: { variant: variant.name, supporting_variants: [variant.name], variant_count: 1, root_cause: rootCause, response_fingerprint: fingerprint, finding_type: "cache_poisoning", subtype: variant.name === "full-query" ? "full-query" : variant.name, marker: expectedMarker, poison_attempt: proofAttempt.attempt, poison_cache_state: poisonCache.state, proof: persistedRedirect ? "same_key_redirect_persistence_with_explicit_hit" : "same_key_marker_persistence_with_explicit_hit", cache_state: cache.state, cache_evidence: cache.evidence, cache_key_mode: variant.cache_key_mode, cache_profile_isolation_verified: profile.isolation_verified, credential_policy: "with_project_credentials" }
          });
        } else if (persistedMarker || persistedRedirect) {
          addDiagnostic({ variant: variant.name, classification: "marker_persisted_proof_incomplete", reason: poisonCache.state === "hit" ? "The marker-bearing poison request was already a cache HIT, so it cannot prove that this request seeded the entry." : !exactHit ? "No explicit cache HIT signal was observed on clean confirmation." : !isolationAccepted ? "The cache profile did not verify that the cache buster isolates keys." : "The poison request lacked a fresh MISS signal or verified key isolation.", cache_state: cache.state, poison_cache_state: poisonCache.state, isolation_verified: profile.isolation_verified });
        } else if (usableAttempts.some(function (item) { return clean && confirm && same(item.observation, clean) && same(clean, confirm); })) {
          addDiagnostic({ variant: variant.name, classification: "inconclusive_mutation_only", reason: "A response mutation without a candidate-specific persisted marker cannot establish cache poisoning." });
        } else if (markerAttempt) {
          addDiagnostic({ variant: variant.name, classification: "reflected_not_persisted", reason: "The candidate marker affected the poison response but did not persist to two clean requests." });
        }
      });
      var analyzeNormalization = phase === "advanced" && familyEnabled(input, "url-normalization") && (input.url_normalization_oracle === true || (scanMode === "full" && input.allow_shared_cache_key_tests === true && input.url_normalization_oracle == null));
      if (analyzeNormalization) {
        var normalizationEvidence = [], normalizationConfirmed = true;
        for (var normalizationRepeat = 0; normalizationRepeat < 2; normalizationRepeat += 1) {
          var rawPoison = map["normalization-poison-" + normalizationRepeat], rawClean = map["normalization-clean-" + normalizationRepeat], rawConfirm = map["normalization-confirm-" + normalizationRepeat];
          var poisonBody = rawBody(rawPoison), cleanBody = rawBody(rawClean), confirmBody = rawBody(rawConfirm);
          if (!poisonBody || poisonBody !== cleanBody || cleanBody !== confirmBody || poisonBody.indexOf("<" + token + "n" + normalizationRepeat + ">") === -1 || rawCacheEvidence(rawPoison).state === "hit" || (rawCacheEvidence(rawClean).state !== "hit" && rawCacheEvidence(rawConfirm).state !== "hit")) normalizationConfirmed = false;
          [rawPoison, rawClean, rawConfirm].forEach(function (item) { var id = rawEvidenceId(item); if (id) normalizationEvidence.push(id); });
        }
        var rawHit = [map["normalization-clean-0"], map["normalization-confirm-0"], map["normalization-clean-1"], map["normalization-confirm-1"]].some(function (item) { return rawCacheEvidence(item).state === "hit"; });
        if (normalizationConfirmed && rawHit) findings.push({
          title: "Web cache poisoning via URL normalization", severity: "high", confidence: "firm",
          explanation: "Two unique raw paths containing harmless angle-bracket markers collided with their browser-encoded equivalents, and each encoded clean request reproduced the raw response twice.",
          evidence_exchange_ids: normalizationEvidence,
          metadata: { variant: "url-normalization", supporting_variants: ["url-normalization"], variant_count: 1, root_cause: "cache-poisoning:" + endpointRoot(targetUrl) + ":url-normalization", finding_type: "cache_poisoning", marker: token, proof: "same_key_marker_persistence_with_explicit_hit", credential_policy: "without_project_credentials" }
        });
      }
    }
    if (modes.indexOf("deception") !== -1 && (scanMode === "light" || phase === "advanced") && baseLooksPrivate) {
      deceptionVariants(deceptionBaseUrl, token, input).forEach(function (variant, index) {
        var authenticated = map["deception-with-project-credentials-" + index], anonymous = map["deception-without-project-credentials-" + index], confirm = map["deception-confirm-" + index];
        var deceptionCache = pairedCacheEvidence(anonymous, confirm);
        var authenticatedCache = cacheEvidence(authenticated);
        if (authenticated && anonymous && confirm && authenticated.status_code >= 200 && authenticated.status_code < 300 && authenticatedCache.state !== "hit" && same(authenticated, withCredentials) && !same(authenticated, withoutCredentials) && same(authenticated, anonymous) && same(anonymous, confirm) && deceptionCache.state === "hit") {
          var deceptionFingerprint = effectFingerprint(anonymous, null);
          findings.push({
            title: "Web cache deception via " + variant.name,
            severity: "high",
            confidence: "firm",
            explanation: "A response that differs between credentialed and credential-free controls was reproduced without project credentials at a cacheable-looking path with an explicit cache HIT signal.",
            evidence_exchange_ids: [withCredentials.exchange_id, withCredentialsRepeat.exchange_id, withoutCredentials.exchange_id, withoutCredentialsRepeat.exchange_id, authenticated.exchange_id, anonymous.exchange_id, confirm.exchange_id].filter(Boolean),
            metadata: { variant: variant.name, supporting_variants: [variant.name], variant_count: 1, root_cause: "cache-deception:" + endpointRoot(targetUrl) + ":" + deceptionFingerprint, response_fingerprint: deceptionFingerprint, finding_type: "cache_deception", cache_state: deceptionCache.state, cache_evidence: deceptionCache.evidence, seed_credential_policy: "with_project_credentials", retrieval_credential_policy: "without_project_credentials" }
          });
        }
      });
    }
    var knownRootCauses = {}, currentFindings = deduplicateFindings(findings);
    (input.known_root_causes || []).forEach(function (rootCause) { knownRootCauses[String(rootCause).toLowerCase()] = true; });
    var deduplicatedFindings = currentFindings.filter(function (finding) {
      var rootCause = String(finding.metadata && finding.metadata.root_cause || "").toLowerCase();
      if (!rootCause || !knownRootCauses[rootCause]) return true;
      addDiagnostic({ variant: finding.metadata.variant, classification: "duplicate_root_cause_suppressed", root_cause: finding.metadata.root_cause, reason: "This root cause was already confirmed by an earlier stage or target." });
      return false;
    });
    var accumulatedRootCauses = uniqueLines((input.known_root_causes || []).concat(currentFindings.map(function (finding) { return finding.metadata.root_cause; }).filter(Boolean)), 1000);
    var followUp = null;
    if (scanMode === "full" && phase === "confirm") {
      followUp = copyFollowUp(input, "advanced"); followUp.prior_candidate_headers = (input.headers || []).slice(0, 5000); delete followUp.use_only_supplied_headers; delete followUp.headers;
      followUp.oracle_families = ["header-combinations", "cookies", "full-query", "parameter-cloaking", "fat-get", "url-normalization"];
      var confirmedQueryParameters = [];
      currentFindings.forEach(function (finding) {
        (finding.metadata.supporting_variants || [finding.metadata.variant]).forEach(function (variant) {
          if (/^query:/.test(variant)) confirmedQueryParameters.push(variant.slice("query:".length));
        });
      });
      followUp.confirmed_query_parameters = uniqueLines(confirmedQueryParameters, 1000, function (value) { return /^[A-Za-z0-9_.-]{1,80}$/.test(value); });
      followUp.known_root_causes = accumulatedRootCauses;
    } else if (phase === "advanced" || (scanMode === "light" && phase === "confirm")) {
      followUp = queuedTargetFollowUp(input, scanMode === "light" ? "confirm" : "screen");
      if (followUp) followUp.known_root_causes = accumulatedRootCauses;
    }
    var analysisCoverage = plan(input, context).result.coverage;
    var result = { findings: deduplicatedFindings, result: { marker: token, scan_mode: scanMode, phase: phase, target_url: targetUrl, candidate_context: { screened_headers: (input.prior_candidate_headers || input.headers || []).slice(0, 5000), confirmed_query_parameters: (input.confirmed_query_parameters || []).slice(0, 1000) }, base_appears_private: !!baseLooksPrivate, credential_mode: { baseline_with_project_credentials: "with_project_credentials", baseline_without_project_credentials: "without_project_credentials" }, credential_baselines: { with_project_credentials: { stable: !!withStable, first: cacheEvidence(withCredentials), repeat: cacheEvidence(withCredentialsRepeat) }, without_project_credentials: { stable: !!withoutStable, first: cacheEvidence(withoutCredentials), repeat: cacheEvidence(withoutCredentialsRepeat) } }, baseline_cache: { with_project_credentials: cacheEvidence(withCredentials), without_project_credentials: cacheEvidence(withoutCredentials) }, cache_profile: profile, mutation_diagnostics: diagnostics, mutation_diagnostics_total: diagnosticTotal, mutation_diagnostics_truncated: diagnosticTotal > diagnostics.length, coverage: analysisCoverage, coverage_unit: "candidate_inputs", tested_operations: observations.length, follow_up: followUp } };
    preparedMemo = null;
    return result;
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
