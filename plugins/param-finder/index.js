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

  var DEFAULTS = {
    query: ["admin", "debug", "redirect", "url", "callback", "return", "next", "id", "user", "role"],
    body: ["admin", "debug", "id", "user", "role", "isAdmin", "enabled"],
    cookie: ["admin", "debug", "role", "session", "user", "auth"],
    header: ["X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-HTTP-Method-Override"]
  };

  function uniqueWords(input, context, location) {
    var out = [], seen = {}, max = Math.max(1, Math.min(Number(input.max_words || 500), 5000));
    function add(value) {
      value = String(value || "").trim();
      if (!value || value.length > 128) return;
      if (location === "header" && !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)) return;
      if (location !== "header" && !/^[A-Za-z0-9_.:\[\]-]+$/.test(value)) return;
      var key = value.toLowerCase();
      if (!seen[key] && out.length < max) { seen[key] = true; out.push(value); }
    }
    if (input.use_only_supplied_words !== true) (DEFAULTS[location] || []).forEach(add);
    (input.harvested_words || []).forEach(add);
    (input.words || []).forEach(add);
    var resources = context.resources || {};
    var names = location === "header" ? ["headers", "boring_headers"] : ["params", "assetnote-params", "words"];
    if (input.use_only_supplied_words !== true) {
      names.forEach(function (name) {
        var text = resources[name];
        if (typeof text === "string") text.split(/\r?\n/).forEach(add);
        else if (Array.isArray(text)) text.forEach(add);
      });
    }
    return out;
  }

  function baseExchange(context) {
    if (!context.base_exchange || !context.base_exchange.exchange_id || !context.base_exchange.url) {
      throw new Error("ParamFinder requires a saved base exchange");
    }
    return context.base_exchange;
  }

  function marker(input, suffix) {
    return String(input.marker || "hp-param-7f31") + "-" + suffix;
  }

  function operation(base, input, location, words, id) {
    var value = marker(input, id);
    var op = { id: id, type: "http_request", base_exchange_id: base.exchange_id, method: base.method, protocol: "auto" };
    var query = [];
    if (input.cache_bust !== false) query.push({ name: String(input.cache_buster_name || "hp_pf_cb"), value: marker(input, "cache-" + id) });
    if (location === "query") query = query.concat(words.map(function (word) { return { name: word, value: value }; }));
    if (query.length) op.query_params = query;
    if (location === "header") op.headers = words.map(function (word) { return { name: word, value: value }; });
    if (location === "cookie") op.cookie_params = words.map(function (word) { return { name: word, value: value }; });
    if (location === "body") op.body_params = words.map(function (word) { return { name: word, value: value }; });
    return op;
  }

  function requestedLocations(input) {
    var locations = input.locations && input.locations.length ? input.locations : ["query", "header"];
    return locations.filter(function (value, index) {
      return ["query", "body", "cookie", "header"].indexOf(value) !== -1 && locations.indexOf(value) === index;
    });
  }

  function candidates(input, context) {
    var output = {};
    requestedLocations(input).forEach(function (location) {
      var scoped = {};
      Object.keys(input).forEach(function (key) { scoped[key] = input[key]; });
      if (input.words_by_location && Array.isArray(input.words_by_location[location])) scoped.words = input.words_by_location[location];
      output[location] = uniqueWords(scoped, context, location);
    });
    return output;
  }

  function plan(input, context) {
    var base = baseExchange(context), operations = [], skipped = [];
    operations.push(operation(base, input, null, [], "baseline-0"));
    operations.push(operation(base, input, null, [], "baseline-1"));
    var all = candidates(input, context);
    var phase = input.phase === "confirm" ? "confirm" : "screen";
    Object.keys(all).forEach(function (location) {
      var words = all[location];
      if (phase === "confirm") {
        words.forEach(function (word, index) {
          for (var repeat = 0; repeat < 2; repeat += 1) {
            var id = "confirm-" + location + "-" + index + "-" + repeat;
            var op = operation(base, input, location, [word], id);
            if (op) operations.push(op); else skipped.push(location);
          }
        });
      } else {
        var bucketSize = Math.max(2, Math.min(Number(input.bucket_size || 16), 64));
        for (var start = 0, bucket = 0; start < words.length; start += bucketSize, bucket += 1) {
          var id = "screen-" + location + "-" + bucket;
          var op = operation(base, input, location, words.slice(start, start + bucketSize), id);
          if (op) operations.push(op); else skipped.push(location);
        }
      }
    });
    var operationLimit = Math.max(4, Math.min(Number(input.max_requests || 5000), 5000));
    if (phase === "confirm" && operationLimit % 2 === 1) operationLimit -= 1;
    operations = operations.slice(0, operationLimit);
    return { operations: operations, result: { phase: phase, candidates: all, skipped_locations: Array.from(new Set(skipped)), operation_count: operations.length, truncated: operations.length >= operationLimit } };
  }

  function byId(observations) {
    var map = {};
    observations.forEach(function (observation) { map[observation.id] = observation; });
    return map;
  }

  function responseText(item) {
    if (item && item.response_body_base64) return decode64(item.response_body_base64);
    return String(item && item.response_preview && item.response_preview.text || "");
  }

  function normalized(item, input) {
    var output = responseText(item).toLowerCase();
    var buster = String(input.cache_buster_name || "hp_pf_cb").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    output = output
      .replace(new RegExp("([?&]" + buster + "=)[^&\\\"'<> ]+", "gi"), "$1<cachebuster>")
      .replace(/(<input\b[^>]*\bname=["']?(?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token)["']?[^>]*\bvalue=)["'][^"']*["']/gi, "$1\"<volatile>\"")
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "<uuid>")
      .replace(/\s+/g, " ").trim();
    (input.ignore_patterns || []).forEach(function (pattern) { try { output = output.replace(new RegExp(String(pattern), "gi"), "<ignored>"); } catch (_) {} });
    return output;
  }

  function similarity(left, right) {
    if (left === right) return 1;
    if (!left || !right) return 0;
    var a = {}, b = {}, union = {}, same = 0, total = 0;
    left.split(/[^a-z0-9_]+/).filter(Boolean).forEach(function (token) { a[token] = true; union[token] = true; });
    right.split(/[^a-z0-9_]+/).filter(Boolean).forEach(function (token) { b[token] = true; union[token] = true; });
    Object.keys(union).forEach(function (token) { total += 1; if (a[token] && b[token]) same += 1; });
    return total ? same / total : 0;
  }

  function equivalent(a, b, input) {
    if (!a || !b || a.error || b.error || a.status_code !== b.status_code) return false;
    var threshold = Math.max(0.5, Math.min(Number(input.similarity_threshold == null ? 0.96 : input.similarity_threshold), 1));
    return similarity(normalized(a, input), normalized(b, input)) >= threshold;
  }

  function changed(a, b, baselineUnstable, input) {
    if (!a || !b || a.error || b.error) return false;
    if (a.status_code !== b.status_code) return true;
    if (baselineUnstable) return false;
    return !equivalent(a, b, input);
  }

  function analyze(input, observations, context) {
    var map = byId(observations), baseline = map["baseline-0"], second = map["baseline-1"];
    if (!baseline || !second) return { findings: [], result: { error: "baseline observations missing" } };
    var baselineUnstable = changed(baseline, second, false, input);
    var all = candidates(input, context), findings = [];
    if (input.phase === "confirm") {
      Object.keys(all).forEach(function (location) {
        all[location].forEach(function (word, index) {
          var first = map["confirm-" + location + "-" + index + "-0"];
          var repeat = map["confirm-" + location + "-" + index + "-1"];
          var reproducible = equivalent(first, repeat, input);
          if (reproducible && changed(baseline, first, baselineUnstable, input)) {
            findings.push({
              title: "Hidden " + location + " parameter: " + word,
              severity: "info",
              confidence: baselineUnstable ? "tentative" : "firm",
              explanation: "Adding the parameter produced a repeatable response change relative to two control requests.",
              remediation: "Determine whether this unlinked input changes security-sensitive behavior or cache keys.",
              evidence_exchange_ids: [baseline.exchange_id, first.exchange_id, repeat.exchange_id].filter(Boolean),
              metadata: { location: location, parameter: word }
            });
          }
        });
      });
      return { findings: findings, result: { phase: "confirm", baseline_unstable: baselineUnstable, confirmed: findings.length } };
    }
    var narrowed = {}, bucketSize = Math.max(2, Math.min(Number(input.bucket_size || 16), 64));
    Object.keys(all).forEach(function (location) {
      narrowed[location] = [];
      for (var start = 0, bucket = 0; start < all[location].length; start += bucketSize, bucket += 1) {
        if (changed(baseline, map["screen-" + location + "-" + bucket], baselineUnstable, input)) {
          narrowed[location] = narrowed[location].concat(all[location].slice(start, start + bucketSize));
        }
      }
    });
    return {
      findings: [],
      result: {
        phase: "screen",
        baseline_unstable: baselineUnstable,
        candidate_buckets: narrowed,
        follow_up: Object.keys(narrowed).some(function (location) { return narrowed[location].length > 0; }) ? { phase: "confirm", locations: Object.keys(narrowed).filter(function (location) { return narrowed[location].length > 0; }), words_by_location: narrowed, use_only_supplied_words: true, max_words: Number(input.max_words || 500), max_requests: Number(input.max_requests || 5000), marker: input.marker, cache_bust: input.cache_bust !== false, cache_buster_name: input.cache_buster_name, similarity_threshold: input.similarity_threshold, ignore_patterns: input.ignore_patterns } : null,
        note: "Candidate buckets are cache-busted and must be confirmed individually; null follow_up means no response differential was observed."
      }
    };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
