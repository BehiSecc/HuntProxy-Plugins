(function () {
  "use strict";

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
    if (location === "query") op.query_params = words.map(function (word) { return { name: word, value: value }; });
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
    operations.push({ id: "baseline-0", type: "http_request", base_exchange_id: base.exchange_id, method: base.method, protocol: "auto" });
    operations.push({ id: "baseline-1", type: "http_request", base_exchange_id: base.exchange_id, method: base.method, protocol: "auto" });
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

  function changed(a, b, baselineUnstable) {
    if (!a || !b) return false;
    if (a.status_code !== b.status_code) return true;
    if (baselineUnstable) return false;
    if (a.response_body_hash && b.response_body_hash) return a.response_body_hash !== b.response_body_hash;
    if (a.response_length != null && b.response_length != null && Math.abs(a.response_length - b.response_length) > 8) return true;
    return String(a.response_preview && a.response_preview.text || "") !== String(b.response_preview && b.response_preview.text || "");
  }

  function analyze(input, observations, context) {
    var map = byId(observations), baseline = map["baseline-0"], second = map["baseline-1"];
    if (!baseline || !second) return { findings: [], result: { error: "baseline observations missing" } };
    var baselineUnstable = changed(baseline, second, false);
    var all = candidates(input, context), findings = [];
    if (input.phase === "confirm") {
      Object.keys(all).forEach(function (location) {
        all[location].forEach(function (word, index) {
          var first = map["confirm-" + location + "-" + index + "-0"];
          var repeat = map["confirm-" + location + "-" + index + "-1"];
          var reproducible = first && repeat && first.status_code === repeat.status_code && first.response_body_hash === repeat.response_body_hash;
          if (reproducible && changed(baseline, first, baselineUnstable)) {
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
        if (changed(baseline, map["screen-" + location + "-" + bucket], baselineUnstable)) {
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
        follow_up: { phase: "confirm", locations: Object.keys(narrowed), words_by_location: narrowed, use_only_supplied_words: true, max_words: Number(input.max_words || 500), max_requests: Number(input.max_requests || 5000), marker: input.marker },
        note: "Run the confirm phase with each candidate bucket as words for its matching location."
      }
    };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
