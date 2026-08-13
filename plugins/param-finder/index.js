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
    query: ["chosen_discount", "roleid", "admin", "debug", "redirect", "url", "callback", "return", "next", "id", "user", "role"],
    body: ["chosen_discount", "roleid", "admin", "debug", "id", "user", "role", "isAdmin", "enabled"],
    cookie: ["admin", "debug", "role", "session", "user", "auth"],
    header: ["X-Custom-IP-Authorization", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-HTTP-Method-Override"]
  };

  function uniqueWords(input, context, location) {
    var out = [], seen = {}, limitReached = false, max = Math.max(1, Math.min(Number(input.max_words || 100000), 100000));
    function add(value) {
      value = String(value || "").trim();
      if (!value || value.length > 128) return;
      if (location === "header" && !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value)) return;
      if (location !== "header" && !/^[A-Za-z0-9_.:\[\]-]+$/.test(value)) return;
      var key = value.toLowerCase();
      if (!seen[key]) {
        seen[key] = true;
        if (out.length < max) out.push(value); else limitReached = true;
      }
    }
    (input.harvested_words || []).forEach(add);
    (input.words || []).forEach(add);
    if (input.use_only_supplied_words !== true) (DEFAULTS[location] || []).forEach(add);
    var resources = context.resources || {};
    var names = location === "header" ? ["headers", "boring_headers"] : ["params", "assetnote-params", "words"];
    if (input.use_only_supplied_words !== true) {
      names.forEach(function (name) {
        var text = resources[name];
        if (typeof text === "string") text.split(/\r?\n/).forEach(add);
        else if (Array.isArray(text)) text.forEach(add);
      });
    }
    out.word_limit_reached = limitReached;
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

  function operation(base, input, location, words, id, cacheKey, probeValue) {
    var value = probeValue || marker(input, id);
    var op = { id: id, type: "http_request", base_exchange_id: base.exchange_id, method: base.method, protocol: "auto" };
    var query = [];
    if (input.cache_bust !== false) query.push({ name: String(input.cache_buster_name || "hp_pf_cb"), value: cacheKey || marker(input, "cache-" + id) });
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

  function candidateSignature(input, all, base) {
    var hash = 2166136261;
    function add(value) {
      var text = String(value);
      for (var index = 0; index < text.length; index += 1) {
        hash ^= text.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
      }
      hash ^= 255; hash = Math.imul(hash, 16777619);
    }
    add(input.phase === "confirm" ? "confirm" : "screen");
    add(base.exchange_id); add(base.method); add(base.url);
    add(Math.max(2, Math.min(Number(input.bucket_size || 64), 64)));
    add(input.cache_key_tests !== false);
    add(input.cache_bust !== false);
    add(input.cache_buster_name || "hp_pf_cb");
    add(input.marker || "hp-param-7f31");
    add(input.similarity_threshold == null ? 0.96 : input.similarity_threshold);
    (input.ignore_patterns || []).forEach(add);
    requestedLocations(input).forEach(function (location) {
      add(location); (all[location] || []).forEach(add);
    });
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function operationGroups(base, input, all, phase) {
    var groups = [];
    requestedLocations(input).forEach(function (location) {
      var words = all[location] || [];
      if (phase === "confirm") {
        words.forEach(function (word, index) {
          var operations = [];
          for (var repeat = 0; repeat < 2; repeat += 1) {
            operations.push(operation(base, input, location, [word], "confirm-" + location + "-" + index + "-" + repeat));
          }
          if (input.cache_key_tests !== false && (location === "query" || location === "header")) {
            for (var cacheRepeat = 0; cacheRepeat < 2; cacheRepeat += 1) {
              var cacheKey = marker(input, "cache-key-" + location + "-" + index + "-" + cacheRepeat);
              var probeValue = marker(input, "cache-probe-" + location + "-" + index + "-" + cacheRepeat);
              operations.push(operation(base, input, location, [word], "cache-poison-" + location + "-" + index + "-" + cacheRepeat, cacheKey, probeValue));
              operations.push(operation(base, input, null, [], "cache-clean-" + location + "-" + index + "-" + cacheRepeat, cacheKey));
            }
          }
          groups.push({ location: location, start: index, count: 1, operations: operations });
        });
      } else {
        var bucketSize = Math.max(2, Math.min(Number(input.bucket_size || 64), 64));
        for (var start = 0, bucket = 0; start < words.length; start += bucketSize, bucket += 1) {
          var slice = words.slice(start, start + bucketSize), id = "screen-" + location + "-" + bucket;
          var bucketOperations = [operation(base, input, location, slice, id)];
          if (input.cache_key_tests !== false && (location === "query" || location === "header")) {
            var screenCacheKey = marker(input, "cache-key-screen-" + location + "-" + bucket);
            var screenProbeValue = marker(input, "cache-probe-screen-" + location + "-" + bucket);
            bucketOperations.push(operation(base, input, location, slice, "cache-screen-poison-" + location + "-" + bucket, screenCacheKey, screenProbeValue));
            bucketOperations.push(operation(base, input, null, [], "cache-screen-clean-" + location + "-" + bucket, screenCacheKey));
          }
          groups.push({ location: location, start: start, count: slice.length, bucket: bucket, operations: bucketOperations });
        }
      }
    });
    return groups;
  }

  function selectedPage(input, context) {
    var base = baseExchange(context), all = candidates(input, context);
    var phase = input.phase === "confirm" ? "confirm" : "screen";
    var groups = operationGroups(base, input, all, phase);
    var cursor = Number(input.cursor || 0);
    if (!Number.isInteger(cursor) || cursor < 0 || cursor > groups.length) throw new Error("ParamFinder cursor is invalid for this candidate set");
    var signature = candidateSignature(input, all, base);
    if (cursor > 0 && !input.candidate_signature) throw new Error("ParamFinder continuation requires candidate_signature");
    if (input.candidate_signature && input.candidate_signature !== signature) throw new Error("ParamFinder continuation no longer matches the saved request, detection settings, or candidate set");
    var operationLimit = Math.max(4, Math.min(Number(input.max_requests || 500), 5000));
    var operations = [operation(base, input, null, [], "baseline-0"), operation(base, input, null, [], "baseline-1")];
    var end = cursor;
    while (end < groups.length && operations.length + groups[end].operations.length <= operationLimit) {
      operations = operations.concat(groups[end].operations); end += 1;
    }
    if (cursor < groups.length && end === cursor) {
      throw new Error("max_requests is too small for two baselines and one complete " + phase + " test group; at least " + (2 + groups[cursor].operations.length) + " requests are required");
    }
    return { base: base, all: all, phase: phase, groups: groups, cursor: cursor, end: end, signature: signature, operations: operations, operation_limit: operationLimit };
  }

  function coverage(page) {
    var byLocation = {}, generated = 0, tested = 0;
    requestedLocations({ locations: Object.keys(page.all) }).forEach(function (location) {
      byLocation[location] = { generated: page.all[location].length, tested: 0, deferred: page.all[location].length };
      generated += page.all[location].length;
    });
    page.groups.slice(0, page.end).forEach(function (group) { byLocation[group.location].tested += group.count; tested += group.count; });
    Object.keys(byLocation).forEach(function (location) { byLocation[location].deferred = byLocation[location].generated - byLocation[location].tested; });
    var wordLimitReached = Object.keys(page.all).some(function (location) { return page.all[location].word_limit_reached === true; });
    return { scope: "current_phase", phase: page.phase, unit: "candidates", generated: generated, tested: tested, deferred: generated - tested, complete: page.end === page.groups.length, source_complete: page.end === page.groups.length && !wordLimitReached, word_limit_reached: wordLimitReached, by_location: byLocation };
  }

  function continuationInput(input, phase, cursor, signature) {
    var output = {};
    ["locations", "bucket_size", "max_words", "words", "harvested_words", "words_by_location", "use_only_supplied_words", "marker", "cache_bust", "cache_key_tests", "cache_buster_name", "similarity_threshold", "ignore_patterns", "max_requests"].forEach(function (key) {
      if (input[key] !== undefined) output[key] = input[key];
    });
    output.phase = phase; output.cursor = cursor; output.candidate_signature = signature;
    return output;
  }

  function plan(input, context) {
    var page = selectedPage(input, context), all = page.all, candidateCoverage = coverage(page);
    var candidateCounts = {}, candidateSample = {};
    Object.keys(all).forEach(function (location) { candidateCounts[location] = all[location].length; candidateSample[location] = all[location].slice(0, 20); });
    var plannedOperations = 2 + page.groups.reduce(function (total, group) { return total + group.operations.length; }, 0);
    return { execution: "sequential", operations: page.operations, result: { phase: page.phase, candidate_counts: candidateCounts, candidate_sample: candidateSample, skipped_locations: [], operation_count: page.operations.length, planned_operation_count: plannedOperations, cursor: page.cursor, next_cursor: page.end < page.groups.length ? page.end : null, candidate_signature: page.signature, truncated: page.end < page.groups.length, request_budget_exhausted: page.end < page.groups.length, candidate_word_limit_reached: candidateCoverage.word_limit_reached, coverage: candidateCoverage } };
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
  function bodyUnavailable(item) { return !!(item && item.response_body_omitted_reason); }

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
    if (!a || !b || a.error || b.error || bodyUnavailable(a) || bodyUnavailable(b) || a.status_code !== b.status_code) return false;
    var threshold = Math.max(0.5, Math.min(Number(input.similarity_threshold == null ? 0.96 : input.similarity_threshold), 1));
    return similarity(normalized(a, input), normalized(b, input)) >= threshold;
  }

  function changed(a, b, baselineUnstable, input) {
    if (!a || !b || a.error || b.error) return false;
    if (a.status_code !== b.status_code) return true;
    if (baselineUnstable) return false;
    return !equivalent(a, b, input);
  }

  function contains(item, value) { return !!(item && !item.error && !bodyUnavailable(item) && responseText(item).indexOf(value) !== -1); }

  function analyze(input, observations, context) {
    var map = byId(observations), baseline = map["baseline-0"], second = map["baseline-1"];
    if (!baseline || !second) return { findings: [], result: { error: "baseline observations missing" } };
    var baselineUnstable = changed(baseline, second, false, input);
    var page = selectedPage(input, context), all = page.all, findings = [], candidateCoverage = coverage(page);
    if (page.phase === "confirm") {
      page.groups.slice(page.cursor, page.end).forEach(function (group) {
          var location = group.location, index = group.start, word = all[location][index];
          var first = map["confirm-" + location + "-" + index + "-0"];
          var repeat = map["confirm-" + location + "-" + index + "-1"];
          var reproducible = equivalent(first, repeat, input);
          if (reproducible && changed(baseline, first, baselineUnstable, input)) {
            findings.push({
              title: "Hidden " + location + " parameter: " + word,
              severity: "info",
              confidence: baselineUnstable ? "tentative" : "firm",
              explanation: "Adding the parameter produced a repeatable response change relative to two control requests.",
              evidence_exchange_ids: [baseline.exchange_id, first.exchange_id, repeat.exchange_id].filter(Boolean),
              metadata: { location: location, parameter: word }
            });
          }
          if (input.cache_key_tests !== false && (location === "query" || location === "header")) {
            var cacheEvidence = [], cacheConfirmed = true;
            for (var cacheRepeat = 0; cacheRepeat < 2; cacheRepeat += 1) {
              var poison = map["cache-poison-" + location + "-" + index + "-" + cacheRepeat];
              var clean = map["cache-clean-" + location + "-" + index + "-" + cacheRepeat];
              var probeValue = marker(input, "cache-probe-" + location + "-" + index + "-" + cacheRepeat);
              if (!contains(poison, probeValue) || !contains(clean, probeValue)) cacheConfirmed = false;
              if (poison && poison.exchange_id) cacheEvidence.push(poison.exchange_id);
              if (clean && clean.exchange_id) cacheEvidence.push(clean.exchange_id);
            }
            if (cacheConfirmed) findings.push({
              title: "Unkeyed cache " + location + " parameter: " + word,
              severity: "medium", confidence: "firm",
              explanation: "A unique value supplied through this parameter persisted into a clean request with the same isolated cache key in two independent trials.",
              evidence_exchange_ids: cacheEvidence,
              metadata: { location: location, parameter: word, signal: "poison_clean_persistence" }
            });
          }
      });
      var confirmFollowUp = null;
      if (page.end < page.groups.length) {
        confirmFollowUp = continuationInput(input, "confirm", page.end, page.signature);
        if (input.resume_screen) confirmFollowUp.resume_screen = input.resume_screen;
      } else if (input.resume_screen) confirmFollowUp = input.resume_screen;
      return { findings: findings, result: { phase: "confirm", baseline_unstable: baselineUnstable, confirmed: findings.length, cursor: page.cursor, next_cursor: page.end < page.groups.length ? page.end : null, request_budget_exhausted: page.end < page.groups.length, coverage: candidateCoverage, workflow_complete: confirmFollowUp === null, follow_up: confirmFollowUp } };
    }
    var narrowed = {}, bucketSize = Math.max(2, Math.min(Number(input.bucket_size || 64), 64));
    Object.keys(all).forEach(function (location) {
      narrowed[location] = [];
    });
    page.groups.slice(page.cursor, page.end).forEach(function (group) {
        var location = group.location, start = group.start, bucket = group.bucket;
        if (changed(baseline, map["screen-" + location + "-" + bucket], baselineUnstable, input)) {
          narrowed[location] = narrowed[location].concat(all[location].slice(start, start + group.count));
        }
        if (input.cache_key_tests !== false && (location === "query" || location === "header")) {
          var probeValue = marker(input, "cache-probe-screen-" + location + "-" + bucket);
          if (contains(map["cache-screen-clean-" + location + "-" + bucket], probeValue)) narrowed[location] = narrowed[location].concat(all[location].slice(start, start + group.count));
        }
    });
    Object.keys(all).forEach(function (location) {
      narrowed[location] = narrowed[location].filter(function (word, index, words) { return words.indexOf(word) === index; });
    });
    var followUpMaxWords = Math.max(Number(input.max_words || 100000), Object.keys(narrowed).reduce(function (largest, location) { return Math.max(largest, narrowed[location].length); }, 0));
    var nextScreen = page.end < page.groups.length ? continuationInput(input, "screen", page.end, page.signature) : null;
    var hasCandidates = Object.keys(narrowed).some(function (location) { return narrowed[location].length > 0; });
    var followUp = nextScreen;
    if (hasCandidates) {
      var confirmLocations = Object.keys(narrowed).filter(function (location) { return narrowed[location].length > 0; });
      var confirmMinimum = input.cache_key_tests !== false && confirmLocations.some(function (location) { return location === "query" || location === "header"; }) ? 8 : 4;
      followUp = { phase: "confirm", locations: confirmLocations, words_by_location: narrowed, use_only_supplied_words: true, max_words: Math.min(followUpMaxWords, 100000), max_requests: Math.max(Number(input.max_requests || 500), confirmMinimum), marker: input.marker, cache_bust: input.cache_bust !== false, cache_key_tests: input.cache_key_tests !== false, cache_buster_name: input.cache_buster_name, similarity_threshold: input.similarity_threshold, ignore_patterns: input.ignore_patterns };
      if (nextScreen) followUp.resume_screen = nextScreen;
    }
    return {
      findings: [],
      result: {
        phase: "screen",
        baseline_unstable: baselineUnstable,
        candidate_buckets: narrowed,
        cursor: page.cursor,
        next_cursor: page.end < page.groups.length ? page.end : null,
        request_budget_exhausted: page.end < page.groups.length,
        candidate_word_limit_reached: candidateCoverage.word_limit_reached,
        coverage: candidateCoverage,
        workflow_complete: followUp === null,
        follow_up: followUp,
        note: hasCandidates ? "Run the returned confirmation follow-up; it automatically resumes remaining screening coverage afterward." : (nextScreen ? "Run the returned follow-up to continue screening the remaining candidates." : "Screening coverage is complete and no candidate buckets changed.")
      }
    };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
