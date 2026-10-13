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
  function identitySelector(identity) {
    if (identity && identity.profile) return { profile: String(identity.profile) };
    if (identity && identity.cookie_file) return { cookie_file: String(identity.cookie_file) };
    return null;
  }
  function identityKey(identity) {
    var selector = identitySelector(identity);
    if (selector) return Object.keys(selector)[0] + ":" + selector[Object.keys(selector)[0]];
    var headers = identityHeaders(identity).map(function (item) {
      return String(item.name).toLowerCase().trim() + ":" + String(item.value).trim();
    }).filter(function (item) { return item.split(":").slice(1).join(":").length > 0; });
    headers.sort();
    return headers.join("\n");
  }
  function validateIdentity(identity, field) {
    var sources = (identity && identity.profile ? 1 : 0) + (identity && identity.cookie_file ? 1 : 0) + (identity && (identity.cookie || (identity.headers || []).length) ? 1 : 0);
    if (sources !== 1) throw new Error(field + " must provide exactly one non-empty inline cookie/headers, profile, or cookie_file identity source");
  }
  function validateComparisonIdentities(input) {
    if (!input.primary || !input.secondary) throw new Error("primary and secondary identities are required");
    validateIdentity(input.primary, "primary"); validateIdentity(input.secondary, "secondary");
    var primary = identityKey(input.primary), secondary = identityKey(input.secondary);
    if (!primary || !secondary) throw new Error("primary and secondary identities must each contain a non-empty cookie or header");
    if (primary === secondary) throw new Error("primary and secondary identities must be distinct");
  }
  function selectShapes(input, context) {
    var all = [base(context)].concat(context.related_exchanges || []), seen = {}, domains = input.domains || [];
    var selected = [], exclusions = [], excludedByReason = {}, limit = Math.floor(Math.max(1, Math.min(Number(input.max_requests || 100), 500)));
    if (!Number.isFinite(limit)) throw new Error("max_requests must be a finite request-shape limit");
    all.forEach(function (shape) {
      var key = shape.exchange_id + "", method = String(shape.method || "GET").toUpperCase(), reason = null;
      if (seen[key]) reason = "duplicate_exchange";
      else if (!domains.some(function (pattern) { return matches(host(shape.url), pattern); })) reason = "outside_domains";
      else if (["GET", "HEAD", "OPTIONS"].indexOf(method) === -1 && input.allow_state_changes !== true) reason = "state_change_not_allowed";
      else {
        seen[key] = true;
        if (selected.length >= limit) reason = "max_requests";
      }
      if (reason) {
        exclusions.push({ exchange_id: shape.exchange_id, method: method, reason: reason });
        excludedByReason[reason] = (excludedByReason[reason] || 0) + 1;
      } else selected.push(shape);
    });
    return { selected: selected, summary: { available_shapes: all.length, selected_shapes: selected.length, excluded_shapes: exclusions.length, excluded_by_reason: excludedByReason, exclusions: exclusions, max_requests_unit: "request_shapes" } };
  }
  function shapes(input, context) { return selectShapes(input, context).selected; }
  function planResult(selection, identities, mode, operationCount) {
    return { request_shapes: selection.selected.length, identities: identities, mode: mode, planned_operations: operationCount, selection: selection.summary };
  }
  function operation(id, shape, identity, anonymous) {
    var op = { id: id, type: "http_request", base_exchange_id: shape.exchange_id, method: shape.method, protocol: "auto" };
    op.header_tombstones = ["Cookie", "Authorization", "Proxy-Authorization"];
    if (!anonymous) {
      var selector = identitySelector(identity);
      if (selector) op.identity = selector;
      else op.headers = identityHeaders(identity);
    }
    op.credential_mode = "without_project_credentials";
    if (!anonymous && identitySelector(identity)) op.identity_comparison = "auth-analyzer";
    return op;
  }
  function plan(input, context) {
    if (!Array.isArray(input.domains) || !input.domains.length) throw new Error("at least one domain pattern is required");
    var operations = [], selection = selectShapes(input, context), selected = selection.selected;
    if (context.action === "anonymous_audit") {
      if (input.confirm_expected_protected !== true) throw new Error("anonymous audit requires confirm_expected_protected=true");
      if (input.anonymous_context) validateIdentity(input.anonymous_context, "anonymous_context");
      selected.forEach(function (shape, index) {
        for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("shape-" + index + "-anonymous-" + repeat, shape, input.anonymous_context || null, !input.anonymous_context));
      });
      var anonymousResult = planResult(selection, ["anonymous"], "anonymous_audit", operations.length);
      anonymousResult.anonymous_context_supplied = !!input.anonymous_context;
      return { operations: operations, result: anonymousResult };
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
    return { operations: operations, result: planResult(selection, includeAnonymous ? ["primary", "secondary", "anonymous"] : ["primary", "secondary"], "identity_comparison", operations.length) };
  }
  function mapById(items) {
    var map = Object.create(null);
    items.forEach(function (item) {
      if (!item || typeof item.id !== "string") return;
      if (Object.prototype.hasOwnProperty.call(map, item.id)) {
        var previous = map[item.id], ids = (previous.evidence_exchange_ids || []).concat(previous.exchange_id || [], item.exchange_id || []);
        map[item.id] = { id: item.id, error: "duplicate_observation", evidence_exchange_ids: ids };
      } else map[item.id] = item;
    });
    return map;
  }
  function text(item) {
    if (item && item.response_body_base64) return decode64(item.response_body_base64);
    return String(item && item.response_preview && item.response_preview.text || "");
  }
  function usableObservation(item) {
    return !!item && !item.error && !item.skipped && item.tested !== false && !item.transport_error && item.response_complete !== false &&
      Number.isInteger(item.status_code) && item.status_code >= 100 && item.status_code <= 599;
  }
  function bodyUnavailable(item) {
    return !!(item && (item.response_body_omitted_reason || item.response_body_truncated === true ||
      (!item.response_body_base64 && item.response_preview && item.response_preview.truncated === true)));
  }
  function normalize(value, input) {
    var output = String(value || "").toLowerCase();
    output = output
      .replace(/(<input\b[^>]*\bname=["']?(?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token)["']?[^>]*\bvalue=)["'][^"']*["']/gi, "$1\"<volatile>\"")
      .replace(/(["'](?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token|nonce|request_id|trace_id)["']\s*[:=]\s*)["'][^"']+["']/gi, "$1\"<volatile>\"")
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "<uuid>")
      .replace(/\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z\b/gi, "<timestamp>")
      .replace(/(["'](?:log_?id|timestamp|server_time|request_time|created_at|updated_at)["']\s*:\s*)(?:["'][^"']*["']|\d+(?:\.\d+)?)/gi, "$1\"<volatile>\"")
      .replace(/([?&](?:x-amz-signature|x-amz-date|x-amz-expires|signature|sig|expires)=)[^&#"'\s]+/gi, "$1<volatile>")
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
    if (!usableObservation(a) || !usableObservation(b) || bodyUnavailable(a) || bodyUnavailable(b) || a.status_code !== b.status_code) return false;
    var left = normalize(text(a), input), right = normalize(text(b), input);
    var threshold = Math.max(0.5, Math.min(Number(input.similarity_threshold == null ? 0.92 : input.similarity_threshold), 1));
    return similarity(left, right) >= threshold;
  }
  function pair(map, prefix, input) {
    var attempts = [map[prefix + "0"], map[prefix + "1"]];
    return { attempts: attempts, stable: same(attempts[0], attempts[1], input), representative: same(attempts[0], attempts[1], input) ? attempts[0] : null };
  }
  function markersMatch(item, input) {
    var value = text(item).toLowerCase(), success = input.success_markers || [], failure = input.failure_markers || [];
    return (!success.length || success.some(function (marker) { return value.indexOf(String(marker).toLowerCase()) !== -1; })) &&
      !failure.some(function (marker) { return value.indexOf(String(marker).toLowerCase()) !== -1; });
  }
  function allowed(item, input) {
    return !!item && markersMatch(item, input) &&
      ((item.status_code >= 200 && item.status_code < 400) || (input.success_markers || []).length > 0);
  }
  function outcome(pairValue, input) {
    if (!pairValue || pairValue.attempts.some(function (item) { return !usableObservation(item); })) return "inconclusive";
    if (((input.success_markers || []).length || (input.failure_markers || []).length) && pairValue.attempts.some(bodyUnavailable)) return "inconclusive";
    var values = pairValue.attempts.map(function (item) { return allowed(item, input); });
    if (values[0] && values[1]) return "allowed";
    if (!values[0] && !values[1]) return "not_allowed";
    return "inconclusive";
  }
  function evidence() {
    var seen = {}, ids = [];
    Array.prototype.slice.call(arguments).forEach(function (value) {
      var attempts = value && value.attempts || [];
      attempts.forEach(function (item) {
        if (!item) return;
        (item.evidence_exchange_ids || []).concat(item.exchange_id || []).forEach(function (id) {
          if (Number.isInteger(id) && id > 0 && !seen[id]) { seen[id] = true; ids.push(id); }
        });
      });
    });
    return ids;
  }
  function controlAssessment(pairValue, shape, input) {
    var attempts = pairValue ? pairValue.attempts : [], reasons = [];
    if (!pairValue) reasons.push("not_selected");
    else {
      if (attempts.some(function (item) { return !item; })) reasons.push("missing_observation");
      if (attempts.some(function (item) { return item && (item.skipped || item.tested === false); })) reasons.push("not_executed");
      if (attempts.some(function (item) { return item && (item.error || item.transport_error || item.response_complete === false); })) reasons.push("failed_observation");
      if (attempts.some(function (item) { return item && item.error === "duplicate_observation"; })) reasons.push("duplicate_observation");
      if (attempts.some(function (item) { return item && !Number.isInteger(item.status_code); })) reasons.push("invalid_status_observation");
      if (attempts.some(bodyUnavailable)) reasons.push("response_body_unavailable");
      if (!reasons.length && !pairValue.stable) reasons.push("responses_unstable");
    }
    var complete = !!pairValue && attempts.every(usableObservation);
    var savedStatus = typeof shape.status_code === "number" ? shape.status_code : null;
    return { observations_usable: complete, responses_stable: !!(pairValue && pairValue.stable), outcome: pairValue ? outcome(pairValue, input) : "not_tested", limitations: reasons,
      captured_status_code: savedStatus,
      captured_status_match: complete && savedStatus !== null ? attempts.every(function (item) { return item.status_code === savedStatus; }) : null,
      captured_response_match: "not_evaluated", captured_response_match_reason: "saved_response_body_not_compared" };
  }
  function executionCoverage(input, observations, context, classifications) {
    var selection = selectShapes(input, context), expected = Object.create(null), map = mapById(observations);
    var identities = context.action === "anonymous_audit" ? ["anonymous"] : input.include_anonymous === false ? ["primary", "secondary"] : ["primary", "secondary", "anonymous"];
    selection.selected.forEach(function (_, index) {
      identities.forEach(function (identity) {
        for (var repeat = 0; repeat < 2; repeat += 1) expected["shape-" + index + "-" + identity + "-" + repeat] = true;
      });
    });
    var coverage = { scope: "selected_request_shapes", planned_operations: Object.keys(expected).length, observed_operations: 0, usable_operations: 0, failed_operations: 0, skipped_operations: 0, missing_operations: 0, unexpected_observations: 0, duplicate_observations: 0 };
    var seen = {};
    observations.forEach(function (item) {
      if (!item || !Object.prototype.hasOwnProperty.call(expected, item.id)) coverage.unexpected_observations += 1;
      else if (seen[item.id]) coverage.duplicate_observations += 1;
      else seen[item.id] = true;
    });
    Object.keys(expected).forEach(function (id) {
      var item = map[id];
      if (!item) coverage.missing_operations += 1;
      else if (item.skipped || item.tested === false) coverage.skipped_operations += 1;
      else {
        coverage.observed_operations += 1;
        if (usableObservation(item)) coverage.usable_operations += 1;
        else coverage.failed_operations += 1;
      }
    });
    coverage.qualified_shapes = classifications.filter(function (item) { return item.coverage_qualified; }).length;
    coverage.status = !coverage.usable_operations ? "no_executed_coverage" : coverage.failed_operations || coverage.skipped_operations || coverage.missing_operations || coverage.qualified_shapes || coverage.duplicate_observations ? "qualified" : "complete";
    return { tested_operations: coverage.usable_operations, coverage: coverage, selection: selection.summary };
  }
  function analyze(input, observations, context) {
    var map = mapById(observations), findings = [], classifications = [];
    if (context.action === "anonymous_audit") {
      shapes(input, context).forEach(function (shape, index) {
        var anonymous = pair(map, "shape-" + index + "-anonymous-", input), anonymousOutcome = outcome(anonymous, input), anonymousAllowed = anonymousOutcome === "allowed";
        var anonymousControl = controlAssessment(anonymous, shape, input);
        classifications.push({ exchange_id: shape.exchange_id, anonymous_stable: anonymous.stable, anonymous_allowed: anonymousOutcome === "inconclusive" ? null : anonymousAllowed, anonymous_outcome: anonymousOutcome, evidence_exchange_ids: evidence(anonymous), mode: "anonymous_audit", controls: { anonymous: anonymousControl }, coverage_qualified: anonymousControl.limitations.length > 0 });
        if (anonymousAllowed) findings.push({
          title: "Possible unauthenticated authorization exposure", severity: "high", confidence: "firm",
          explanation: "The caller identified this request shape as expected to be protected, but two anonymous requests reproducibly received an allowed response. Any caller-supplied anonymous session context was preserved without inheriting base credentials.",
          evidence_exchange_ids: evidence(anonymous),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url, mode: "anonymous_audit" }
        });
      });
      var anonymousCoverage = executionCoverage(input, observations, context, classifications);
      return { findings: findings, result: { mode: "anonymous_audit", classifications: classifications, tested_operations: anonymousCoverage.tested_operations, coverage: anonymousCoverage.coverage, selection: anonymousCoverage.selection } };
    }
    validateComparisonIdentities(input);
    shapes(input, context).forEach(function (shape, index) {
      var prefix = "shape-" + index + "-", primary = pair(map, prefix + "primary-", input), secondary = pair(map, prefix + "secondary-", input);
      var anonymous = input.include_anonymous === false ? null : pair(map, prefix + "anonymous-", input);
      var primaryOutcome = outcome(primary, input), secondaryOutcome = outcome(secondary, input), anonymousOutcome = anonymous ? outcome(anonymous, input) : "not_tested";
      var primaryAllowed = primaryOutcome === "allowed", secondaryAllowed = secondaryOutcome === "allowed", anonymousAllowed = anonymousOutcome === "allowed";
      var crossIdentity = primary.stable && secondary.stable && primaryAllowed && secondaryAllowed && same(primary.representative, secondary.representative, input);
      var protectedResource = !anonymous || anonymousOutcome === "inconclusive" ? null : (!anonymousAllowed ? true : (!primary.stable || !anonymous.stable ? null : !same(primary.representative, anonymous.representative, input)));
      var controls = { primary: controlAssessment(primary, shape, input), secondary: controlAssessment(secondary, shape, input), anonymous: controlAssessment(anonymous, shape, input) };
      var coverageQualified = !primaryAllowed || Object.keys(controls).some(function (key) { return controls[key].limitations.length > 0; });
      classifications.push({ exchange_id: shape.exchange_id, primary_stable: primary.stable, secondary_stable: secondary.stable, anonymous_stable: anonymous ? anonymous.stable : null, primary_allowed: primaryOutcome === "inconclusive" ? null : primaryAllowed, secondary_allowed: secondaryOutcome === "inconclusive" ? null : secondaryAllowed, anonymous_allowed: anonymousOutcome === "inconclusive" || anonymousOutcome === "not_tested" ? null : anonymousAllowed, anonymous_outcome: anonymousOutcome, primary_outcome: primaryOutcome, secondary_outcome: secondaryOutcome, protected_resource: protectedResource, responses_equal: crossIdentity, evidence_exchange_ids: evidence(primary, secondary, anonymous), controls: controls, coverage_qualified: coverageQualified });
      if (primaryOutcome !== "inconclusive" && secondaryOutcome !== "inconclusive" && primaryAllowed !== secondaryAllowed) {
        var allowedIdentity = primaryAllowed ? "primary" : "secondary";
        findings.push({
          title: "Authorization outcome changes between supplied identities",
          severity: "high", confidence: "firm",
          explanation: "The " + allowedIdentity + " identity received a reproducible allowed response while the other supplied identity did not meet the allowed-response oracle. This is a privilege or identity boundary that requires review when the allowed identity is lower-privileged or attacker-controlled.",
          evidence_exchange_ids: evidence(primary, secondary),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url, allowed_identity: allowedIdentity, primary_status: primary.attempts[0].status_code, secondary_status: secondary.attempts[0].status_code }
        });
      }
      if (crossIdentity && protectedResource !== false) {
        findings.push({
          title: "Possible cross-user authorization exposure",
          severity: "high", confidence: protectedResource === true ? "firm" : "tentative",
          explanation: protectedResource === true ? "The request shape returned the same reproducible allowed response for two supplied identity sources while the anonymous control was not allowed or materially different." : "The request shape returned the same reproducible allowed response for two supplied identity sources; the anonymous control was inconclusive or not tested.",
          evidence_exchange_ids: evidence(primary, secondary, anonymous),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url }
        });
      }
      if (primary.stable && anonymous && anonymous.stable && primaryAllowed && anonymousAllowed && same(primary.representative, anonymous.representative, input)) {
        findings.push({
          title: "Possible unauthenticated authorization exposure",
          severity: "high", confidence: "firm",
          explanation: "The anonymous control reproduced the authenticated response across repeated requests.",
          evidence_exchange_ids: evidence(primary, anonymous),
          metadata: { source_exchange_id: shape.exchange_id, method: shape.method, url: shape.url }
        });
      }
    });
    var coverage = executionCoverage(input, observations, context, classifications);
    return { findings: findings, result: { mode: "identity_comparison", classifications: classifications, tested_operations: coverage.tested_operations, coverage: coverage.coverage, selection: coverage.selection } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
