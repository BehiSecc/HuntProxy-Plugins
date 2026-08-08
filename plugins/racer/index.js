(function () {
  "use strict";

  function boundedInteger(value, fallback, minimum, maximum, name) {
    var number = value == null ? fallback : Number(value);
    if (!Number.isInteger(number) || number < minimum || number > maximum) {
      throw new Error(name + " must be an integer from " + minimum + " to " + maximum);
    }
    return number;
  }

  function clone(value) { return JSON.parse(JSON.stringify(value)); }

  function bindAttemptValue(value, attempt) {
    return typeof value === "string" ? value.split("{attempt}").join(String(attempt)) : value;
  }

  function bindAttemptRequests(requests, attempt) {
    return requests.map(function (source) {
      var request = clone(source);
      if (request.body_base64 && request.body_base64.indexOf("{attempt}") !== -1) throw new Error("{attempt} is not supported in body_base64; use body_text or typed header/URL values");
      request.url = bindAttemptValue(request.url, attempt);
      request.body_text = bindAttemptValue(request.body_text, attempt);
      if (Array.isArray(request.headers)) request.headers.forEach(function (header) { header.value = bindAttemptValue(header.value, attempt); });
      return request;
    });
  }

  function normalizeTemplate(item, index, prefix, inheritedSuccess) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(prefix + " request must be an object");
    var request = { id: String(item.id || (prefix + "-shape-" + index)) };
    ["base_exchange_id", "method", "url", "headers", "header_tombstones", "body_text", "body_base64", "protocol"].forEach(function (field) {
      if (item[field] != null) request[field] = clone(item[field]);
    });
    request.use_project_cookies = item.use_project_cookies !== false;
    if (request.base_exchange_id == null && !request.url) throw new Error(request.id + " requires base_exchange_id or url");
    if (request.body_text != null && request.body_base64 != null) throw new Error(request.id + " cannot combine body_text and body_base64");
    request.success = item.success != null ? clone(item.success) : (inheritedSuccess != null ? clone(inheritedSuccess) : undefined);
    if (request.success == null) delete request.success;
    return { request: request, copies: boundedInteger(item.copies, 1, 1, 100, request.id + ".copies") };
  }

  function legacyTemplates(input, context) {
    var ids = Array.isArray(input.exchange_ids) && input.exchange_ids.length ? input.exchange_ids.slice() : [];
    if (!ids.length && context.base_exchange && context.base_exchange.exchange_id) ids.push(context.base_exchange.exchange_id);
    ids = ids.filter(function (id, index) { return Number.isInteger(id) && id > 0 && ids.indexOf(id) === index; });
    if (!ids.length) throw new Error("Racer requires requests, a base exchange, or exchange_ids");
    var copies = boundedInteger(input.copies, ids.length === 1 ? 20 : 1, 1, 100, "copies");
    return ids.map(function (id, index) {
      return normalizeTemplate({ id: "shape-" + index, base_exchange_id: id, copies: copies }, index, "race", input.success);
    });
  }

  function templates(input, context, field, prefix, inheritedSuccess) {
    var values = input[field];
    if (field === "requests" && (!Array.isArray(values) || !values.length)) return legacyTemplates(input, context);
    if (values == null) return [];
    if (!Array.isArray(values) || !values.length) throw new Error(field + " must be a non-empty array when provided");
    if (values.length > 20) throw new Error(field + " supports at most 20 request shapes");
    return values.map(function (item, index) { return normalizeTemplate(item, index, prefix, inheritedSuccess); });
  }

  function expand(definitions, maximum, prefix) {
    var output = [];
    definitions.forEach(function (definition, shape) {
      for (var copyIndex = 0; copyIndex < definition.copies; copyIndex += 1) {
        var request = clone(definition.request);
        request.id = prefix + "-shape-" + shape + "-copy-" + copyIndex;
        output.push(request);
      }
    });
    if (!output.length || output.length > maximum) throw new Error(prefix + " group must contain 1.." + maximum + " requests");
    return output;
  }

  function singleEach(definitions, prefix) {
    return definitions.map(function (definition, index) {
      var request = clone(definition.request);
      request.id = prefix + "-shape-" + index;
      return request;
    });
  }

  function group(id, technique, attempt, requests, options) {
    return { id: id, type: "race_group", technique: technique, attempt: attempt, requests: requests, options: options };
  }

  function plan(input, context) {
    if (input.allow_state_changes !== true) throw new Error("race testing requires allow_state_changes=true");
    var requestedTechnique = input.technique || "last_byte_sync";
    if (["sequential", "parallel", "last_byte_sync", "h2_single_packet"].indexOf(requestedTechnique) === -1) throw new Error("unsupported race technique");
    var hostTechnique = requestedTechnique === "sequential" ? "sequential_control" : requestedTechnique;
    var attempts = boundedInteger(input.attempts, 3, 1, 20, "attempts");
    var raceDefinitions = templates(input, context, "requests", "race", input.success);
    var setupDefinitions = templates(input, context, "setup_requests", "setup", input.setup_success);
    var validationDefinitions = templates(input, context, "validation_requests", "validation", input.validation_success);
    var raceRequests = expand(raceDefinitions, 100, "race");
    var setupRequests = setupDefinitions.length ? expand(setupDefinitions, 20, "setup") : [];
    var validationRequests = validationDefinitions.length ? expand(validationDefinitions, 20, "validation") : [];
    var timeout = boundedInteger(input.timeout_ms, 30000, 1000, 120000, "timeout_ms");
    var holdTimeout = boundedInteger(input.hold_timeout_ms, 5000, 100, 15000, "hold_timeout_ms");
    var options = { timeout_ms: timeout, hold_timeout_ms: holdTimeout };
    var controlMode = input.control_mode || "single_each";
    if (["none", "single_each", "full_group"].indexOf(controlMode) === -1) throw new Error("unsupported control_mode");
    var operations = [];
    function setup(id, attempt) { if (setupRequests.length) operations.push(group(id, "sequential_control", attempt, bindAttemptRequests(setupRequests, attempt), options)); }
    function validate(id, attempt) { if (validationRequests.length) operations.push(group(id, "sequential_control", attempt, bindAttemptRequests(validationRequests, attempt), options)); }
    if (controlMode !== "none") {
      setup("setup-control", 0);
      operations.push(group("control-0", "sequential_control", 0, bindAttemptRequests(controlMode === "full_group" ? raceRequests : singleEach(raceDefinitions, "control"), 0), options));
      validate("validate-control", 0);
    }
    for (var attempt = 0; attempt < attempts; attempt += 1) {
      setup("setup-" + attempt, attempt);
      operations.push(group("race-" + attempt, hostTechnique, attempt, bindAttemptRequests(raceRequests, attempt), options));
      validate("validate-" + attempt, attempt);
    }
    return {
      operations: operations,
      result: {
        technique: requestedTechnique,
        pattern: input.pattern || "limit_overrun",
        attempts: attempts,
        requests_per_group: raceRequests.length,
        distinct_request_shapes: raceDefinitions.length,
        control_mode: controlMode,
        setup_per_attempt: setupRequests.length,
        validation_per_attempt: validationRequests.length,
        semantic_success: !!input.success || raceDefinitions.some(function (item) { return !!item.request.success; }),
        no_fallback: requestedTechnique === "h2_single_packet" ? "The host must use one real HTTP/2 packet or return protocol_incompatible." : null
      }
    };
  }

  function byId(observations) { var output = {}; observations.forEach(function (item) { output[item.id] = item; }); return output; }
  function responses(observation) { return observation && Array.isArray(observation.responses) ? observation.responses : []; }
  function semanticSuccess(response) { return response && response.success && response.success.matched === true; }
  function isSuccess(response, input) {
    if (response && response.success && typeof response.success.matched === "boolean") return semanticSuccess(response);
    var status = Number(response && response.status_code || 0);
    if (Array.isArray(input.success_statuses) && input.success_statuses.length) return input.success_statuses.indexOf(status) !== -1;
    return status >= 200 && status < 300;
  }
  function signature(response) { return [response.status_code || 0, response.response_body_hash || "", response.response_length == null ? "" : response.response_length].join(":"); }
  function evidence(groups) {
    var ids = [];
    groups.forEach(function (group) { responses(group).forEach(function (response) { if (response.exchange_id && ids.indexOf(response.exchange_id) === -1) ids.push(response.exchange_id); }); });
    return ids.slice(0, 200);
  }
  function groupSucceeded(group, input) {
    var values = responses(group);
    return values.length > 0 && values.every(function (response) { return isSuccess(response, input); });
  }

  function analyze(input, observations) {
    var map = byId(observations), attempts = boundedInteger(input.attempts, 3, 1, 20, "attempts");
    var controlMode = input.control_mode || "single_each", control = map["control-0"];
    var maximum = boundedInteger(input.expected_max_successes, 1, 0, 100, "expected_max_successes");
    var controlSignatures = {};
    responses(control).forEach(function (response) { controlSignatures[signature(response)] = true; });
    var anomalous = [], novel = [], diagnostics = [], supporting = [];
    for (var attempt = 0; attempt < attempts; attempt += 1) {
      var race = map["race-" + attempt], setup = map["setup-" + attempt], validation = map["validate-" + attempt];
      var groupResponses = responses(race), successes = groupResponses.filter(function (response) { return isSuccess(response, input); }).length;
      var semantic = groupResponses.some(function (response) { return response && response.success && typeof response.success.matched === "boolean"; });
      var setupPassed = !setup || groupSucceeded(setup, input);
      var validationPassed = !validation || groupSucceeded(validation, input);
      var synchronized = input.technique === "parallel" || (race && race.synchronized === true);
      if (input.technique === "sequential") synchronized = false;
      var newSignatures = groupResponses.map(signature).filter(function (value) { return control && !controlSignatures[value]; });
      var qualifies = setupPassed && validationPassed && input.technique !== "sequential" && (synchronized || input.technique === "parallel");
      if (qualifies && successes > maximum) { anomalous.push(race); supporting.push(setup, validation); }
      if (qualifies && control && newSignatures.length) novel.push(race);
      var operationErrors = race && race.error ? [race.error] : [];
      diagnostics.push({ attempt: attempt, synchronized: !!synchronized, release_skew_ms: race && race.release_skew_ms, successes: successes, semantic_success_used: semantic, setup_passed: setupPassed, validation_passed: validationPassed, novel_signatures: newSignatures, errors: operationErrors.concat(groupResponses.filter(function (response) { return !!response.error; }).map(function (response) { return response.error; })) });
    }
    var findings = [], requiredRepeats = Math.min(2, attempts);
    if (anomalous.length >= requiredRepeats) {
      findings.push({
        title: "Reproducible race-condition limit overrun",
        severity: "high",
        confidence: "firm",
        explanation: "More responses matched the declared semantic success condition than the allowed maximum in multiple synchronized attempts" + (input.validation_requests ? ", and post-race validation confirmed the resulting state." : "."),
        remediation: "Make the state transition atomic and enforce the invariant in one transaction or serialized critical section.",
        evidence_exchange_ids: evidence((control ? [control] : []).concat(anomalous, supporting.filter(Boolean))),
        metadata: { pattern: input.pattern || "limit_overrun", technique: input.technique || "last_byte_sync", anomalous_attempts: anomalous.length, expected_max_successes: maximum, control_mode: controlMode }
      });
    } else if (anomalous.length > 0) {
      findings.push({
        title: "Race-condition success observed",
        severity: "medium",
        confidence: "tentative",
        explanation: "A synchronized attempt exceeded the declared semantic success maximum, but the result did not repeat enough times for firm confirmation.",
        remediation: "Make the state transition atomic and rerun bounded confirmation with fresh per-attempt state.",
        evidence_exchange_ids: evidence(anomalous.concat(supporting.filter(Boolean))),
        metadata: { pattern: input.pattern || "limit_overrun", technique: input.technique || "last_byte_sync", anomalous_attempts: anomalous.length, expected_max_successes: maximum, control_mode: controlMode }
      });
    } else if (novel.length >= requiredRepeats) {
      findings.push({
        title: "Reproducible race-only response state",
        severity: "medium",
        confidence: "tentative",
        explanation: "Multiple synchronized attempts produced response states not observed in the sequential control. Manual state validation is required.",
        remediation: "Review the affected state machine for non-atomic transitions, partial construction, and stale precondition checks.",
        evidence_exchange_ids: evidence([control].concat(novel)),
        metadata: { pattern: input.pattern || "multi_endpoint", technique: input.technique || "last_byte_sync", anomalous_attempts: novel.length, control_mode: controlMode }
      });
    }
    return { findings: findings, result: { diagnostics: diagnostics, control_mode: controlMode, control_response_count: responses(control).length, semantic_predicates_recommended: !diagnostics.some(function (item) { return item.semantic_success_used; }), synchronization: input.technique === "h2_single_packet" ? "The host negotiated ALPN h2 and released every stream's final DATA fragment in one TLS write; protocol-incompatible targets are never downgraded." : null } };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
