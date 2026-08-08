(function () {
  "use strict";

  function exchangeIds(input, context) {
    var ids = Array.isArray(input.exchange_ids) && input.exchange_ids.length ? input.exchange_ids.slice() : [];
    if (!ids.length && context.base_exchange && context.base_exchange.exchange_id) ids.push(context.base_exchange.exchange_id);
    ids = ids.filter(function (id, index) { return Number.isInteger(id) && id > 0 && ids.indexOf(id) === index; });
    if (!ids.length) throw new Error("Racer requires a base exchange or exchange_ids");
    if (ids.length > 20) throw new Error("Racer supports at most 20 request shapes");
    return ids;
  }

  function requests(input, context) {
    var ids = exchangeIds(input, context);
    var copies = input.copies == null ? (ids.length === 1 ? 20 : 1) : Math.max(1, Math.min(Number(input.copies), 100));
    var output = [];
    ids.forEach(function (exchangeId, shape) {
      for (var copy = 0; copy < copies; copy += 1) output.push({ id: "shape-" + shape + "-copy-" + copy, base_exchange_id: exchangeId });
    });
    if (output.length > 100) throw new Error("race group exceeds 100 requests; lower copies or exchange_ids");
    return output;
  }

  function plan(input, context) {
    if (input.allow_state_changes !== true) throw new Error("race testing requires allow_state_changes=true");
    var technique = input.technique || "last_byte_sync";
    if (["parallel", "last_byte_sync", "h2_single_packet"].indexOf(technique) === -1) throw new Error("unsupported race technique");
    var attempts = Math.max(2, Math.min(Number(input.attempts || 3), 20));
    var groupRequests = requests(input, context), timeout = Math.max(1000, Math.min(Number(input.timeout_ms || 30000), 120000));
    var options = { timeout_ms: timeout, hold_timeout_ms: Math.max(100, Math.min(Number(input.hold_timeout_ms || 5000), 15000)) };
    var operations = [{ id: "control-0", type: "race_group", technique: "sequential_control", attempt: 0, requests: groupRequests, options: options }];
    for (var attempt = 0; attempt < attempts; attempt += 1) {
      operations.push({ id: "race-" + attempt, type: "race_group", technique: technique, attempt: attempt, requests: groupRequests, options: options });
    }
    return {
      operations: operations,
      result: {
        technique: technique,
        pattern: input.pattern || "limit_overrun",
        attempts: attempts,
        requests_per_group: groupRequests.length,
        no_fallback: technique === "h2_single_packet" ? "The host must use one real HTTP/2 packet or return protocol_incompatible." : null
      }
    };
  }

  function byId(observations) { var output = {}; observations.forEach(function (item) { output[item.id] = item; }); return output; }
  function responses(observation) { return observation && Array.isArray(observation.responses) ? observation.responses : []; }
  function isSuccess(response, input) {
    var status = Number(response.status_code || 0);
    if (Array.isArray(input.success_statuses) && input.success_statuses.length) return input.success_statuses.indexOf(status) !== -1;
    return status >= 200 && status < 300;
  }
  function signature(response) { return [response.status_code || 0, response.response_body_hash || "", response.response_length == null ? "" : response.response_length].join(":"); }
  function evidence(groups) {
    var ids = [];
    groups.forEach(function (group) { responses(group).forEach(function (response) { if (response.exchange_id && ids.indexOf(response.exchange_id) === -1) ids.push(response.exchange_id); }); });
    return ids.slice(0, 200);
  }

  function analyze(input, observations) {
    var map = byId(observations), control = map["control-0"], attempts = Math.max(2, Math.min(Number(input.attempts || 3), 20));
    if (!control) return { findings: [], result: { error: "sequential control observation missing" } };
    var maximum = Math.max(0, Math.min(Number(input.expected_max_successes == null ? 1 : input.expected_max_successes), 100));
    var controlSignatures = {};
    responses(control).forEach(function (response) { controlSignatures[signature(response)] = true; });
    var anomalous = [], novel = [], diagnostics = [];
    for (var attempt = 0; attempt < attempts; attempt += 1) {
      var group = map["race-" + attempt], groupResponses = responses(group);
      var successes = groupResponses.filter(function (response) { return isSuccess(response, input); }).length;
      var synchronized = input.technique === "parallel" || (group && group.synchronized === true);
      var newSignatures = groupResponses.map(signature).filter(function (value) { return !controlSignatures[value]; });
      if (synchronized && successes > maximum) anomalous.push(group);
      if (synchronized && newSignatures.length) novel.push(group);
      diagnostics.push({ attempt: attempt, synchronized: !!synchronized, release_skew_ms: group && group.release_skew_ms, successes: successes, novel_signatures: newSignatures });
    }
    var findings = [], requiredRepeats = Math.min(2, attempts);
    if (anomalous.length >= requiredRepeats) {
      findings.push({
        title: "Reproducible race-condition limit overrun",
        severity: "high",
        confidence: "firm",
        explanation: "More successful operations than the declared safe maximum occurred in multiple synchronized attempts, unlike the sequential control.",
        remediation: "Make the state transition atomic and enforce the invariant in one transaction or serialized critical section.",
        evidence_exchange_ids: evidence([control].concat(anomalous)),
        metadata: { pattern: input.pattern || "limit_overrun", technique: input.technique || "last_byte_sync", anomalous_attempts: anomalous.length, expected_max_successes: maximum }
      });
    } else if (novel.length >= requiredRepeats) {
      findings.push({
        title: "Reproducible race-only response state",
        severity: "medium",
        confidence: "tentative",
        explanation: "Multiple synchronized attempts produced response states not observed in the sequential control. Manual state validation is required.",
        remediation: "Review the affected state machine for non-atomic transitions, partial construction, and stale precondition checks.",
        evidence_exchange_ids: evidence([control].concat(novel)),
        metadata: { pattern: input.pattern || "multi_endpoint", technique: input.technique || "last_byte_sync", anomalous_attempts: novel.length }
      });
    }
    return { findings: findings, result: { diagnostics: diagnostics, control_response_count: responses(control).length, host_blocker: input.technique === "h2_single_packet" ? "Requires host support for releasing final HTTP/2 DATA bytes in one real TCP packet; fallback is forbidden." : null } };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
