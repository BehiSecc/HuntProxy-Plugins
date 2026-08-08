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
    if (!value || !value.exchange_id || !value.url || !value.raw_request_base64) {
      throw new Error("Request Smuggler requires a saved HTTP/1-capable exchange with raw request access");
    }
    return value;
  }
  function target(url) {
    var match = String(url).match(/^(https?):\/\/([^/?#]+)([^?#]*)(\?[^#]*)?$/);
    if (!match) throw new Error("target must be HTTP(S)");
    return { url: match[1] + "://" + match[2] + "/", authority: match[2], path: (match[3] || "/") + (match[4] || "") };
  }
  function authHeaders(exchange) {
    var raw = fromBase64(exchange.raw_request_base64), head = raw.split("\r\n\r\n", 1)[0], output = [];
    head.split("\r\n").slice(1).forEach(function (line) {
      if (/^(authorization|cookie):/i.test(line) && line.indexOf("\r") === -1 && line.indexOf("\n") === -1) output.push(line);
    });
    return output;
  }
  function message(method, path, authority, extraHeaders, body, auth, close) {
    var lines = [method + " " + path + " HTTP/1.1", "Host: " + authority, "User-Agent: HuntProxy-Request-Smuggler/1"];
    auth.forEach(function (line) { lines.push(line); });
    extraHeaders.forEach(function (line) { lines.push(line); });
    lines.push("Connection: " + (close ? "close" : "keep-alive"));
    return lines.join("\r\n") + "\r\n\r\n" + (body || "");
  }
  function options(input, pauseAt) {
    var timeout = Math.max(500, Math.min(Number(input.read_timeout_ms || 3000), 15000));
    var value = { response_mode: "until_idle", read_timeout_ms: timeout, idle_timeout_ms: 300, half_close_write: false };
    if (pauseAt != null) { value.pause_at_byte = pauseAt; value.pause_ms = Math.max(100, Math.min(Number(input.pause_ms || 1000), 10000)); }
    return value;
  }
  function techniqueSet(input, context) {
    var exchange = base(context), parsed = target(exchange.url), auth = authHeaders(exchange), token = String(input.marker).toLowerCase();
    var markerPath = parsed.path + (parsed.path.indexOf("?") === -1 ? "?" : "&") + "hp_desync=" + token;
    var smuggled = "GET " + markerPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\nConnection: close\r\n\r\n";
    var techniques = [];
    function add(family, name, request, comparison, pauseAt) { techniques.push({ family: family, name: name, request: request, comparison: comparison, pause_at: pauseAt }); }

    var clteBody = "0\r\n\r\nX";
    add("cl_te", "CL.TE terminal-byte discrepancy", message("POST", parsed.path, parsed.authority, ["Content-Length: " + clteBody.length, "Transfer-Encoding: chunked", "Content-Type: application/x-www-form-urlencoded"], clteBody, auth, false), "single");
    var teclBody = "1\r\nZ\r\n0\r\n\r\n";
    add("te_cl", "TE.CL short content length", message("POST", parsed.path, parsed.authority, ["Content-Length: 4", "Transfer-Encoding: chunked", "Content-Type: application/x-www-form-urlencoded"], teclBody, auth, false), "single");
    add("te_te", "TE.TE whitespace obfuscation", message("POST", parsed.path, parsed.authority, ["Transfer-Encoding: chunked", "Transfer-Encoding : chunked", "Content-Length: " + clteBody.length], clteBody, auth, false), "single");
    add("te_te", "TE.TE conflicting duplicate", message("POST", parsed.path, parsed.authority, ["Transfer-Encoding: x", "Transfer-Encoding: chunked", "Content-Length: " + clteBody.length], clteBody, auth, false), "single");
    add("cl_0", "CL.0 queued follow-up", message("POST", parsed.path, parsed.authority, ["Content-Length: " + smuggled.length, "Content-Type: text/plain"], smuggled, auth, false), "single");
    add("0_cl", "0.CL body on GET", message("GET", parsed.path, parsed.authority, ["Content-Length: " + smuggled.length], smuggled, auth, false), "single");
    add("parser_discrepancy", "conflicting duplicate Content-Length", message("POST", parsed.path, parsed.authority, ["Content-Length: 4", "Content-Length: 5", "Content-Type: text/plain"], "12345", auth, false), "single");
    add("parser_discrepancy", "signed Content-Length", message("POST", parsed.path, parsed.authority, ["Content-Length: +5", "Content-Type: text/plain"], "12345", auth, false), "single");
    var clientProbe = message("POST", parsed.path, parsed.authority, ["Content-Length: " + smuggled.length, "Content-Type: text/plain"], smuggled, auth, false);
    add("client_side", "keep-alive CL.0 readiness probe", clientProbe, "single");
    var first = message("GET", parsed.path, parsed.authority, [], "", auth, false);
    var follow = message("GET", markerPath, parsed.authority, [], "", auth, true);
    add("connection_state", "same-connection pipeline state", first + follow, "pipeline");
    var paused = message("POST", parsed.path, parsed.authority, ["Content-Length: 1", "Content-Type: text/plain"], "Z", auth, false);
    add("pause_based", "pause before fixed-length body", paused, "single", paused.length - 1);
    var chunked = message("POST", parsed.path, parsed.authority, ["Transfer-Encoding: chunked"], "1\r\nZ\r\n0\r\n\r\n", auth, false);
    add("pause_based", "pause before terminal chunk", chunked, "single", chunked.lastIndexOf("0\r\n\r\n"));

    var selected = input.families && input.families.length ? input.families : ["cl_te", "te_cl", "te_te", "cl_0", "0_cl", "parser_discrepancy", "client_side", "connection_state", "pause_based"];
    return techniques.filter(function (item) { return selected.indexOf(item.family) !== -1; }).slice(0, Math.max(1, Math.min(Number(input.max_techniques || 20), 20)));
  }
  function rawOperation(id, targetUrl, request, input, pauseAt) {
    return { id: id, type: "raw_http1", target_url: targetUrl, request_base64: toBase64(request), use_project_cookies: false, options: options(input, pauseAt) };
  }
  function plan(input, context) {
    if (input.confirm_intrusive !== true) throw new Error("desynchronization testing requires confirm_intrusive=true");
    if (!/^[a-z0-9]{8,32}$/i.test(String(input.marker || ""))) throw new Error("marker must be a unique 8-32 character alphanumeric value");
    var exchange = base(context), parsed = target(exchange.url), auth = authHeaders(exchange), operations = [];
    var control = message("GET", parsed.path, parsed.authority, [], "", auth, true);
    var pipeline = message("GET", parsed.path, parsed.authority, [], "", auth, false) + message("GET", parsed.path, parsed.authority, [], "", auth, true);
    for (var repeat = 0; repeat < 2; repeat += 1) {
      operations.push(rawOperation("control-single-" + repeat, parsed.url, control, input));
      operations.push(rawOperation("control-pipeline-" + repeat, parsed.url, pipeline, input));
    }
    var techniques = techniqueSet(input, context);
    techniques.forEach(function (technique, index) {
      for (var repeat = 0; repeat < 2; repeat += 1) operations.push(rawOperation("probe-" + index + "-" + repeat, parsed.url, technique.request, input, technique.pause_at));
    });
    return { operations: operations, result: { techniques: techniques.map(function (item) { return { family: item.family, name: item.name, comparison: item.comparison }; }), limitations: ["HTTP/1 only", "No malformed HTTP/2, H2 downgrade, or H2 tunneling claims", "Browser execution is required to prove a client-side desync exploit"] } };
  }
  function mapById(observations) { var map = {}; observations.forEach(function (item) { map[item.id] = item; }); return map; }
  function responseCount(item) { return item && item.raw && Array.isArray(item.raw.responses) ? item.raw.responses.length : 0; }
  function outcome(item) { return String(item && item.raw && item.raw.read_outcome || "missing"); }
  function stable(a, b) {
    if (!a || !b || outcome(a) !== outcome(b) || responseCount(a) !== responseCount(b)) return false;
    var ar = a.raw.responses || [], br = b.raw.responses || [];
    return ar.map(function (item) { return item.status_code; }).join(",") === br.map(function (item) { return item.status_code; }).join(",");
  }
  function evidence(items) { return items.map(function (item) { return item && item.raw && item.raw.exchange_id; }).filter(Boolean); }
  function analyze(input, observations, context) {
    var map = mapById(observations), techniques = techniqueSet(input, context), findings = [], diagnostics = [];
    var single = [map["control-single-0"], map["control-single-1"]], pipeline = [map["control-pipeline-0"], map["control-pipeline-1"]];
    var controlsStable = stable(single[0], single[1]) && stable(pipeline[0], pipeline[1]);
    techniques.forEach(function (technique, index) {
      var probes = [map["probe-" + index + "-0"], map["probe-" + index + "-1"]];
      var controls = technique.comparison === "pipeline" ? pipeline : single;
      var repeatedTimeout = outcome(probes[0]) === "timeout" && outcome(probes[1]) === "timeout" && outcome(controls[0]) !== "timeout" && outcome(controls[1]) !== "timeout";
      var repeatedBoundary = stable(probes[0], probes[1]) && responseCount(probes[0]) !== responseCount(controls[0]);
      diagnostics.push({ family: technique.family, technique: technique.name, outcomes: probes.map(outcome), response_counts: probes.map(responseCount), signal: repeatedTimeout ? "timeout" : repeatedBoundary ? "response_boundary" : "none" });
      if (controlsStable && (repeatedTimeout || repeatedBoundary)) {
        findings.push({
          title: "Potential HTTP request desynchronization: " + technique.name,
          severity: "high",
          confidence: "firm",
          explanation: repeatedTimeout ? "The probe repeatedly timed out while matching controls completed, indicating inconsistent message framing." : "The probe repeatedly produced a different HTTP response boundary count from matching controls.",
          remediation: "Reject ambiguous HTTP/1 framing, normalize Transfer-Encoding consistently across every hop, and avoid connection reuse after parsing errors.",
          evidence_exchange_ids: evidence(controls.concat(probes)),
          metadata: { family: technique.family, signal: repeatedTimeout ? "timeout" : "response_boundary" }
        });
      }
    });
    return { findings: findings, result: { controls_stable: controlsStable, diagnostics: diagnostics, limitations: ["These probes identify HTTP/1 parsing discrepancies; exploitability requires controlled manual validation.", "Client-side desync is readiness-only without browser execution.", "Malformed HTTP/2 and downgrade/tunneling tests are not supported by this host transport."] } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
