(function () {
  "use strict";
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function decode64(value) { var out = "", buffer = 0, bits = 0; String(value || "").replace(/=+$/, "").split("").forEach(function (c) { var i = alphabet.indexOf(c); if (i < 0) return; buffer = (buffer << 6) | i; bits += 6; if (bits >= 8) { bits -= 8; out += String.fromCharCode((buffer >> bits) & 255); } }); return out; }
  function encode64(value) { var out = "", i, b; for (i = 0; i < value.length; i += 3) { b = value.charCodeAt(i) << 16; if (i + 1 < value.length) b |= value.charCodeAt(i + 1) << 8; if (i + 2 < value.length) b |= value.charCodeAt(i + 2); out += alphabet[(b >> 18) & 63] + alphabet[(b >> 12) & 63] + (i + 1 < value.length ? alphabet[(b >> 6) & 63] : "=") + (i + 2 < value.length ? alphabet[b & 63] : "="); } return out; }
  function source(input, context) {
    var exchange = context.base_exchange;
    if (!exchange || !exchange.exchange_id || !exchange.identity) throw new Error("UploadAnalyzer requires identity.use access to a saved multipart request");
    if (input.allow_uploads !== true) throw new Error("upload tests create server-side state and require allow_uploads=true");
    var headers = {}, body = decode64(exchange.identity.request_body_base64 || "");
    (exchange.identity.request_headers || []).forEach(function (item) { headers[String(item.name).toLowerCase()] = decode64(item.value_base64); });
    var match = String(headers["content-type"] || "").match(/multipart\/form-data\s*;[^\r\n]*boundary=(?:"([^"]+)"|([^;\s]+))/i);
    if (!match) throw new Error("base request must use multipart/form-data with a boundary");
    if (exchange.identity.request_body_truncated) throw new Error("multipart request body is too large for safe plugin mutation");
    var boundary = match[1] || match[2], fileMatch = /filename="([^"]*)"/i.exec(body);
    if (!fileMatch) throw new Error("multipart request has no quoted filename part");
    var headerStart = body.lastIndexOf("--" + boundary, fileMatch.index), headerEnd = body.indexOf("\r\n\r\n", fileMatch.index);
    var contentEnd = body.indexOf("\r\n--" + boundary, headerEnd + 4);
    if (headerStart < 0 || headerEnd < 0 || contentEnd < 0) throw new Error("could not safely locate the first multipart file part");
    return { exchange: exchange, headers: headers, body: body, boundary: boundary, headerStart: headerStart, headerEnd: headerEnd, contentStart: headerEnd + 4, contentEnd: contentEnd, filename: fileMatch[1] };
  }
  function marker(input) { var value = String(input.marker || "huntproxy-upload"); if (!/^[a-z0-9_-]{6,40}$/i.test(value)) throw new Error("marker must be 6-40 alphanumeric, underscore, or hyphen characters"); return value; }
  function variants(input) {
    var value = marker(input), text = "HuntProxy benign upload marker: " + value + "\n";
    return [
      { name: "filename-double-extension", filename: value + ".txt.jpg", type: "text/plain", content: text },
      { name: "filename-reversed-extension", filename: value + ".jpg.txt", type: "image/jpeg", content: text },
      { name: "filename-uppercase-extension", filename: value + ".TXT", type: "text/plain", content: text },
      { name: "filename-encoded-dot", filename: value + "%2etxt", type: "text/plain", content: text },
      { name: "content-type-image-mismatch", filename: value + ".txt", type: "image/png", content: text },
      { name: "content-type-octet-stream", filename: value + ".txt", type: "application/octet-stream", content: text },
      { name: "magic-png-text", filename: value + ".txt", type: "text/plain", content: "\x89PNG\r\n\x1a\n" + text },
      { name: "magic-gif-text", filename: value + ".txt", type: "text/plain", content: "GIF89a" + text },
      { name: "magic-pdf-text", filename: value + ".txt", type: "text/plain", content: "%PDF-1.4\n% " + text },
      { name: "benign-gif-markup-polyglot", filename: value + ".gif", type: "image/gif", content: "GIF89a/*<huntproxy-marker id=\"" + value + "\">*/" }
    ].slice(0, Math.max(1, Math.min(Number(input.max_files || 10), 10)));
  }
  function mutated(source, variant) {
    var headers = source.body.slice(source.headerStart, source.headerEnd);
    headers = headers.replace(/filename="[^"]*"/i, "filename=\"" + variant.filename + "\"");
    if (/\r\nContent-Type:[^\r\n]*/i.test(headers)) headers = headers.replace(/\r\nContent-Type:[^\r\n]*/i, "\r\nContent-Type: " + variant.type);
    else headers += "\r\nContent-Type: " + variant.type;
    return source.body.slice(0, source.headerStart) + headers + "\r\n\r\n" + variant.content + source.body.slice(source.contentEnd);
  }
  function operation(id, source, body) { return { id: id, type: "http_request", base_exchange_id: source.exchange.exchange_id, method: source.exchange.method, body_base64: encode64(body), protocol: "auto" }; }
  function plan(input, context) {
    var value = source(input, context), operations = [], list = variants(input);
    for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("baseline-" + repeat, value, value.body));
    list.forEach(function (variant, index) { var body = mutated(value, variant); for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("variant-" + index + "-" + repeat, value, body)); });
    return { operations: operations, result: { variants: list.map(function (item) { return item.name; }), marker: marker(input), destructive_payloads: false } };
  }
  function byId(items) { var out = {}; items.forEach(function (item) { out[item.id] = item; }); return out; }
  function preview(item) { return String(item && item.response_preview && item.response_preview.text || "").toLowerCase(); }
  function same(a, b) { return a && b && a.status_code === b.status_code && (a.response_body_hash && b.response_body_hash ? a.response_body_hash === b.response_body_hash : a.response_length === b.response_length); }
  function pair(map, prefix) { return same(map[prefix + "0"], map[prefix + "1"]) ? map[prefix + "0"] : null; }
  function rejected(item) { return !item || item.status_code >= 400 || /invalid (file|upload)|not allowed|unsupported (file|media)|extension/.test(preview(item)); }
  function analyze(input, observations, context) {
    var map = byId(observations), baseline = pair(map, "baseline-"), findings = [], outcomes = [];
    variants(input).forEach(function (variant, index) {
      var result = pair(map, "variant-" + index + "-"), accepted = baseline && result && !rejected(result);
      outcomes.push({ variant: variant.name, reproduced: !!result, apparently_accepted: !!accepted });
      if (accepted && Math.floor(result.status_code / 100) === Math.floor(baseline.status_code / 100)) findings.push({
        title: "Upload validation accepted " + variant.name, severity: "medium", confidence: same(baseline, result) ? "firm" : "tentative",
        explanation: "A bounded, inert upload mutation was accepted reproducibly in the same response class as the original upload. This indicates inconsistent filename, declared type, or content validation; it does not by itself prove code execution.",
        remediation: "Generate server-side filenames, verify content from decoded bytes, allowlist extensions and MIME types, store outside the web root, and serve downloads with safe content headers.",
        evidence_exchange_ids: [baseline.exchange_id, result.exchange_id].filter(Boolean), metadata: { variant: variant.name, marker: marker(input) }
      });
    });
    return { findings: findings, result: { baseline_stable: !!baseline, outcomes: outcomes, tested_operations: observations.length } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
