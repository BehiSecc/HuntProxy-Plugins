(function () {
  "use strict";

  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function decode64(value) {
    var out = "", buffer = 0, bits = 0;
    String(value || "").replace(/=+$/, "").split("").forEach(function (c) {
      var i = alphabet.indexOf(c); if (i < 0) return;
      buffer = (buffer << 6) | i; bits += 6;
      if (bits >= 8) { bits -= 8; out += String.fromCharCode((buffer >> bits) & 255); }
    });
    return out;
  }
  function encode64(value) {
    var out = "", i, b;
    for (i = 0; i < value.length; i += 3) {
      b = value.charCodeAt(i) << 16;
      if (i + 1 < value.length) b |= value.charCodeAt(i + 1) << 8;
      if (i + 2 < value.length) b |= value.charCodeAt(i + 2);
      out += alphabet[(b >> 18) & 63] + alphabet[(b >> 12) & 63]
        + (i + 1 < value.length ? alphabet[(b >> 6) & 63] : "=")
        + (i + 2 < value.length ? alphabet[b & 63] : "=");
    }
    return out;
  }
  function extension(input, key, fallback) {
    var value = String(input[key] || fallback).replace(/^\.+/, "");
    if (!/^[A-Za-z0-9]{1,12}$/.test(value)) throw new Error(key + " must contain 1-12 alphanumeric characters");
    return value;
  }
  function marker(input) {
    var value = String(input.marker || "huntproxy-upload");
    if (!/^[a-z0-9_-]{6,40}$/i.test(value)) throw new Error("marker must be 6-40 alphanumeric, underscore, or hyphen characters");
    return value;
  }
  function source(input, context) {
    var exchange = context.base_exchange;
    if (!exchange || !exchange.exchange_id || !exchange.identity) throw new Error("UploadAnalyzer requires identity.use access to a saved multipart request");
    if (input.allow_uploads !== true) throw new Error("upload tests create server-side state and require allow_uploads=true");
    var headers = {}, body = decode64(exchange.identity.request_body_base64 || "");
    (exchange.identity.request_headers || []).forEach(function (item) { headers[String(item.name).toLowerCase()] = decode64(item.value_base64); });
    var match = String(headers["content-type"] || "").match(/multipart\/form-data\s*;[^\r\n]*boundary=(?:"([^"]+)"|([^;\s]+))/i);
    if (!match) throw new Error("base request must use multipart/form-data with a boundary");
    if (exchange.identity.request_body_truncated) throw new Error("multipart request body is too large for safe plugin mutation");
    var boundary = match[1] || match[2], disposition = /content-disposition:[^\r\n]*(?:filename="([^"]*)"|filename\*=UTF-8''([^;\r\n]+))/i.exec(body);
    if (!disposition) throw new Error("multipart request has no supported filename or filename* part");
    var filenameIndex = disposition.index, headerStart = body.lastIndexOf("--" + boundary, filenameIndex), headerEnd = body.indexOf("\r\n\r\n", filenameIndex);
    var contentEnd = body.indexOf("\r\n--" + boundary, headerEnd + 4);
    if (headerStart < 0 || headerEnd < 0 || contentEnd < 0) throw new Error("could not safely locate the first multipart file part");
    return { exchange: exchange, body: body, boundary: boundary, headerStart: headerStart, headerEnd: headerEnd, contentStart: headerEnd + 4, contentEnd: contentEnd };
  }
  function upperMixed(value) {
    return value.split("").map(function (character, index) { return index % 2 ? character.toUpperCase() : character.toLowerCase(); }).join("");
  }
  function variants(input) {
    var value = marker(input), prohibited = extension(input, "prohibited_extension", "php"), allowed = extension(input, "allowed_extension", "txt");
    var text = "HuntProxy inert upload marker: " + value + "\n";
    var list = [
      { name: "control-allowed-extension", role: "allowed-control", filename: value + "." + allowed, type: "text/plain", content: text },
      { name: "control-prohibited-extension", role: "blocked-control", filename: value + "." + prohibited, type: "text/plain", content: text },
      { name: "case-folded-extension", role: "filename-bypass", filename: value + "." + upperMixed(prohibited), type: "text/plain", content: text },
      { name: "trailing-dot", role: "filename-bypass", filename: value + "." + prohibited + ".", type: "text/plain", content: text },
      { name: "trailing-space", role: "filename-bypass", filename: value + "." + prohibited + " ", type: "text/plain", content: text },
      { name: "double-extension", role: "filename-bypass", filename: value + "." + prohibited + "." + allowed, type: "text/plain", content: text },
      { name: "semicolon-suffix", role: "filename-bypass", filename: value + "." + prohibited + ";." + allowed, type: "text/plain", content: text },
      { name: "encoded-dot", role: "filename-bypass", filename: value + "%2e" + prohibited, type: "text/plain", content: text },
      { name: "double-encoded-dot", role: "filename-bypass", filename: value + "%252e" + prohibited, type: "text/plain", content: text },
      { name: "encoded-null-suffix", role: "filename-bypass", filename: value + "." + prohibited + "%00." + allowed, type: "text/plain", content: text },
      { name: "encoded-slash-suffix", role: "filename-bypass", filename: value + "." + prohibited + "%2f." + allowed, type: "text/plain", content: text },
      { name: "windows-ads-suffix", role: "filename-bypass", filename: value + "." + prohibited + "::$DATA." + allowed, type: "text/plain", content: text },
      { name: "declared-image-plain-text", role: "content-validation", filename: value + "." + allowed, type: "image/png", content: text },
      { name: "octet-stream-plain-text", role: "content-validation", filename: value + "." + allowed, type: "application/octet-stream", content: text },
      { name: "png-signature-text", role: "content-validation", filename: value + "." + allowed, type: "text/plain", content: "\x89PNG\r\n\x1a\n" + text },
      { name: "gif-signature-text", role: "content-validation", filename: value + "." + allowed, type: "text/plain", content: "GIF89a" + text },
      { name: "pdf-signature-text", role: "content-validation", filename: value + "." + allowed, type: "text/plain", content: "%PDF-1.4\n% " + text }
    ];
    var maximum = Math.max(2, Math.min(Number(input.max_files || list.length), list.length));
    return list.slice(0, maximum);
  }
  function mutated(value, variant) {
    var headers = value.body.slice(value.headerStart, value.headerEnd);
    if (/filename="[^"]*"/i.test(headers)) headers = headers.replace(/filename="[^"]*"/i, "filename=\"" + variant.filename.replace(/["\r\n]/g, "") + "\"");
    else headers = headers.replace(/filename\*=UTF-8''[^;\r\n]+/i, "filename*=UTF-8''" + variant.filename);
    if (/\r\nContent-Type:[^\r\n]*/i.test(headers)) headers = headers.replace(/\r\nContent-Type:[^\r\n]*/i, "\r\nContent-Type: " + variant.type);
    else headers += "\r\nContent-Type: " + variant.type;
    return value.body.slice(0, value.headerStart) + headers + "\r\n\r\n" + variant.content + value.body.slice(value.contentEnd);
  }
  function operation(id, value, body) {
    return { id: id, type: "http_request", base_exchange_id: value.exchange.exchange_id, method: value.exchange.method, body_base64: encode64(body), protocol: "auto" };
  }
  function plan(input, context) {
    var value = source(input, context), operations = [], list = variants(input);
    list.forEach(function (variant, index) {
      var body = mutated(value, variant);
      for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("variant-" + index + "-" + repeat, value, body));
    });
    return { operations: operations, result: {
      variants: list.map(function (item) { return { name: item.name, role: item.role, filename: item.filename }; }),
      marker: marker(input), destructive_payloads: false, executable_payloads: false, retrieval_performed: false,
      comparison_model: "allowed control versus prohibited control versus normalization variants"
    } };
  }
  function byId(items) { var out = {}; items.forEach(function (item) { out[item.id] = item; }); return out; }
  function preview(item) { return String(item && item.response_preview && item.response_preview.text || "").toLowerCase(); }
  function normalized(item) {
    return preview(item).replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "<uuid>").replace(/[a-z0-9_-]{24,}/gi, "<opaque>").replace(/\b\d+\b/g, "<n>").replace(/\s+/g, " ").trim();
  }
  function similarity(a, b) {
    if (!a || !b || a.status_code !== b.status_code) return 0;
    if (a.response_body_hash && b.response_body_hash && a.response_body_hash === b.response_body_hash) return 1;
    var left = normalized(a), right = normalized(b);
    if (left === right) return 1;
    if (!left || !right) return a.response_length === b.response_length ? 0.95 : 0;
    var la = {}, lb = {}, union = {}, intersection = 0, total = 0;
    left.split(/[^a-z0-9_<>-]+/).filter(Boolean).forEach(function (word) { la[word] = true; union[word] = true; });
    right.split(/[^a-z0-9_<>-]+/).filter(Boolean).forEach(function (word) { lb[word] = true; union[word] = true; });
    Object.keys(union).forEach(function (word) { total += 1; if (la[word] && lb[word]) intersection += 1; });
    return total ? intersection / total : 0;
  }
  function pair(map, prefix) {
    var first = map[prefix + "0"], second = map[prefix + "1"];
    if (!first || !second || first.error || second.error) return null;
    return similarity(first, second) >= 0.9 ? first : null;
  }
  function includesMarker(item, markers) { var text = preview(item); return (markers || []).some(function (marker) { return text.indexOf(String(marker).toLowerCase()) !== -1; }); }
  function rejected(item, input) {
    return !item || item.error || item.status_code >= 400
      || /invalid (?:file|upload|filename)|not allowed|unsupported (?:file|media)|prohibited|blocked|extension denied|upload failed/.test(preview(item))
      || includesMarker(item, input.failure_markers);
  }
  function accepted(item, input) {
    if (rejected(item, input) || item.status_code < 200 || item.status_code >= 400) return false;
    return !(input.success_markers && input.success_markers.length) || includesMarker(item, input.success_markers);
  }
  function analyze(input, observations) {
    var map = byId(observations), list = variants(input), findings = [], outcomes = [];
    var allowedIndex = list.map(function (item) { return item.role; }).indexOf("allowed-control");
    var blockedIndex = list.map(function (item) { return item.role; }).indexOf("blocked-control");
    var allowed = allowedIndex >= 0 ? pair(map, "variant-" + allowedIndex + "-") : null;
    var prohibited = blockedIndex >= 0 ? pair(map, "variant-" + blockedIndex + "-") : null;
    var allowedAccepted = accepted(allowed, input), prohibitedBlocked = !!prohibited && rejected(prohibited, input), prohibitedAccepted = accepted(prohibited, input);
    list.forEach(function (variant, index) {
      var result = pair(map, "variant-" + index + "-"), isAccepted = accepted(result, input), score = allowed && result ? similarity(allowed, result) : 0;
      outcomes.push({ variant: variant.name, role: variant.role, reproduced: !!result, apparently_accepted: !!isAccepted, allowed_similarity: Math.round(score * 1000) / 1000, error: result ? null : "unstable_or_failed" });
      if (variant.role === "filename-bypass" && allowedAccepted && prohibitedBlocked && isAccepted && (score >= 0.82 || includesMarker(result, input.success_markers))) {
        findings.push({
          title: "Upload filename restriction bypass using " + variant.name, severity: "high", confidence: score >= 0.9 ? "firm" : "tentative",
          explanation: "The direct prohibited-extension control was rejected, while this inert filename-normalization variant was accepted reproducibly with an outcome consistent with the allowed control.",
          remediation: "Decode and normalize filenames once, generate server-side names, apply an extension allowlist after normalization, and store uploads outside the web root.",
          evidence_exchange_ids: [allowed.exchange_id, prohibited.exchange_id, result.exchange_id].filter(Boolean),
          metadata: { variant: variant.name, role: variant.role, marker: marker(input), prohibited_extension: extension(input, "prohibited_extension", "php"), allowed_similarity: Math.round(score * 1000) / 1000 }
        });
      }
      if (variant.role === "content-validation" && input.expect_content_validation === true && allowedAccepted && isAccepted && (score >= 0.82 || includesMarker(result, input.success_markers))) {
        findings.push({
          title: "Upload content validation accepted " + variant.name, severity: "medium", confidence: score >= 0.9 ? "firm" : "tentative",
          explanation: "The caller asserted that content validation is expected, but this inert declared-type or signature mismatch was accepted reproducibly.",
          remediation: "Validate decoded file bytes against the permitted format and serve stored objects with safe content headers.",
          evidence_exchange_ids: [allowed.exchange_id, result.exchange_id].filter(Boolean), metadata: { variant: variant.name, role: variant.role, marker: marker(input) }
        });
      }
    });
    if (allowedAccepted && prohibitedAccepted) findings.push({
      title: "Direct prohibited upload extension accepted", severity: "medium", confidence: similarity(allowed, prohibited) >= 0.9 ? "firm" : "tentative",
      explanation: "The caller-designated prohibited extension was accepted directly with inert text content. This indicates a missing or ineffective filename-extension restriction, but does not prove executability or public retrieval.",
      remediation: "Apply a normalized extension allowlist, generate server-side filenames, and store uploads outside the web root.",
      evidence_exchange_ids: [allowed.exchange_id, prohibited.exchange_id].filter(Boolean), metadata: { variant: "control-prohibited-extension", marker: marker(input), prohibited_extension: extension(input, "prohibited_extension", "php") }
    });
    return { findings: findings, result: {
      allowed_control_accepted: !!allowedAccepted, prohibited_control_blocked: !!prohibitedBlocked, prohibited_control_accepted: !!prohibitedAccepted,
      outcomes: outcomes, tested_operations: observations.length,
      limitations: ["Acceptance does not prove that an uploaded object is web-accessible or executable; this extension never uploads executable code and does not retrieve uploads by default.", "Only the first supported multipart file part is mutated.", "Storage renaming and asynchronous malware scanning require separate read-back validation."]
    } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
