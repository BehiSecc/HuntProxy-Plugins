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
    var partHeaders = body.slice(headerStart, headerEnd);
    var typeMatch = /(?:^|\r\n)Content-Type:\s*([^\r\n]+)/i.exec(partHeaders);
    var fileType = typeMatch ? typeMatch[1].trim() : null;
    return { exchange: exchange, body: body, boundary: boundary, headerStart: headerStart, headerEnd: headerEnd, contentStart: headerEnd + 4, contentEnd: contentEnd, fileType: fileType };
  }
  function upperMixed(value) {
    return value.split("").map(function (character, index) { return index % 2 ? character.toUpperCase() : character.toLowerCase(); }).join("");
  }
  function variants(input, capturedType) {
    var value = marker(input), prohibited = extension(input, "prohibited_extension", "php"), allowed = extension(input, "allowed_extension", "txt");
    var text = "HuntProxy inert upload marker: " + value + "\n";
    var declaredImageType = /^image\/[A-Za-z0-9!#$&^_.+-]+(?:\s*;[^\r\n]*)?$/i.test(String(capturedType || "")) ? capturedType : "image/png";
    var list = [
      { name: "control-allowed-extension", role: "allowed-control", filename: value + "." + allowed, type: capturedType, content: text },
      { name: "control-prohibited-extension", role: "blocked-control", filename: value + "." + prohibited, type: capturedType, content: text },
      { name: "case-folded-extension", role: "filename-bypass", filename: value + "." + upperMixed(prohibited), type: capturedType, content: text },
      { name: "trailing-dot", role: "filename-bypass", filename: value + "." + prohibited + ".", type: capturedType, content: text },
      { name: "trailing-space", role: "filename-bypass", filename: value + "." + prohibited + " ", type: capturedType, content: text },
      { name: "double-extension", role: "filename-bypass", filename: value + "." + prohibited + "." + allowed, type: capturedType, content: text },
      { name: "semicolon-suffix", role: "filename-bypass", filename: value + "." + prohibited + ";." + allowed, type: capturedType, content: text },
      { name: "encoded-dot", role: "filename-bypass", filename: value + "%2e" + prohibited, type: capturedType, content: text },
      { name: "double-encoded-dot", role: "filename-bypass", filename: value + "%252e" + prohibited, type: capturedType, content: text },
      { name: "encoded-null-suffix", role: "filename-bypass", filename: value + "." + prohibited + "%00." + allowed, type: capturedType, content: text },
      { name: "encoded-slash-suffix", role: "filename-bypass", filename: value + "." + prohibited + "%2f." + allowed, type: capturedType, content: text },
      { name: "windows-ads-suffix", role: "filename-bypass", filename: value + "." + prohibited + "::$DATA." + allowed, type: capturedType, content: text },
      { name: "parent-directory", role: "path-traversal", filename: "../" + value + "." + prohibited, type: capturedType, content: text },
      { name: "encoded-parent-directory", role: "path-traversal", filename: "..%2f" + value + "." + prohibited, type: capturedType, content: text },
      { name: "declared-image-plain-text", role: "content-validation", filename: value + "." + allowed, type: declaredImageType, content: text },
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
    if (variant.type !== null && variant.type !== undefined) {
      if (/\r\nContent-Type:[^\r\n]*/i.test(headers)) headers = headers.replace(/\r\nContent-Type:[^\r\n]*/i, "\r\nContent-Type: " + variant.type);
      else headers += "\r\nContent-Type: " + variant.type;
    }
    return value.body.slice(0, value.headerStart) + headers + "\r\n\r\n" + variant.content + value.body.slice(value.contentEnd);
  }
  function operation(id, value, body) {
    return { id: id, type: "http_request", base_exchange_id: value.exchange.exchange_id, method: value.exchange.method, body_base64: encode64(body), protocol: "auto" };
  }
  function chain(input,value) {
    if(input.allow_server_config_uploads!==true) return null;
    var ext=extension(input,"server_config_extension","l33t"), filename=marker(input)+"."+ext;
    var url=String(input.safe_readback_url||"").replace(/\{filename\}/g,encodeURIComponent(filename));
    if(!/^https?:\/\/[^\s]+$/i.test(url)) throw new Error("safe_readback_url is required for the opted-in server configuration chain");
    return {extension:ext,filename:filename,url:url,mime:"application/x-huntproxy-inert"};
  }
  function plan(input, context) {
    var value = source(input, context), operations = [], list = variants(input, value.fileType), workflow=chain(input,value);
    list.forEach(function (variant, index) {
      var body = mutated(value, variant);
      for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("variant-" + index + "-" + repeat, value, body));
    });
    if(workflow){
      var config={filename:".htaccess",type:"text/plain",content:"AddType "+workflow.mime+" ."+workflow.extension+"\n"};
      var payload={filename:workflow.filename,type:"text/plain",content:"HuntProxy inert upload marker: "+marker(input)+"\n"};
      for(var setup=0;setup<2;setup+=1) operations.push(operation("server-config-"+setup,value,mutated(value,config)));
      for(var upload=0;upload<2;upload+=1) operations.push(operation("server-payload-"+upload,value,mutated(value,payload)));
      for(var read=0;read<2;read+=1) operations.push({id:"server-readback-"+read,type:"http_request",base_exchange_id:value.exchange.exchange_id,method:"GET",url:workflow.url,header_tombstones:["Content-Type","Content-Length"],body_base64:encode64(""),protocol:"auto"});
    }
    return { operations: operations, execution: workflow?"sequential":"parallel", stop_on_error:!!workflow, result: {
      variants: list.map(function (item) { return { name: item.name, role: item.role, filename: item.filename }; }),
      marker: marker(input), destructive_payloads: false, executable_payloads: false, retrieval_performed:!!workflow,
      server_config_chain: workflow?{filename:workflow.filename,declared_mime:workflow.mime,safe_readback_url:workflow.url}:null,
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
  function responseHeader(item,name) {
    return (item&&item.response_headers||[]).filter(function(header){return String(header.name).toLowerCase()===String(name).toLowerCase();}).map(function(header){return decode64(header.value_base64||"");});
  }
  function reflectedParentPath(item, variant) {
    var text=preview(item).replace(/&#x2f;|&#47;|&sol;/gi,"/");
    try { text=decodeURIComponent(text); } catch (_) {}
    var basename=variant.filename.replace(/^.*(?:\/|%2f|\\)/i,"").toLowerCase();
    return text.indexOf("../"+basename)!==-1 || text.indexOf("..\\"+basename)!==-1;
  }
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
    var map = byId(observations), list = variants(input), findings = [], outcomes = [], workflow=chain(input);
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
      if (variant.role === "path-traversal" && isAccepted && reflectedParentPath(result,variant)) {
        findings.push({
          title: "Upload path traversal sequence accepted using " + variant.name, severity: "high", confidence: "firm",
          explanation: "The upload response reproducibly reflected the inert file beneath a parent-directory path after filename decoding. This demonstrates unsafe path normalization, but does not claim that the object is executable.",
          remediation: "Discard client path components, decode once, generate server-side filenames, enforce the resolved storage root, and keep uploads outside the web root.",
          evidence_exchange_ids: [result.exchange_id].filter(Boolean),
          metadata: { variant: variant.name, role: variant.role, marker: marker(input), reflected_parent_path: true }
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
    var chainResult=null;
    if(workflow){
      var configPair=pair(map,"server-config-"), payloadPair=pair(map,"server-payload-"), readbackPair=pair(map,"server-readback-");
      var configured=accepted(configPair,input), payloadAccepted=accepted(payloadPair,input), markerReturned=!!readbackPair&&preview(readbackPair).indexOf(marker(input).toLowerCase())!==-1;
      var mimeApplied=!!readbackPair&&responseHeader(readbackPair,"content-type").some(function(value){return value.toLowerCase().split(";")[0].trim()===workflow.mime;});
      chainResult={config_accepted:configured,payload_accepted:payloadAccepted,readback_reproduced:!!readbackPair,marker_returned:markerReturned,declared_mime_applied:mimeApplied};
      if(configured&&payloadAccepted&&markerReturned&&mimeApplied) findings.push({
        title:"Upload server configuration chain applied to inert file",severity:"high",confidence:"firm",
        explanation:"The server accepted a directory configuration file, then served an inert alternate-extension upload twice with the unique configured MIME type. This proves the bounded configuration chain without uploading executable content.",
        remediation:"Reject server configuration filenames, store uploads outside interpreted directories, disable per-directory overrides, and generate server-side filenames.",
        evidence_exchange_ids:[configPair.exchange_id,payloadPair.exchange_id,readbackPair.exchange_id].filter(Boolean),
        metadata:{variant:"server-config-chain",role:"multi-stage",marker:marker(input),extension:workflow.extension,executable_payload:false}
      });
    }
    return { findings: findings, result: {
      allowed_control_accepted: !!allowedAccepted, prohibited_control_blocked: !!prohibitedBlocked, prohibited_control_accepted: !!prohibitedAccepted,
      outcomes: outcomes, server_config_chain:chainResult, tested_operations: observations.length,
      limitations: ["Acceptance does not prove that an uploaded object is web-accessible or executable; this extension never uploads executable code and does not retrieve uploads by default.", "Only the first supported multipart file part is mutated.", "Storage renaming and asynchronous malware scanning require separate read-back validation."]
    } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
