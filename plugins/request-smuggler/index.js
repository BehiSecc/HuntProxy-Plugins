(function () {
  "use strict";

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function fromBase64(value) {
    value=String(value||"").replace(/\s+/g,"");var bytes=new Uint8Array(base64Length(value)),written=0;
    for(var offset=0;offset<value.length;offset+=4){
      var a=B64.indexOf(value.charAt(offset)),b=B64.indexOf(value.charAt(offset+1)),c=B64.indexOf(value.charAt(offset+2)),d=B64.indexOf(value.charAt(offset+3));
      if(a<0||b<0)break;bytes[written++]=(a<<2)|(b>>4);
      if(c>=0)bytes[written++]=((b&15)<<4)|(c>>2);
      if(d>=0)bytes[written++]=((c&3)<<6)|d;
    }
    var output="";for(var start=0;start<written;start+=8192)output+=String.fromCharCode.apply(null,bytes.subarray(start,Math.min(written,start+8192)));
    return output;
  }
  function base64Length(value){value=String(value||"").replace(/\s+/g,"");if(!value)return 0;var padding=/==$/.test(value)?2:/=$/.test(value)?1:0;return Math.max(0,Math.floor(value.length*3/4)-padding);}
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
  function zeroCl(parsed, path, canaryPath, inherited, marker, variant, offset) {
    var chopped = "GET " + path + " HTTP/1.1\r\nX: y";
    var revealed = "GET " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\nX-HuntProxy-Desync: " + marker + "\r\nConnection: close\r\n\r\n";
    var hiddenLength = chopped.length + offset;
    return {
      early: message("GET", path, parsed.authority, inherited, variant.lines(hiddenLength).concat(["X-HuntProxy-Desync: " + marker]), "", false),
      victim: chopped + revealed,
      offset: offset
    };
  }
  function zeroClVariants() {
    return [
      { name: "space before colon", lines: function (value) { return ["Content-Length : " + value]; } },
      { name: "wrapped value", lines: function (value) { return ["Content-Length:\r\n " + value]; } },
      { name: "tab before colon", lines: function (value) { return ["Content-Length\t: " + value]; } },
      { name: "leading whitespace", lines: function (value) { return ["X-Junk: x", " Content-Length: " + value]; } },
      { name: "hop-by-hop", lines: function (value) { return ["Content-Length: " + value, "Connection: Content-Length"]; } },
      { name: "hidden hop-by-hop", lines: function (value) { return ["Content-Length: " + value, "Connection : Content-Length"]; } },
      { name: "duplicate", lines: function (value) { return ["Content-Length: " + value, "Content-Length: " + value]; } },
      { name: "underscore", lines: function (value) { return ["Content_Length: " + value]; } },
      { name: "LF name wrap", lines: function (value) { return ["X-Junk: x\nContent-Length: " + value]; } },
      { name: "CR name wrap", lines: function (value) { return ["X-Junk: x\rContent-Length: " + value]; } }
    ];
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
  function h2Probe(parsed, path, canaryPath, inherited, marker, variant, tunnelPath, tunnelOuterPath) {
    var prefix = "GET " + canaryPath + " HTTP/1.1\r\nX-HuntProxy-Desync: " + marker;
    if (variant === "h2_cl") return { headers: h2Headers(parsed, "POST", path, inherited, [{ name: "content-length", value: "0" }]), body: prefix };
    if (variant === "h2_te") return { headers: h2Headers(parsed, "POST", path, inherited, [{ name: "transfer-encoding", value: "chunked" }]), body: "0\r\n\r\n" + prefix };
    if (variant === "h2_crlf") return { headers: h2Headers(parsed, "POST", path, inherited, [{ name: "x-huntproxy", value: "probe\r\nTransfer-Encoding: chunked" }]), body: "0\r\n\r\n" + prefix };
    if (variant === "h2_split") return { headers: h2Headers(parsed, "GET", path, inherited, [{ name: "x-huntproxy", value: "probe\r\n\r\nGET " + canaryPath + " HTTP/1.1\r\nHost: " + parsed.authority }]), body: "" };
    if (variant === "h2_tunnel_name") return { headers: h2Headers(parsed, "HEAD", tunnelOuterPath, inherited, [{ name: "x: y\r\n\r\nGET " + tunnelPath + " HTTP/1.1\r\nHost", value: parsed.authority + "\r\nX-HuntProxy-Desync: " + marker + "\r\n\r\n" }]), body: "" };
    if (variant === "h2_header_name_host") return { headers: h2Headers(parsed,"GET",path,inherited,[{name:"foo: bar\r\nHost: "+marker+"."+parsed.authority,value:"xyz"}]),body:"" };
    return { headers: [
      { name: ":method", value: "HEAD" },
      { name: ":scheme", value: "https" },
      { name: ":authority", value: parsed.authority },
      { name: ":path", value: tunnelOuterPath + " HTTP/1.1\r\nHost: " + parsed.authority + "\r\n\r\nGET " + tunnelPath + " HTTP/1.1\r\nX-HuntProxy-Desync: " + marker }
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
    var tunnelPath=safePath(input.tunnel_path||path,"tunnel_path"),tunnelOuterPath=safePath(input.tunnel_outer_path||"/login","tunnel_outer_path");
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
    var zeroVariants = zeroClVariants(), zeroOffsets = Array.isArray(input.zero_cl_offsets) && input.zero_cl_offsets.length ? input.zero_cl_offsets : [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
    zeroOffsets = zeroOffsets.map(function (value) { value = Number(value); if (!Number.isInteger(value) || value < 0 || value > 64) throw new Error("zero_cl_offsets must contain integers from 0 to 64"); return value; }).filter(function (value, index, values) { return values.indexOf(value) === index; });
    add("0_cl", "0.CL " + zeroVariants[0].name + " offset " + zeroOffsets[0], zeroCl(parsed, path, canaryPath, inherited, marker, zeroVariants[0], zeroOffsets[0]), true, "0_cl", "zero_cl_pair");
    var connectionHost = String(input.connection_state_host || (marker + "." + parsed.authority));
    if (!connectionHost || /[\r\n\s]/.test(connectionHost) || connectionHost.length > 255) throw new Error("connection_state_host must be a CRLF-free Host value");
    var connectionPath = safePath(input.connection_state_path || path, "connection_state_path");
    add("connection_state", "second-request Host validation", withHost(connectionPath, parsed, inherited, connectionHost, true), true, "connection_state", "connection_state");
    add("h2_cl", "H2.CL downgrade", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_cl",tunnelPath,tunnelOuterPath), true, "h2_cl", "h2");
    add("h2_te", "H2.TE downgrade / response queue", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_te",tunnelPath,tunnelOuterPath), true, "h2_te", "h2");
    add("h2_crlf", "H2 CRLF Transfer-Encoding injection", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_crlf",tunnelPath,tunnelOuterPath), true, "h2_te", "h2");
    add("h2_split", "H2 CRLF request splitting", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_split",tunnelPath,tunnelOuterPath), true, "h2_split", "h2");
    add("h2_tunnel", "H2 header-name request tunnelling", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_tunnel_name",tunnelPath,tunnelOuterPath), false, "h2_tunnel", "h2_tunnel");
    add("h2_tunnel", "H2 pseudo-path request tunnelling", h2Probe(parsed, path, canaryPath, inherited, marker, "h2_tunnel_path",tunnelPath,tunnelOuterPath), false, "h2_tunnel", "h2_tunnel");
    add("h2_tunnel", "H2 header-name Host injection", h2Probe(parsed,path,canaryPath,inherited,marker,"h2_header_name_host",tunnelPath,tunnelOuterPath),false,"h2_tunnel","h2_header_injection");
    add("pause", "server-side pause-based CL.0", pauseProbe(parsed,path,canaryPath,inherited,marker), true, "pause", "pause");
    add("parser_discrepancy", "conflicting duplicate Content-Length", message("POST", path, parsed.authority, inherited, ["Content-Length: 4", "Content-Length: 5", "Content-Type: text/plain"], "12345", false) + normalGet(path, parsed, inherited, true), false);
    add("parser_discrepancy", "signed Content-Length", message("POST", path, parsed.authority, inherited, ["Content-Length: +5", "Content-Type: text/plain"], "12345", false) + normalGet(path, parsed, inherited, true), false);
    zeroOffsets.slice(1).forEach(function (offset) {
      add("0_cl", "0.CL " + zeroVariants[0].name + " offset " + offset, zeroCl(parsed, path, canaryPath, inherited, marker, zeroVariants[0], offset), true, "0_cl", "zero_cl_pair");
    });
    zeroVariants.slice(1).forEach(function (variant) {
      add("0_cl", "0.CL " + variant.name + " offset " + zeroOffsets[0], zeroCl(parsed, path, canaryPath, inherited, marker, variant, zeroOffsets[0]), true, "0_cl", "zero_cl_pair");
    });
    var selected = input.families && input.families.length ? input.families : ["cl_te", "te_cl", "te_te", "cl_0", "0_cl", "connection_state", "h2_cl", "h2_te", "h2_crlf", "h2_split", "h2_tunnel", "parser_discrepancy"];
    return { parsed: parsed, inherited: inherited, path: path, canary_path: canaryPath, connection_host: connectionHost, connection_path: connectionPath, items: items.filter(function (item) { return selected.indexOf(item.family) !== -1; }).slice(0, Math.max(1, Math.min(Number(input.max_techniques || 30), 30))) };
  }
  function options(input) {
    return { response_mode: "until_idle", read_timeout_ms: Math.max(1000, Math.min(Number(input.read_timeout_ms || 8000), 30000)), idle_timeout_ms: Math.max(500, Math.min(Number(input.idle_timeout_ms || 1500), 5000)), half_close_write: false };
  }
  function raw(id, parsed, request, input) { return { id: id, type: "raw_http1", target_url: parsed.url, request_base64: toBase64(request), use_project_cookies: false, options: options(input) }; }
  function rawGroup(id, parsed, members, input) { return { id: id, type: "raw_http1_group", target_url: parsed.url, members: members.map(function (member) { return { id: member.id, request_base64: toBase64(member.request), use_project_cookies: false, options: member.options || options(input) }; }) }; }
  function delayedZeroClOptions(input) { var value = options(input); value.pause_at_byte = 1; value.pause_ms = Math.max(1, Math.min(Number(input.zero_cl_delay_ms || 50), 1000)); value.await_response_before_continue = false; return value; }
  function rawH2(id, parsed, request, input) { return { id: id, type: "raw_http2", target_url: parsed.url, streams: [{ id: id + "-stream", headers: request.headers, body_text: request.body }], options: { timeout_ms: Math.max(1000, Math.min(Number(input.read_timeout_ms || 8000), 30000)), final_data_together: false } }; }
  function isH2Mode(mode){return mode==="h2"||mode==="h2_tunnel"||mode==="h2_header_injection";}
  function rawPause(id,parsed,request,input){return {id:id,type:"raw_http1",target_url:parsed.url,request_base64:toBase64(request.bytes),use_project_cookies:false,options:{pause_at_byte:request.split,pause_ms:Math.max(1,Math.min(Number(input.pause_ms||61000),120000)),await_response_before_continue:input.pause_await_response===true,half_close_write:false,response_mode:"until_idle",read_timeout_ms:Math.max(1000,Math.min(Number(input.read_timeout_ms||30000),120000)),idle_timeout_ms:Math.max(500,Math.min(Number(input.idle_timeout_ms||1500),5000))}};}
  function plan(input, context) {
    if (input.confirm_intrusive !== true) throw new Error("desynchronization testing requires confirm_intrusive=true");
    if (!/^[a-z0-9]{8,32}$/i.test(String(input.marker || ""))) throw new Error("marker must be a unique 8-32 character alphanumeric value");
    var set = techniques(input, context), repeats = Math.max(3, Math.min(Number(input.repeats || 5), 9)), operations = [];
    for (var direct = 0; direct < 2; direct += 1) {
      operations.push(raw("direct-base-" + direct, set.parsed, normalGet(set.path, set.parsed, set.inherited, true), input));
      operations.push(raw("direct-canary-" + direct, set.parsed, normalGet(set.canary_path, set.parsed, set.inherited, true), input));
    }
    if (set.items.some(function (item) { return isH2Mode(item.mode); })) {
      for (var h2Direct = 0; h2Direct < 2; h2Direct += 1) {
        operations.push(rawH2("h2-direct-base-" + h2Direct, set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
        operations.push(rawH2("h2-direct-canary-" + h2Direct, set.parsed, { headers: h2Headers(set.parsed, "GET", set.canary_path, set.inherited), body: "" }, input));
      }
    }
    // Establish every clean baseline before any ambiguous request can taint a
    // reused upstream pool. Post-probe observations are separate requests and
    // are never recycled as controls for a later cycle.
    set.items.forEach(function (technique, index) {
      for (var controlRepeat = 0; controlRepeat < repeats; controlRepeat += 1) {
        if (technique.mode === "zero_cl_pair") operations.push(raw("control-" + index + "-" + controlRepeat, set.parsed, technique.request.victim, input));
        else if (isH2Mode(technique.mode)) operations.push(rawH2("control-" + index + "-" + controlRepeat, set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
        else operations.push(raw("control-" + index + "-" + controlRepeat, set.parsed, technique.mode === "connection_state" ? technique.request : normalGet(set.path, set.parsed, set.inherited, true), input));
      }
    });
    set.items.forEach(function (technique, index) {
      if (technique.mode === "zero_cl_pair") {
        var zeroControl = technique.request.victim, zeroClean = normalGet(set.path, set.parsed, set.inherited, true), observerCount = Math.max(1, Math.min(Number(input.zero_cl_observers || 2), 5));
        for (var zeroRepeat = 0; zeroRepeat < repeats; zeroRepeat += 1) {
          operations.push(rawGroup("pair-" + index + "-" + zeroRepeat, set.parsed, [
            { id: "probe-" + index + "-" + zeroRepeat, request: technique.request.early },
            { id: "victim-" + index + "-" + zeroRepeat, request: zeroControl, options: delayedZeroClOptions(input) }
          ], input));
          for (var observer = 0; observer < observerCount; observer += 1) operations.push(raw("observer-" + index + "-" + zeroRepeat + "-" + observer, set.parsed, zeroClean, input));
        }
        return;
      }
      for (var repeat = 0; repeat < repeats; repeat += 1) {
        var clean = normalGet(set.path, set.parsed, set.inherited, true), probe = technique.request;
        if (technique.mode === "connection_state") {
          probe = normalGet(set.path, set.parsed, set.inherited, false) + withHost(set.connection_path, set.parsed, set.inherited, set.connection_host, true);
        }
        if(technique.mode==="pause"){
          operations.push(rawPause("probe-"+index+"-"+repeat,set.parsed,probe,input));
          operations.push(raw("observer-"+index+"-"+repeat+"-0",set.parsed,clean,input));
          operations.push(raw("observer-"+index+"-"+repeat+"-1",set.parsed,clean,input));
        } else if (isH2Mode(technique.mode)) {
          operations.push(rawH2("probe-" + index + "-" + repeat, set.parsed, probe, input));
          operations.push(rawH2("observer-" + index + "-" + repeat + "-0", set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
          operations.push(rawH2("observer-" + index + "-" + repeat + "-1", set.parsed, { headers: h2Headers(set.parsed, "GET", set.path, set.inherited), body: "" }, input));
        } else {
          operations.push(raw("probe-" + index + "-" + repeat, set.parsed, probe, input));
          operations.push(raw("observer-" + index + "-" + repeat + "-0", set.parsed, clean, input));
          operations.push(raw("observer-" + index + "-" + repeat + "-1", set.parsed, clean, input));
        }
      }
    });
    var requestCount = operations.reduce(function (count, operation) { return count + (operation.type === "raw_http1_group" ? operation.members.length : operation.type === "raw_http2" ? operation.streams.length : 1); }, 0);
    return { execution: "sequential", operations: operations, result: { repeats: repeats, auth_included: input.include_auth === true, canary_path: set.canary_path, request_count: requestCount, techniques: set.items.map(function (item) { return { family: item.family, name: item.name, polarity: item.polarity, canary_confirmation: item.confirmable }; }), limitations: ["HTTP/2 families require HTTPS with ALPN h2 and never fall back to HTTP/1", "Pause-based probing is opt-in because each cycle may hold a connection for up to pause_ms", "Browser client-side desync requires a direct real-browser workflow and is not currently confirmed by this plugin", "Authentication is excluded unless include_auth=true"] } };
  }
  function byId(observations) { var output = {}; observations.forEach(function (item) { output[item.id] = item; if (Array.isArray(item.members)) item.members.forEach(function (member) { output[member.id] = member; }); }); return output; }
  function rawResult(item) { return item && !item.error && item.raw ? item.raw : null; }
  function h2StreamUsable(item, stream) {
    return !!(item && stream && !item.error && item.protocol === "h2" && !item.timed_out && !item.goaway && !stream.reset && stream.status_code != null && stream.complete !== false && stream.truncated !== true && stream.response_body_truncated !== true);
  }
  function hasResult(item) {
    if (rawResult(item)) return true;
    return !!(item && Array.isArray(item.streams) && item.streams.some(function (stream) { return h2StreamUsable(item, stream); }));
  }
  function outcome(item) {
    var value = rawResult(item); if (value) return String(value.read_outcome || "missing");
    if (!item || item.error || !Array.isArray(item.streams) || item.protocol !== "h2") return "error";
    if (item.timed_out) return "timeout";
    if (item.goaway) return "goaway";
    if (item.streams.some(function (stream) { return !!stream.reset; })) return "reset";
    if (item.streams.length && item.streams.every(function (stream) { return h2StreamUsable(item, stream); })) return "complete";
    return "incomplete";
  }
  function transcript(item) { var value = rawResult(item); return value ? fromBase64(value.response_transcript_base64 || value.response_base64 || "") : ""; }
  var segmentMemo=null,transcriptMemo=null,markerMemo=null;
  function segments(item) {
    var key=item&&item.id;if(segmentMemo&&key&&Object.prototype.hasOwnProperty.call(segmentMemo,key))return segmentMemo[key];
    var output;
    if (item && Array.isArray(item.streams)) output=item.streams.map(function (stream) { var encoded=String(stream.response_body_base64||""),location="",contentType="";(stream.response_headers||[]).forEach(function(header){var name=String(header.name||"").toLowerCase(),value=header.value_base64?fromBase64(header.value_base64):String(header.value||"");if(name==="location")location=value;else if(name==="content-type")contentType=value;});return { status: stream.status_code == null ? null : Number(stream.status_code), text: fromBase64(encoded.slice(0,87384)), hash:stream.response_body_hash||"", length:stream.response_length==null?0:Number(stream.response_length), protocol:"h2", location:location, contentType:contentType, complete:stream.complete!==false, reset:stream.reset||null, truncated:stream.truncated===true||stream.response_body_truncated===true, usable:h2StreamUsable(item,stream) }; });
    else { var value = rawResult(item),encoded=value?String(value.response_transcript_base64||value.response_base64||""):"",available=base64Length(encoded);output=value?(value.responses || []).map(function (response) { var evidenceTruncated=response.offset+response.length>available;return { status: response.status_code == null ? null : Number(response.status_code), text: null, source:item, offset:response.offset, length:response.length, protocol:"h1", complete:true, reset:null, truncated:evidenceTruncated, usable:response.status_code!=null&&!evidenceTruncated }; }):[]; }
    if(segmentMemo&&key)segmentMemo[key]=output;return output;
  }
  function normalized(value) { value = String(value || ""); if (value.length > 32768) value = value.slice(0, 16384) + value.slice(-16384);if(markerMemo)value=value.replace(new RegExp(markerMemo,"gi"),"<marker>");return value.toLowerCase().replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, "<id>").replace(/\b\d{10,13}\b/g, "<time>").replace(/\s+/g, " ").trim(); }
  function segmentText(segment){if(!segment)return "";if(segment.text!=null)return segment.text;var item=segment.source,key=item&&item.id,bytes=transcriptMemo&&key&&transcriptMemo[key];if(bytes==null){bytes=transcript(item);if(transcriptMemo&&key)transcriptMemo[key]=bytes;}segment.text=segment.length>32768?bytes.slice(segment.offset,segment.offset+16384)+bytes.slice(segment.offset+segment.length-16384,segment.offset+segment.length):bytes.slice(segment.offset,segment.offset+segment.length);return segment.text;}
  function semanticText(segment) {
    if(segment&&segment.semantic!=null)return segment.semantic;
    var text=segmentText(segment),separator=text.indexOf("\r\n\r\n"),body=text,location=segment&&segment.location||"",contentType=segment&&segment.contentType||"";
    if(segment&&segment.protocol==="h1"&&separator>=0){
      var lines=text.slice(0,separator).split("\r\n");body=text.slice(separator+4);
      lines.slice(1).forEach(function(line){var split=line.indexOf(":");if(split<=0)return;var name=line.slice(0,split).trim().toLowerCase(),value=line.slice(split+1).trim();if(name==="location")location=value;else if(name==="content-type")contentType=value;});
    }
    var normalizedBody=normalized(body),normalizedLocation=normalized(location),normalizedType=normalized(contentType),semantic="status:"+(segment&&segment.status==null?"":segment.status)+"|location:"+normalizedLocation+"|type:"+normalizedType+"|body:"+normalizedBody;if(segment){segment.semantic=semantic;segment.semanticBody=normalizedBody;segment.semanticLocation=normalizedLocation;}return semantic;
  }
  function usableSegment(segment){return !!(segment&&segment.usable!==false&&segment.status!=null&&segment.complete!==false&&!segment.reset&&!segment.truncated);}
  function similarity(left, right) {
    left = String(left || ""); right = String(right || ""); if (left === right) return 1; if (!left || !right) return 0;
    var a = {}, b = {}, union = {}, same = 0, total = 0;
    left.split(/[^a-z0-9_<>]+/).filter(Boolean).forEach(function (token) { a[token] = 1; union[token] = 1; });
    right.split(/[^a-z0-9_<>]+/).filter(Boolean).forEach(function (token) { b[token] = 1; union[token] = 1; });
    Object.keys(union).forEach(function (token) { total += 1; if (a[token] && b[token]) same += 1; }); return total ? same / total : 0;
  }
  function sameSegment(left, right) { if(!usableSegment(left)||!usableSegment(right)||left.status!==right.status)return false;if(left.hash&&right.hash)return left.hash===right.hash;var a=semanticText(left),b=semanticText(right);return a===b||similarity(a,b)>=0.98; }
  function sameCanarySegment(left,right){
    if(!usableSegment(left)||!usableSegment(right)||left.status!==right.status)return false;
    semanticText(left);semanticText(right);
    if(right.semanticLocation)return left.semanticLocation===right.semanticLocation&&(!right.semanticBody||left.semanticBody===right.semanticBody);
    if(left.hash&&right.hash&&(left.length>0||right.length>0))return left.hash===right.hash;
    if(right.semanticBody)return left.semanticBody===right.semanticBody;
    return false;
  }
  function stable(left, right) {
    var a = segments(left), b = segments(right); if (!hasResult(left) || !hasResult(right) || outcome(left) !== outcome(right) || a.length !== b.length) return false;
    for (var index = 0; index < a.length; index += 1) {
      if (!sameSegment(a[index], b[index])) return false;
    }
    return true;
  }
  function matchesCanary(segment, canary, base) { return !!(usableSegment(segment)&&usableSegment(canary)&&usableSegment(base)&&sameCanarySegment(segment,canary)); }
  function matchesBase(segment, base) { return !!(usableSegment(segment)&&usableSegment(base)&&sameSegment(segment,base)); }
  function nestedHttpSegments(segment) {
    var text=segmentText(segment),output=[],cursor=0;
    while(cursor<text.length){
      var match=/HTTP\/1\.[01]\s+([1-5][0-9][0-9])[^\r\n]*\r\n/g;match.lastIndex=cursor;var found=match.exec(text);if(!found)break;
      var start=found.index,headEnd=text.indexOf("\r\n\r\n",match.lastIndex);if(headEnd<0)break;
      var headerLines=text.slice(match.lastIndex,headEnd).split("\r\n"),contentLength=null,validHeaders=true;
      headerLines.forEach(function(line){var split=line.indexOf(":");if(split<=0){validHeaders=false;return;}if(line.slice(0,split).trim().toLowerCase()==="content-length"){var parsed=Number(line.slice(split+1).trim());if(Number.isInteger(parsed)&&parsed>=0)contentLength=parsed;else validHeaders=false;}});
      if(!validHeaders||contentLength==null){cursor=headEnd+4;continue;}
      var end=headEnd+4+contentLength;if(end>text.length)break;
      output.push({status:Number(found[1]),text:text.slice(start,end),hash:"",length:end-start,protocol:"h1",complete:true,reset:null,truncated:false,usable:true});cursor=end;
    }
    return output;
  }
  function matchesNestedCanary(segment,canary,base){return nestedHttpSegments(segment).some(function(nested){return matchesCanary(nested,canary,base);});}
  function probeRejected(item,probeSegments){
    if(item&&Array.isArray(item.streams)&&item.streams.some(function(stream){return /^(PROTOCOL_ERROR|COMPRESSION_ERROR)$/.test(String(stream.reset||""));}))return true;
    var first=probeSegments[0],status=first&&first.status;return usableSegment(first)&&[400,408,411,413,414,417,421,431,500,501,505].indexOf(status)!==-1;
  }
  function evidence(items) { var output=[]; items.forEach(function(item){var value=rawResult(item);if(value&&value.exchange_id)output.push(value.exchange_id);if(item&&Array.isArray(item.streams))item.streams.forEach(function(stream){if(stream.exchange_id)output.push(stream.exchange_id);});});return output; }
  function analyze(input, observations, context) {
    segmentMemo={};transcriptMemo={};markerMemo=String(input.marker||"").toLowerCase();
    var map = byId(observations), set = techniques(input, context), repeats = Math.max(3, Math.min(Number(input.repeats || 5), 9)), findings = [], diagnostics = [];
    var hasH2=set.items.some(function(item){return isH2Mode(item.mode);});
    var h1BaseDirect=[map["direct-base-0"],map["direct-base-1"]],h1CanaryDirect=[map["direct-canary-0"],map["direct-canary-1"]];
    var h2BaseDirect=[map["h2-direct-base-0"],map["h2-direct-base-1"]],h2CanaryDirect=[map["h2-direct-canary-0"],map["h2-direct-canary-1"]];
    var h1Stable=stable(h1BaseDirect[0],h1BaseDirect[1])&&stable(h1CanaryDirect[0],h1CanaryDirect[1]);
    var h2Stable=!hasH2||(stable(h2BaseDirect[0],h2BaseDirect[1])&&stable(h2CanaryDirect[0],h2CanaryDirect[1]));
    var threshold = Math.max(3, Math.ceil(repeats * 0.6));
    set.items.forEach(function (technique, index) {
      var h2Mode=isH2Mode(technique.mode),baseDirect=h2Mode?h2BaseDirect:h1BaseDirect,canaryDirect=h2Mode?h2CanaryDirect:h1CanaryDirect;
      var directStable=h2Mode?h2Stable:h1Stable,baseSignature=segments(baseDirect[0])[0],canarySignature=segments(canaryDirect[0])[0];
      var canaryDistinct=directStable&&baseSignature&&canarySignature&&(baseSignature.status!==canarySignature.status||!sameSegment(baseSignature,canarySignature));
      var controls = [], probes = [], victims = [], recoveries = [], observers = [], clean = 0, contaminated = 0, divergentVictims = 0, timeouts = 0, probeRejections = 0, probeInconclusive = 0, probeDifferences = 0, observerCount = technique.mode === "zero_cl_pair" ? Math.max(1, Math.min(Number(input.zero_cl_observers || 2), 5)) : 2;
      for (var repeat = 0; repeat < repeats; repeat += 1) {
        var control = map["control-" + index + "-" + repeat], probe = map["probe-" + index + "-" + repeat], victim=map["victim-"+index+"-"+repeat], recovery=map["recovery-"+index+"-"+repeat]; controls.push(control); probes.push(probe); victims.push(victim); recoveries.push(recovery);
        var repeatObservers=[];for(var observer=0;observer<observerCount;observer+=1){var observed=map["observer-"+index+"-"+repeat+"-"+observer];repeatObservers.push(observed);observers.push(observed);}if(technique.mode!=="zero_cl_pair"&&repeatObservers.every(function(item){return !item;})){repeatObservers=[victim,recovery];observers.push(victim,recovery);}
        var controlSegments = segments(control), controlClean = hasResult(control) && outcome(control) !== "timeout" && controlSegments.length >= 1 && controlSegments.every(function (segment) { return usableSegment(segment) && (!canaryDistinct || !matchesCanary(segment, canarySignature, baseSignature)); }); if (controlClean) clean += 1;
        var probeSegments=segments(probe), victimSegments=segments(victim), recoverySegments=segments(recovery),observerSegments=[];repeatObservers.forEach(function(item){observerSegments=observerSegments.concat(segments(item));});var rejectedProbe=probeRejected(probe,probeSegments),downstream=(rejectedProbe?probeSegments.slice(1):probeSegments).concat(victimSegments,recoverySegments,observerSegments);
        if(rejectedProbe)probeRejections+=1;else if(!hasResult(probe))probeInconclusive+=1;else if(probeSegments[0]&&!matchesBase(probeSegments[0],baseSignature))probeDifferences+=1;
        var confirmedThisRepeat=false;
        if (technique.mode === "zero_cl_pair") {
          var mutantControl=segments(control)[0], mutantVictim=victimSegments[0];
          confirmedThisRepeat=!!(canaryDistinct && mutantControl && matchesBase(mutantControl,baseSignature) && downstream.some(function(segment){return matchesCanary(segment,canarySignature,baseSignature);}));
        } else if (technique.mode === "connection_state") {
          var directHost=segments(control)[0], indirectHost=probeSegments.length > 1 ? probeSegments[probeSegments.length-1] : null;
          confirmedThisRepeat=!!(usableSegment(directHost)&&usableSegment(indirectHost)&&!sameSegment(directHost,indirectHost)&&matchesBase(probeSegments[0],baseSignature));
        } else if (technique.mode === "h2_tunnel") {
          confirmedThisRepeat=!!(canaryDistinct&&probeSegments.some(function(segment){return usableSegment(segment)&&matchesNestedCanary(segment,canarySignature,baseSignature);}));
        } else if (technique.mode !== "h2_header_injection" && technique.confirmable && canaryDistinct) {
          confirmedThisRepeat=downstream.some(function(segment){return matchesCanary(segment,canarySignature,baseSignature);});
        }
        if(confirmedThisRepeat)contaminated+=1;
        var victimFirst=segments(victim)[0],recoveryFirst=segments(recovery)[0],observerDiverged=observerSegments.some(function(segment){return usableSegment(segment)&&!matchesBase(segment,baseSignature);}); if((usableSegment(victimFirst)&&!matchesBase(victimFirst,baseSignature))||(usableSegment(recoveryFirst)&&!matchesBase(recoveryFirst,baseSignature))||observerDiverged) divergentVictims+=1;
        if (outcome(probe) === "timeout" && outcome(control) !== "timeout") timeouts += 1;
      }
      var confirmed = directStable && canaryDistinct && clean === repeats && contaminated >= threshold;
      var candidate = directStable && clean === repeats && timeouts >= threshold;
      var unstableZero=technique.mode==="zero_cl_pair"&&divergentVictims>=Math.max(2,Math.ceil(repeats*0.4));
      var responseCandidate=directStable&&clean===repeats&&(divergentVictims>=threshold||unstableZero),unstableMarker=directStable&&canaryDistinct&&clean===repeats&&contaminated>0;
      diagnostics.push({ family: technique.family, technique: technique.name, polarity: technique.polarity, clean_controls: clean, canary_confirmations: contaminated, divergent_victims: divergentVictims, probe_only_timeouts: timeouts, probe_rejections: probeRejections, probe_inconclusive: probeInconclusive, probe_response_differences: probeDifferences, repeats: repeats, signal: confirmed ? "marker_contamination" : unstableMarker ? "marker_contamination_unstable" : responseCandidate ? "victim_divergence" : candidate ? "timing_candidate" : probeRejections === repeats ? "rejected" : probeInconclusive === repeats ? "inconclusive" : "none" });
      if (confirmed) findings.push({
        title: "Confirmed " + (h2Mode ? "HTTP/2 downgrade/tunnelling" : "HTTP/1 request desynchronization") + ": " + technique.name, severity: technique.mode==="h2_header_injection"?"medium":"high", confidence: "firm",
        explanation: (technique.mode === "h2_tunnel" ? "A nested or directly routed canary response was reproducibly exposed by the HTTP/2 tunnelling probe" : technique.mode==="h2_header_injection"?"The malformed HTTP/2 header name reproducibly changed the downstream response":"A harmless marker request was reproducibly parsed out of the ambiguous pipeline") + " in " + contaminated + " of " + repeats + " attempts, while every standalone control remained clean.",
        remediation: "Reject ambiguous framing at the first hop, normalize Transfer-Encoding and Content-Length consistently across every hop, and close connections after parser errors.",
        evidence_exchange_ids: evidence(baseDirect.concat(canaryDirect, controls, probes, victims, recoveries, observers)), metadata: { family: technique.family, polarity: technique.polarity, signal: "marker_contamination", confirmations: contaminated, attempts: repeats }
      });
      else if (unstableMarker) findings.push({
        title: (h2Mode ? "HTTP/2 downgrade" : "HTTP/1 framing") + " discrepancy candidate: " + technique.name, severity: "medium", confidence: "tentative",
        explanation: "The exact canary response appeared downstream after an ambiguous probe in " + contaminated + " of " + repeats + " attempts. This pool-dependent marker signal did not reach the configured firm quorum and is retained as unstable evidence.",
        remediation: "Review every HTTP hop for inconsistent framing rules and validate on an isolated connection before treating this as exploitable.",
        evidence_exchange_ids: evidence(controls.concat(probes,victims,recoveries,observers)), metadata: { family: technique.family, polarity: technique.polarity, signal: "marker_contamination_unstable", confirmations: contaminated, attempts: repeats }
      });
    });
    var result={ findings: findings, result: { direct_controls_stable: h1Stable && h2Stable, diagnostics: diagnostics, limitations: ["Firm framing findings require repeated downstream marker contamination; timeout, rejection, and response-divergence-only signals remain diagnostics.", "HTTP/2 probes require HTTPS with ALPN h2 and never fall back to HTTP/1.", "HTTP/2 reset, GOAWAY, incomplete, and truncated streams are never treated as downstream responses.", "HTTP/2 nested-response confirmation requires a complete Content-Length-framed inner response.", "Pause-based findings require the explicit pause family; browser client-side desync remains out of scope."] } };segmentMemo=null;transcriptMemo=null;markerMemo=null;return result;
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
