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
  function base(context) {
    var value = context.base_exchange;
    if (!value || !value.exchange_id || !value.identity) throw new Error("CSRFAnalyzer requires identity.use access to a saved request");
    if (["GET", "HEAD", "OPTIONS"].indexOf(String(value.method).toUpperCase()) !== -1) throw new Error("CSRFAnalyzer requires a state-changing request shape");
    return value;
  }
  function raw(context) {
    var list = context.base_exchange.identity.request_headers || [], headers = {}, ordered = [];
    list.forEach(function (item) {
      var name = String(item.name), value = decode64(item.value_base64);
      ordered.push({ name: name, value: value });
      if (!headers[name.toLowerCase()]) headers[name.toLowerCase()] = [];
      headers[name.toLowerCase()].push(value);
    });
    return { headers: headers, ordered_headers: ordered, body: decode64(context.base_exchange.identity.request_body_base64 || "") };
  }
  function firstHeader(data, name) { var values = data.headers[String(name).toLowerCase()] || []; return values.length ? values[0] : ""; }
  function tokenNames(input) {
    return (input.token_names && input.token_names.length ? input.token_names : ["csrf", "csrf_token", "_csrf", "xsrf", "_token", "authenticity_token", "x-csrf-token", "x-xsrf-token"])
      .map(function (value) { return String(value); });
  }
  function lowerSet(values) { var out = {}; values.forEach(function (value) { out[String(value).toLowerCase()] = true; }); return out; }
  function decodeComponent(value) { try { return decodeURIComponent(String(value).replace(/\+/g, " ")); } catch (_) { return String(value); } }
  function formParts(body) {
    return String(body).split("&").map(function (part) {
      var at = part.indexOf("=");
      return { raw: part, name: decodeComponent(at < 0 ? part : part.slice(0, at)), value: decodeComponent(at < 0 ? "" : part.slice(at + 1)) };
    });
  }
  function queryParts(url) {
    var query = String(url).split("?")[1] || "";
    query = query.split("#")[0];
    return query ? formParts(query) : [];
  }
  function identityHeaders(identity) {
    var headers = (identity && identity.headers || []).map(function (item) { return { name: String(item.name), value: String(item.value) }; });
    if (identity && identity.cookie) headers.push({ name: "Cookie", value: String(identity.cookie) });
    return headers;
  }
  function freshToken(input) {
    if(!input.fresh_token) return null;
    return {acquire_url:String(input.fresh_token.acquire_url),body_regex:String(input.fresh_token.body_regex),location:String(input.fresh_token.location),name:String(input.fresh_token.name),identity:input.fresh_token.identity||null};
  }
  function tokenPatch(config,value) {
    var token={name:config.name,value:value}, patch={};
    if(config.location==="query") patch.query_params=[token];
    else if(config.location==="header") patch.headers=[token];
    else patch.body_params=[token];
    return patch;
  }
  function freshValue(input,location,name,value){var config=freshToken(input);return config&&config.location===location&&config.name.toLowerCase()===String(name).toLowerCase()?"{{extract:csrf_fresh}}":value;}
  function jsonPointer(parts) { return "/" + parts.map(function(part){return String(part).replace(/~/g,"~0").replace(/\//g,"~1");}).join("/"); }
  function jsonTokenPaths(value, wanted, parts, output, depth) {
    if(!value || typeof value!=="object" || depth>8 || output.length>=40) return;
    Object.keys(value).forEach(function(name){
      var next=parts.concat([name]);
      if(wanted[String(name).toLowerCase()] && output.length<40) output.push(next);
      jsonTokenPaths(value[name],wanted,next,output,depth+1);
    });
  }
  function jsonChanged(value, path, replacement, remove) {
    var copy=JSON.parse(JSON.stringify(value)), current=copy;
    for(var index=0;index<path.length-1;index+=1) current=current[path[index]];
    if(remove) delete current[path[path.length-1]]; else current[path[path.length-1]]=replacement;
    return encode64(JSON.stringify(copy));
  }
  function jsonChangedAll(value, paths, replacement, remove) {
    var copy=JSON.parse(JSON.stringify(value));
    paths.forEach(function(path){
      var current=copy;
      for(var index=0;index<path.length-1;index+=1) current=current && current[path[index]];
      if(!current) return;
      if(remove) delete current[path[path.length-1]]; else current[path[path.length-1]]=replacement;
    });
    return encode64(JSON.stringify(copy));
  }
  function mergePatch(left,right) {
    var output={}, keys={}, arrayKeys={headers:true,header_tombstones:true,query_params:true,cookie_params:true,body_params:true};
    Object.keys(left||{}).concat(Object.keys(right||{})).forEach(function(key){keys[key]=true;});
    Object.keys(keys).forEach(function(key){
      if(arrayKeys[key]) output[key]=(output[key]||[]).concat((left&&left[key])||[],(right&&right[key])||[]);
      else if(right && Object.prototype.hasOwnProperty.call(right,key)) output[key]=right[key];
      else if(left && Object.prototype.hasOwnProperty.call(left,key)) output[key]=left[key];
    });
    return output;
  }
  function mutationList(input, context) {
    var exchange = base(context), data = raw(context), wanted = lowerSet(tokenNames(input)), values = [], seen = {};
    var invalid = "huntproxy-invalid-csrf", contentType = firstHeader(data, "content-type").toLowerCase();
    var combinedRemoval={}, combinedInvalid={}, tokenFields=0;
    function add(name, patch, kind, negativeControl) {
      if (!seen[name]) { seen[name] = true; values.push({ name: name, patch: patch, kind: kind || "token", negative_control: negativeControl || null }); }
    }
    queryParts(exchange.url).forEach(function (part) {
      if (!wanted[part.name.toLowerCase()]) return;
      tokenFields+=1;
      combinedRemoval=mergePatch(combinedRemoval,{query_params:[{name:part.name,value:null}]});
      combinedInvalid=mergePatch(combinedInvalid,{query_params:[{name:part.name,value:invalid}]});
      add("query-remove:" + part.name, { query_params: [{ name: part.name, value: null }] });
      add("query-invalid:" + part.name, { query_params: [{ name: part.name, value: invalid }] });
      add("query-duplicate-invalid-first:" + part.name, { query_params: [{ name: part.name, value: invalid }, { name: part.name, value: freshValue(input,"query",part.name,part.value) }] }, "duplicate-token");
      add("query-duplicate-invalid-last:" + part.name, { query_params: [{ name: part.name, value: freshValue(input,"query",part.name,part.value) }, { name: part.name, value: invalid }] }, "duplicate-token");
    });
    data.ordered_headers.forEach(function (header) {
      if (!wanted[header.name.toLowerCase()]) return;
      tokenFields+=1;
      combinedRemoval=mergePatch(combinedRemoval,{header_tombstones:[header.name]});
      combinedInvalid=mergePatch(combinedInvalid,{header_tombstones:[header.name],headers:[{name:header.name,value:invalid}]});
      add("header-remove:" + header.name, { header_tombstones: [header.name] });
      add("header-invalid:" + header.name, { headers: [{ name: header.name, value: invalid }] });
      add("header-duplicate-invalid-first:" + header.name, { header_tombstones: [header.name], headers: [{ name: header.name, value: invalid }, { name: header.name, value: freshValue(input,"header",header.name,header.value) }] }, "duplicate-token");
      add("header-duplicate-invalid-last:" + header.name, { header_tombstones: [header.name], headers: [{ name: header.name, value: freshValue(input,"header",header.name,header.value) }, { name: header.name, value: invalid }] }, "duplicate-token");
    });
    if (contentType.indexOf("application/x-www-form-urlencoded") !== -1) {
      var parts = formParts(data.body);
      parts.forEach(function (part) {
        if (!wanted[part.name.toLowerCase()]) return;
        tokenFields+=1;
        combinedRemoval=mergePatch(combinedRemoval,{body_params:[{name:part.name,value:null}]});
        combinedInvalid=mergePatch(combinedInvalid,{body_params:[{name:part.name,value:invalid}]});
        add("body-remove:" + part.name, { body_params: [{ name: part.name, value: null }] });
        add("body-invalid:" + part.name, { body_params: [{ name: part.name, value: invalid }] });
        var fresh=freshToken(input), refreshBody=fresh&&fresh.location==="body"&&fresh.name.toLowerCase()===part.name.toLowerCase();
        if(refreshBody){
          add("body-duplicate-invalid-first:"+part.name,{body_params:[{name:part.name,value:invalid},{name:part.name,value:"{{extract:csrf_fresh}}"}]},"duplicate-token");
          add("body-duplicate-invalid-last:"+part.name,{body_params:[{name:part.name,value:"{{extract:csrf_fresh}}"},{name:part.name,value:invalid}]},"duplicate-token");
        } else {
          var without = parts.filter(function (candidate) { return candidate.name.toLowerCase() !== part.name.toLowerCase(); }).map(function (candidate) { return candidate.raw; });
          add("body-duplicate-invalid-first:" + part.name, { body_base64: encode64(without.concat([encodeURIComponent(part.name) + "=" + encodeURIComponent(invalid), encodeURIComponent(part.name) + "=" + encodeURIComponent(part.value)]).join("&")) }, "duplicate-token");
          add("body-duplicate-invalid-last:" + part.name, { body_base64: encode64(without.concat([encodeURIComponent(part.name) + "=" + encodeURIComponent(part.value), encodeURIComponent(part.name) + "=" + encodeURIComponent(invalid)]).join("&")) }, "duplicate-token");
        }
      });
    } else if (contentType.indexOf("application/json") !== -1) {
      try {
        var object = JSON.parse(data.body);
        var paths=[]; jsonTokenPaths(object,wanted,[],paths,0);
        if(paths.length){tokenFields+=paths.length; combinedRemoval=mergePatch(combinedRemoval,{body_base64:jsonChangedAll(object,paths,invalid,true)}); combinedInvalid=mergePatch(combinedInvalid,{body_base64:jsonChangedAll(object,paths,invalid,false)});}
        paths.forEach(function (path) {
          var pointer=jsonPointer(path);
          add("json-remove:" + pointer, { body_base64: jsonChanged(object,path,invalid,true) });
          add("json-invalid:" + pointer, { body_base64: jsonChanged(object,path,invalid,false) });
        });
      } catch (_) {}
    }

    if(tokenFields) add("control-invalid-all-tokens",combinedInvalid,"token-negative-control");
    function addDefense(name,patch,kind){
      if(!tokenFields) return add(name,patch,kind);
      add(name,patch,kind+"-diagnostic");
      add(name+"+token-remove",mergePatch(combinedRemoval,patch),kind+"-token","control-invalid-all-tokens");
    }

    addDefense("origin-remove", { header_tombstones: ["Origin"] }, "origin");
    addDefense("origin-null", { header_tombstones: ["Origin"], headers: [{ name: "Origin", value: "null" }] }, "origin");
    addDefense("origin-cross-site", { header_tombstones: ["Origin"], headers: [{ name: "Origin", value: String(input.cross_site_origin || "https://csrf.invalid") }] }, "origin");
    addDefense("referer-remove", { header_tombstones: ["Referer"] }, "referer");
    addDefense("referer-cross-site", { header_tombstones: ["Referer"], headers: [{ name: "Referer", value: String(input.cross_site_origin || "https://csrf.invalid") + "/huntproxy" }] }, "referer");
    addDefense("origin-and-referer-remove", { header_tombstones: ["Origin", "Referer"] }, "origin-referer");
    addDefense("origin-and-referer-cross-site", { header_tombstones: ["Origin", "Referer"], headers: [{ name: "Origin", value: String(input.cross_site_origin || "https://csrf.invalid") }, { name: "Referer", value: String(input.cross_site_origin || "https://csrf.invalid") + "/huntproxy" }] }, "origin-referer");

    addDefense("content-type-remove", { header_tombstones: ["Content-Type"] }, "content-type");
    if (contentType.indexOf("application/json") !== -1 || contentType.indexOf("application/x-www-form-urlencoded") !== -1) {
      addDefense("content-type-text-plain", { header_tombstones: ["Content-Type"], headers: [{ name: "Content-Type", value: "text/plain" }] }, "content-type");
    }
    if(contentType.indexOf("application/x-www-form-urlencoded") !== -1) {
      var methodQuery=formParts(data.body).filter(function(part){return !wanted[part.name.toLowerCase()];}).map(function(part){return {name:part.name,value:part.value};});
      queryParts(exchange.url).forEach(function(part){if(wanted[part.name.toLowerCase()]) methodQuery.push({name:part.name,value:null});});
      add("method-get-form-query", mergePatch(combinedRemoval,{ method: "GET", query_params: methodQuery, body_base64: encode64(""), header_tombstones: ["Content-Type", "Content-Length"] }), "method-token",tokenFields?"control-invalid-all-tokens":null);
    } else add("method-get-empty-body", mergePatch(combinedRemoval,{ method: "GET", body_base64: encode64(""), header_tombstones: ["Content-Type", "Content-Length"] }), tokenFields?"method-token":"method",tokenFields?"control-invalid-all-tokens":null);
    addDefense("method-override-get", { headers: [{ name: "X-HTTP-Method-Override", value: "GET" }] }, "method");

    if (input.secondary_identity) {
      add("cross-session-original-token", {
        header_tombstones: ["Cookie", "Authorization", "Proxy-Authorization"],
        headers: identityHeaders(input.secondary_identity)
      }, "session-binding");
    }
    (input.paired_cookie_tests||[]).forEach(function(test){
      var headers=identityHeaders(test.identity), patch={header_tombstones:["Cookie","Authorization","Proxy-Authorization"],headers:headers};
      var fresh=freshToken(input), useFresh=fresh&&fresh.location===test.token.location&&fresh.name.toLowerCase()===String(test.token.name).toLowerCase();
      var token={name:String(test.token.name),value:useFresh?"{{extract:csrf_fresh}}":String(test.token.value)};
      if(test.token.location==="query") patch.query_params=[token];
      else if(test.token.location==="header") patch.headers=headers.concat([token]);
      else patch.body_params=[token];
      add("paired-cookie:"+String(test.name),patch,"cookie-token-binding");
    });
    return values.slice(0, Math.max(1, Math.min(Number(input.max_mutations || 50), 80)));
  }
  function operation(id, exchange, patch) {
    var op = { id: id, type: "http_request", base_exchange_id: exchange.exchange_id, method: exchange.method, protocol: "auto" };
    Object.keys(patch || {}).forEach(function (key) { op[key] = patch[key]; });
    return op;
  }
  function workflowRequest(id,exchange,patch) {
    var request={id:id,base_exchange_id:exchange.exchange_id,method:exchange.method,protocol:"auto"};
    Object.keys(patch||{}).forEach(function(key){request[key]=patch[key];});
    return request;
  }
  function workflow(id,exchange,config,patch,refresh) {
    var acquirePatch={method:"GET",url:config.acquire_url,body_base64:encode64(""),header_tombstones:["Content-Type","Content-Length"]};
    if(config.identity){acquirePatch.header_tombstones=acquirePatch.header_tombstones.concat(["Cookie","Authorization","Proxy-Authorization"]);acquirePatch.headers=identityHeaders(config.identity);}
    var submitPatch=refresh===false?patch:mergePatch(tokenPatch(config,"{{extract:csrf_fresh}}"),patch);
    return {id:id,type:"http_workflow",steps:[
      {id:"acquire",request:workflowRequest("ignored",exchange,acquirePatch),extract:[{from:"body_regex",name:"csrf_fresh",pattern:config.body_regex,group:1,required:true}]},
      {id:"submit",request:workflowRequest("ignored",exchange,submitPatch)}
    ]};
  }
  function patchTouchesToken(patch,config){var key=config.location==="query"?"query_params":config.location==="header"?"headers":"body_params";return (patch&&patch[key]||[]).some(function(item){return String(item.name).toLowerCase()===config.name.toLowerCase();});}
  function plan(input, context) {
    if (input.allow_state_change !== true) throw new Error("CSRF testing repeats the state-changing request and requires allow_state_change=true");
    var exchange = base(context), operations = [], mutations = mutationList(input, context), fresh=freshToken(input);
    for (var repeat = 0; repeat < 2; repeat += 1) operations.push(fresh?workflow("baseline-"+repeat,exchange,fresh,{},true):operation("baseline-" + repeat, exchange, {}));
    mutations.forEach(function (mutation, index) {
      for (var repeat = 0; repeat < 2; repeat += 1) {
        var id="mutation-"+index+"-"+repeat, refresh=!/^method-get-/.test(mutation.name)&&(!fresh||!patchTouchesToken(mutation.patch,fresh));
        operations.push(fresh?workflow(id,exchange,fresh,mutation.patch,refresh):operation(id,exchange,mutation.patch));
      }
    });
    return { operations: operations, result: { mutations: mutations.map(function (item) { return { name: item.name, kind: item.kind, negative_control: item.negative_control }; }), repeated_state_changes: operations.length, planned_requests:operations.length*(fresh?2:1), fresh_token_workflows:!!fresh, semantic_comparison: true } };
  }
  function terminalObservations(items){return items.map(function(item){if(!item||!item.terminal)return item;var terminal={};Object.keys(item.terminal||{}).forEach(function(key){terminal[key]=item.terminal[key];});terminal.id=item.id;if(item.error)terminal.error=item.error;return terminal;});}
  function byId(items) { var map = {}; items.forEach(function (item) { map[item.id] = item; }); return map; }
  function preview(item) { return String(item && item.response_preview && item.response_preview.text || "").toLowerCase(); }
  function normalized(item) {
    return preview(item)
      .replace(/(["']?(?:csrf|xsrf|token|nonce)["']?\s*[:=]\s*["'])[^"']+/gi, "$1<dynamic>")
      .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "<uuid>")
      .replace(/[a-z0-9_-]{24,}/gi, "<opaque>")
      .replace(/\b\d{4}-\d\d-\d\d[t ][^\s<]+/gi, "<time>")
      .replace(/\b\d+\b/g, "<n>")
      .replace(/\s+/g, " ").trim();
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
  function stablePair(map, prefix) {
    var first = map[prefix + "0"], second = map[prefix + "1"];
    if (!first || !second || first.error || second.error) return null;
    return similarity(first, second) >= 0.9 ? first : null;
  }
  function includesMarker(item, markers) { var text = preview(item); return (markers || []).some(function (marker) { return text.indexOf(String(marker).toLowerCase()) !== -1; }); }
  function rejected(item, input) {
    return !item || item.error || item.status_code === 401 || item.status_code === 403 || item.status_code === 419 || item.status_code >= 500
      || /csrf|forbidden|invalid (?:anti[- ]?forgery )?token|origin mismatch|referer mismatch|request rejected/.test(preview(item))
      || includesMarker(item, input.failure_markers);
  }
  function successful(item, input) {
    if (rejected(item, input) || item.status_code < 200 || item.status_code >= 400) return false;
    return !(input.success_markers && input.success_markers.length) || includesMarker(item, input.success_markers);
  }
  function analyze(input, observations, context) {
    observations=terminalObservations(observations);
    var map = byId(observations), baseline = stablePair(map, "baseline-"), findings = [], outcomes = [], mutations = mutationList(input, context);
    var baselineSuccess = successful(baseline, input);
    mutations.forEach(function (mutation, index) {
      var result = stablePair(map, "mutation-" + index + "-"), accepted = baselineSuccess && successful(result, input);
      var score = baseline && result ? similarity(baseline, result) : 0;
      var comparable = score >= 0.82 || (result && baseline && Math.floor(result.status_code / 100) === Math.floor(baseline.status_code / 100) && (result.status_code === 302 || includesMarker(result, input.success_markers)));
      var negativeIndex=mutation.negative_control?mutations.map(function(item){return item.name;}).indexOf(mutation.negative_control):-1;
      var negative=negativeIndex>=0?stablePair(map,"mutation-"+negativeIndex+"-"):null, negativeRejected=!mutation.negative_control || (!!negative && rejected(negative,input));
      var diagnostic=/-diagnostic$/.test(mutation.kind);
      outcomes.push({ mutation: mutation.name, kind: mutation.kind, reproducible: !!result, accepted: !!accepted, baseline_similarity: Math.round(score * 1000) / 1000, negative_control: mutation.negative_control, negative_control_rejected: !!negativeRejected, diagnostic_only: diagnostic, error: result ? null : "unstable_or_failed" });
      if (!diagnostic && accepted && comparable && negativeRejected) findings.push({
        title: "CSRF defense bypass using " + mutation.name,
        severity: mutation.kind === "content-type" || mutation.kind === "method" ? "medium" : "high",
        confidence: score >= 0.9 ? "firm" : "tentative",
        explanation: "The state-changing request remained reproducibly successful after an isolated " + mutation.kind + " control, with a response semantically consistent with the successful baseline.",
        remediation: "Require an unpredictable session-bound CSRF token and validate Origin and Referer independently for every state-changing request; reject alternate methods, duplicate tokens, and unsupported content types.",
        evidence_exchange_ids: [baseline.exchange_id, result.exchange_id].filter(Boolean),
        metadata: { mutation: mutation.name, kind: mutation.kind, baseline_similarity: Math.round(score * 1000) / 1000 }
      });
    });
    return { findings: findings, result: { baseline_stable: !!baseline, baseline_successful: !!baselineSuccess, fresh_token_workflows:!!freshToken(input), outcomes: outcomes, tested_operations: observations.length, limitations: ["State-changing response comparison cannot prove server-side state without a caller-supplied success marker or a separate read-back request.", "Multipart CSRF token fields are not mutated automatically."] } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
