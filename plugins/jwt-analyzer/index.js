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
  function variants(input, context) {
    var jwt = parsed(input, context), list = [], signature = jwt.pieces[2], enabled = input.tests || ["none", "invalid_signature", "missing_signature", "expired", "no_exp", "empty_hmac", "kid_path"];
    function add(name, header, payload, sig) { if (enabled.indexOf(name) !== -1) list.push({ name: name, token: token(header, payload, sig) }); }
    add("none", Object.assign({}, jwt.header, { alg: "none" }), jwt.payload, "");
    if (enabled.indexOf("invalid_signature") !== -1) list.push({ name: "invalid_signature", token: jwt.pieces[0] + "." + jwt.pieces[1] + "." + (signature ? signature.slice(0, -1) + (signature.slice(-1) === "A" ? "B" : "A") : "A") });
    if (enabled.indexOf("missing_signature") !== -1) list.push({ name: "missing_signature", token: jwt.pieces[0] + "." + jwt.pieces[1] + "." });
    add("expired", jwt.header, Object.assign({}, jwt.payload, { exp: 1 }), signature);
    var noExp = Object.assign({}, jwt.payload); delete noExp.exp; add("no_exp", jwt.header, noExp, signature);
    add("empty_hmac", Object.assign({}, jwt.header, { alg: "HS256" }), jwt.payload, "");
    add("kid_path", Object.assign({}, jwt.header, { alg: "HS256", kid: "../../../../dev/null" }), jwt.payload, "");
    if (input.embedded_jwk && enabled.indexOf("embedded_jwk") !== -1) add("embedded_jwk", Object.assign({}, jwt.header, { jwk: input.embedded_jwk }), jwt.payload, "");
    if (input.key_url && !/^https?:\/\//i.test(input.key_url)) throw new Error("key_url must be an explicit HTTP(S) URL");
    ["jku", "x5u"].forEach(function (name) { if (input.key_url && enabled.indexOf(name) !== -1) { var header = Object.assign({}, jwt.header); header[name] = input.key_url; add(name, header, jwt.payload, ""); } });
    return list.slice(0, 12);
  }
  function operation(id, baseId, located, replacement) {
    var op = { id: id, type: "http_request", base_exchange_id: baseId, protocol: "auto" };
    if (located.kind === "cookie") op.cookie_params = [{ name: located.name, value: replacement }];
    else op.headers = [{ name: located.name, value: "Bearer " + replacement }];
    return op;
  }
  function plan(input, context) {
    var jwt = parsed(input, context), operations = [];
    if (input.active !== false) {
      for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("baseline-" + repeat, context.base_exchange.exchange_id, jwt.located, jwt.located.token));
      variants(input, context).forEach(function (variant, index) { for (var repeat = 0; repeat < 2; repeat += 1) operations.push(operation("variant-" + index + "-" + repeat, context.base_exchange.exchange_id, jwt.located, variant.token)); });
    }
    return { operations: operations, result: { token_location: jwt.located.kind, algorithm: jwt.header.alg || null, active_variants: input.active === false ? [] : variants(input, context).map(function (item) { return item.name; }) } };
  }
  function byId(items) { var out = {}; items.forEach(function (item) { out[item.id] = item; }); return out; }
  function same(a, b) { return a && b && a.status_code === b.status_code && (a.response_body_hash && b.response_body_hash ? a.response_body_hash === b.response_body_hash : a.response_length === b.response_length); }
  function pair(map, prefix) { return same(map[prefix + "0"], map[prefix + "1"]) ? map[prefix + "0"] : null; }
  function analyze(input, observations, context) {
    var jwt = parsed(input, context), map = byId(observations), findings = [], baseId = context.base_exchange.exchange_id, now = Math.floor(Date.now() / 1000);
    function passive(title, severity, explanation) { findings.push({ title: title, severity: severity, confidence: "firm", explanation: explanation, remediation: "Issue short-lived tokens with explicit validation policy and verify algorithm, signature, claims, and trusted key sources server-side.", evidence_exchange_ids: [baseId] }); }
    if (String(jwt.header.alg || "").toLowerCase() === "none") passive("JWT uses the none algorithm", "high", "The captured token declares alg=none and therefore carries no cryptographic authentication.");
    if (jwt.payload.exp === undefined) passive("JWT has no expiration claim", "low", "The captured token does not contain an exp claim.");
    else if (Number(jwt.payload.exp) < now) passive("Captured JWT is expired", "informational", "The captured token expiration is in the past; acceptance would indicate missing claim validation.");
    if (jwt.header.jku || jwt.header.x5u) passive("JWT references a remote key URL", "medium", "The token header selects verification material through a URL and requires a strict allowlist.");
    var baseline = pair(map, "baseline-");
    if (input.active !== false && baseline) variants(input, context).forEach(function (variant, index) {
      var accepted = pair(map, "variant-" + index + "-");
      if (accepted && accepted.status_code >= 200 && accepted.status_code < 400 && same(baseline, accepted)) findings.push({
        title: "JWT validation bypass using " + variant.name.replace(/_/g, " "), severity: "high", confidence: "firm",
        explanation: "A deliberately invalid JWT mutation reproduced the authenticated baseline response twice.",
        remediation: "Reject altered tokens and enforce an allowlisted algorithm, valid signature, expiration, and trusted key-selection metadata.",
        evidence_exchange_ids: [baseline.exchange_id, accepted.exchange_id].filter(Boolean), metadata: { variant: variant.name }
      });
    });
    return { findings: findings, result: { algorithm: jwt.header.alg || null, claims: Object.keys(jwt.payload).sort(), tested_operations: observations.length } };
  }
  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
