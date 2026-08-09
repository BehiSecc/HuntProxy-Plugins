(function () {
  "use strict";

  function baseExchange(context) {
    if (!context.base_exchange || !context.base_exchange.exchange_id) {
      throw new Error("Choose a saved base exchange when running the inspect action.");
    }
    return context.base_exchange;
  }

  function plan(input, context) {
    if (context.action !== "inspect") throw new Error("Unsupported action.");
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new Error("The inspect action input must be an object.");
    }
    if (Object.keys(input).length) throw new Error("The inspect action does not accept input fields.");
    var base = baseExchange(context);
    var method = String(base.method || "GET").toUpperCase();
    if (["GET", "HEAD", "OPTIONS"].indexOf(method) === -1) {
      throw new Error("The example only replays read-oriented GET, HEAD, or OPTIONS requests.");
    }
    return {
      operations: [{
        id: "replay",
        type: "http_request",
        base_exchange_id: base.exchange_id,
        method: method,
        protocol: "auto"
      }],
      result: { source_exchange_id: base.exchange_id }
    };
  }

  function analyze(input, observations) {
    var replay = observations.find(function (item) { return item.id === "replay"; }) || {};
    return {
      findings: [],
      result: {
        exchange_id: replay.exchange_id || null,
        status_code: replay.status_code == null ? null : replay.status_code,
        response_length: replay.response_length == null ? null : replay.response_length,
        error: replay.error || null
      }
    };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
}());
