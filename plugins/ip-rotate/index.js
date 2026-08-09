(function () {
  "use strict";

  function origin(value) {
    var match = String(value || "").match(/^(https?):\/\/([^\/?#]+)\/?$/i);
    if (!match || match[2].indexOf("@") !== -1) {
      throw new Error("target_url must be an exact HTTP(S) origin without credentials, path, query, or fragment");
    }
    return match[1].toLowerCase() + "://" + match[2].toLowerCase();
  }

  function enable(input) {
    if (!Array.isArray(input.regions) || !input.regions.length) {
      throw new Error("enable requires at least one AWS region");
    }
    var target = origin(input.target_url);
    return {
      execution: "sequential",
      stop_on_error: true,
      operations: [{
        id: "ip-rotation-enable",
        type: "aws_api_gateway",
        action: "enable",
        target_url: target,
        regions: input.regions.map(String),
        stage_name: String(input.stage_name || "huntproxy")
      }],
      result: { requested_action: "enable", target_origin: target, regions: input.regions.map(String) }
    };
  }

  function disable(input) {
    var target = origin(input.target_url);
    return {
      execution: "sequential",
      stop_on_error: true,
      operations: [{ id: "ip-rotation-disable", type: "aws_api_gateway", action: "disable", target_url: target }],
      result: { requested_action: "disable", target_origin: target }
    };
  }

  function status() {
    return {
      execution: "sequential",
      operations: [{ id: "ip-rotation-status", type: "aws_api_gateway", action: "status" }],
      result: { requested_action: "status" }
    };
  }

  function plan(input, context) {
    if (context.action === "enable") return enable(input);
    if (context.action === "disable") return disable(input);
    if (context.action === "status") return status();
    throw new Error("unsupported IpRotate action");
  }

  function analyze(input, observations, context) {
    var first = observations[0] || {};
    return {
      findings: [],
      result: {
        action: context.action,
        ip_rotation: first.ip_rotation || null,
        error: first.error || null
      }
    };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
})();
