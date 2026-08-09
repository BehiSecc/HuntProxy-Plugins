(function () {
  "use strict";

  function base(context) {
    if (!context.base_exchange || !context.base_exchange.exchange_id) {
      throw new Error("rotate requires base_exchange_id from a saved semantic request");
    }
    return context.base_exchange;
  }

  function hostname(url) {
    var match = String(url || "").match(/^https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase().replace(/\.$/, "") : "";
  }

  function scopeMatches(host, pattern) {
    pattern = String(pattern || "").toLowerCase().replace(/\.$/, "");
    if (pattern.slice(0, 2) === "*.") {
      var suffix = pattern.slice(1);
      return host.length > suffix.length && host.slice(-suffix.length) === suffix;
    }
    return host === pattern;
  }

  function requireScopedTarget(url, scope) {
    var host = hostname(url);
    if (!host || !scopeMatches(host, scope)) throw new Error("target URL is outside target_scope");
    return host;
  }

  function targetPath(url) {
    var match = String(url || "").match(/^https?:\/\/[^/]+(\/[^#]*)?$/i);
    if (!match) throw new Error("saved target URL must be absolute HTTP(S) without a fragment");
    return match[1] || "/";
  }

  function gateway(value) {
    var normalized = String(value || "").replace(/\/+$/, "");
    var match = normalized.match(/^https:\/\/([a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)(\/[^?#]+)$/i);
    if (!match) throw new Error("gateway_endpoints must be regional HTTPS execute-api URLs including a deployed stage path");
    return { url: normalized, host: match[1].toLowerCase() };
  }

  function provision(input) {
    var host = requireScopedTarget(input.target_url, input.target_scope);
    if (!Array.isArray(input.regions) || !input.regions.length) throw new Error("at least one AWS region is required");
    var stage = String(input.stage_name || "huntproxy");
    return {
      execution: "parallel",
      operations: input.regions.map(function (region, index) {
        return { id: "provision-" + index, type: "aws_api_gateway", action: "provision", region: String(region), target_url: input.target_url, stage_name: stage };
      }),
      result: { target_host: host, target_scope: input.target_scope, regions: input.regions, stage_name: stage }
    };
  }

  function cleanup(input) {
    if (!Array.isArray(input.deployments) || !input.deployments.length) throw new Error("at least one deployment is required");
    return {
      execution: "parallel",
      operations: input.deployments.map(function (deployment, index) {
        return { id: "delete-" + index, type: "aws_api_gateway", action: "delete", region: String(deployment.region), rest_api_id: String(deployment.rest_api_id) };
      }),
      result: { requested_deletions: input.deployments.length }
    };
  }

  function rotate(input, context) {
    var source = base(context);
    var host = requireScopedTarget(source.url, input.target_scope);
    var method = String(source.method || "GET").toUpperCase();
    if (["GET", "HEAD", "OPTIONS"].indexOf(method) === -1 && input.allow_state_changes !== true) {
      throw new Error("non-idempotent base requests require allow_state_changes=true");
    }
    if (!Array.isArray(input.gateway_endpoints) || !input.gateway_endpoints.length) throw new Error("at least one gateway endpoint is required");
    var endpoints = input.gateway_endpoints.map(gateway);
    var repeats = Math.max(1, Math.min(Number(input.requests || endpoints.length), 500));
    targetPath(source.url);
    var operations = [];
    for (var index = 0; index < repeats; index += 1) {
      var endpoint = endpoints[index % endpoints.length];
      var operation = { id: "rotate-" + index, type: "aws_api_gateway", action: "request", base_exchange_id: source.exchange_id, gateway_endpoint: endpoint.url, target_scope: input.target_scope, include_auth: input.include_auth === true };
      operations.push(operation);
    }
    return {
      execution: "sequential",
      operations: operations,
      result: { target_host: host, target_scope: input.target_scope, gateway_hosts: endpoints.map(function (endpoint) { return endpoint.host; }), request_count: operations.length, authentication_included: input.include_auth === true }
    };
  }

  function plan(input, context) {
    if (context.action === "provision") return provision(input);
    if (context.action === "cleanup") return cleanup(input);
    if (context.action === "rotate") return rotate(input, context);
    throw new Error("unsupported IpRotate action");
  }

  function analyze(input, observations, context) {
    if (context.action === "provision") {
      var deployments = observations.filter(function (item) { return item.aws_gateway && item.aws_gateway.action === "provisioned"; }).map(function (item) { return item.aws_gateway; });
      return { findings: [], result: { deployments: deployments, gateway_endpoints: deployments.map(function (item) { return item.endpoint; }), errors: observations.filter(function (item) { return !!item.error; }).map(function (item) { return { id: item.id, code: item.error.code, message: item.error.message }; }) } };
    }
    if (context.action === "cleanup") {
      return { findings: [], result: { deleted: observations.filter(function (item) { return item.aws_gateway && item.aws_gateway.action === "deleted"; }).map(function (item) { return item.aws_gateway; }), errors: observations.filter(function (item) { return !!item.error; }).map(function (item) { return { id: item.id, code: item.error.code, message: item.error.message }; }) } };
    }
    var statuses = {}, errors = {}, evidence = [];
    observations.forEach(function (item) {
      if (item.exchange_id) evidence.push(item.exchange_id);
      if (item.error) { var code = String(item.error.code || "unknown"); errors[code] = (errors[code] || 0) + 1; }
      else { var status = String(item.status_code == null ? "no_status" : item.status_code); statuses[status] = (statuses[status] || 0) + 1; }
    });
    return { findings: [], result: { attempted: observations.length, completed: observations.length - Object.keys(errors).reduce(function (total, key) { return total + errors[key]; }, 0), status_counts: statuses, error_counts: errors, evidence_exchange_ids: evidence } };
  }

  globalThis.HuntProxyPlugin = { plan: plan, analyze: analyze };
})();
