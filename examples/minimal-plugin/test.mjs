import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("index.js", import.meta.url), "utf8");
const sandbox = {};
vm.runInNewContext(source, sandbox, { timeout: 250 });
const plugin = sandbox.HuntProxyPlugin;

const context = {
  api_version: 1,
  plugin_id: "minimal-plugin",
  plugin_version: "1.0.0",
  action: "inspect",
  project_id: 1,
  base_exchange: {
    exchange_id: 42,
    method: "GET",
    url: "https://example.test/",
    headers: []
  },
  related_exchanges: [],
  resources: {}
};

const plan = plugin.plan({}, context);
assert.equal(plan.execution, undefined);
assert.deepEqual(JSON.parse(JSON.stringify(plan.operations)), [{
  id: "replay",
  type: "http_request",
  base_exchange_id: 42,
  method: "GET",
  protocol: "auto"
}]);
assert.throws(
  () => plugin.plan({}, { ...context, base_exchange: null }),
  /saved base exchange/
);
assert.throws(
  () => plugin.plan({}, { ...context, base_exchange: { ...context.base_exchange, method: "POST" } }),
  /only replays read-oriented/
);
assert.throws(() => plugin.plan([], context), /input must be an object/);
assert.throws(() => plugin.plan(null, context), /input must be an object/);
assert.throws(() => plugin.plan(1, context), /input must be an object/);
assert.throws(() => plugin.plan({ unexpected: true }, context), /does not accept input fields/);

const analysis = plugin.analyze({}, [{
  id: "replay",
  exchange_id: 43,
  status_code: 200,
  response_length: 128,
  error: null
}], context);
assert.deepEqual(JSON.parse(JSON.stringify(analysis)), {
  findings: [],
  result: {
    exchange_id: 43,
    status_code: 200,
    response_length: 128,
    error: null
  }
});

console.log("Minimal plugin plan and analysis passed.");
