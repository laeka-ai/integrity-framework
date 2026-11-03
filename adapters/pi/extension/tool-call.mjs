#!/usr/bin/env node
// tool-call.mjs: call ONE tool of a Pi extension the way Pi calls it, with no model turn.
// The decision is born of the extension's own tool, never of a text the host wrote.
//
// - The extension is imported by jiti with Pi's own aliases (pi-coding-agent dist/core/extensions/loader.js,
//   getAliases): `typebox` and `@earendil-works/pi-ai` are pi's copies, resolved from pi's loader, never from the
//   extension's directory (they are not hoisted: in an install they sit under pi-coding-agent/node_modules/).
// - Its default export gets a MINIMAL ExtensionAPI: registerTool, and nothing else (any other call throws, so an
//   extension that needs more fails here instead of running half loaded).
// - The arguments go through pi-ai's validateToolArguments, as pi's agent loop does before execute.
// - stdout: ONE JSON line {"tool", "isError", "result"}; `result` is exactly what pi puts in tool_execution_end:
//   the tool's return, or pi's error result {content: [{type: "text", text: <message>}], details: {}}.
//
// usage: node tool-call.mjs <pi-dir> <extension.ts> <tool> <params JSON>
//   <pi-dir>: the directory whose node_modules holds Pi
//   <tool>: the name of a tool the extension registers (a tool that needs Pi's dialog UI is not callable here)
// exit: 0 the tool was called (its isError is in the line), 2 usage or load failure (nothing on stdout).
import { createRequire } from "node:module";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

function fail(message) {
  process.stderr.write(`tool-call: ${message}\n`);
  process.exit(2);
}

const [piDir, extension, toolName, paramsJson] = process.argv.slice(2);
if (!piDir || !extension || !toolName || paramsJson === undefined || process.argv.length !== 6) {
  fail("usage: tool-call.mjs <pi-dir> <extension.ts> <tool> <params JSON>");
}
let params;
try {
  params = JSON.parse(paramsJson);
} catch {
  fail("params must be JSON");
}
if (params === null || typeof params !== "object" || Array.isArray(params)) fail("params must be a JSON object");

const loader = path.resolve(piDir, "node_modules", "@earendil-works", "pi-coding-agent", "dist", "core", "extensions",
                            "loader.js");
let jiti, validateToolArguments;
try {
  const fromPi = createRequire(loader);
  const { createJiti } = await import(pathToFileURL(fromPi.resolve("jiti/package.json").replace(/package\.json$/,
                                                                                                "lib/jiti-static.mjs")).href);
  const probe = createJiti(pathToFileURL(loader).href);
  const piAiCompat = probe.esmResolve("@earendil-works/pi-ai/compat", { parentURL: pathToFileURL(loader).href });
  const alias = {
    typebox: fromPi.resolve("typebox"),
    "typebox/compile": fromPi.resolve("typebox/compile"),
    "typebox/value": fromPi.resolve("typebox/value"),
    "@earendil-works/pi-ai": piAiCompat.startsWith("file:") ? new URL(piAiCompat).pathname : piAiCompat,
    "@earendil-works/pi-ai/compat": piAiCompat.startsWith("file:") ? new URL(piAiCompat).pathname : piAiCompat,
  };
  if (process.env.APPEL_OUTIL_RESOLUTION === "1") process.stderr.write(`tool-call: ${JSON.stringify(alias)}\n`);
  jiti = createJiti(pathToFileURL(loader).href, { moduleCache: false, alias });
  ({ validateToolArguments } = await jiti.import("@earendil-works/pi-ai"));
} catch (e) {
  fail(`pi not found under ${piDir}: ${e instanceof Error ? e.message : String(e)}`);
}

const tools = new Map();
const api = new Proxy({}, {
  get(_target, key) {
    if (key === "registerTool") return (tool) => { tools.set(tool.name, tool); };
    throw new Error(`the minimal ExtensionAPI has no ${String(key)}`);
  },
});
try {
  const factory = await jiti.import(path.resolve(extension), { default: true });
  if (typeof factory !== "function") throw new Error("no default export");
  await factory(api);
} catch (e) {
  fail(`extension not loaded: ${e instanceof Error ? e.message : String(e)}`);
}
const tool = tools.get(toolName);
if (!tool) fail(`the extension registers no ${toolName}`);

let result, isError = false;
const id = `tc-${process.pid}`;
try {
  const args = validateToolArguments(tool, { type: "toolCall", id, name: toolName, arguments: params });
  result = await tool.execute(id, args, undefined, undefined, undefined);
} catch (e) {
  result = { content: [{ type: "text", text: e instanceof Error ? e.message : String(e) }], details: {} };
  isError = true;
}
process.stdout.write(JSON.stringify({ tool: toolName, isError, result }) + "\n");
