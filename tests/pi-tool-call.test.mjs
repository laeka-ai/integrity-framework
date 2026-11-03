// node --test tests/ : usage and failure exits of the tool-call helper (no dependency, no Pi needed).
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HELPER = fileURLToPath(new URL("../adapters/pi/extension/tool-call.mjs", import.meta.url));
const run = (...a) => spawnSync(process.execPath, [HELPER, ...a], { encoding: "utf8" });

test("wrong arity is a usage failure, nothing on stdout", () => {
  const r = run("only-one");
  assert.equal(r.status, 2);
  assert.equal(r.stdout, "");
});

test("params that are not a JSON object are refused", () => {
  assert.equal(run("/x", "/y.ts", "t", "[1]").status, 2);
  assert.equal(run("/x", "/y.ts", "t", "nope").status, 2);
});

test("a missing Pi install is reported, exit 2", () => {
  const r = run("/nonexistent-pi-dir", "/y.ts", "t", "{}");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /pi not found/);
});
