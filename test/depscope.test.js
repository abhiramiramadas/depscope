import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { findPotentiallyUnused } from "../lib/scanner.js";
import { parseArgs, exceedsThreshold } from "../bin/depscope.js";

async function fixture(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "depscope-"));
  for (const [name, content] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(dir, name)), { recursive: true });
    await fs.writeFile(path.join(dir, name), content);
  }
  return dir;
}

test("flags a dependency nothing references", async () => {
  const dir = await fixture({
    "package.json": '{"dependencies":{"left-pad":"1","lodash":"4"}}',
    "index.js": 'import _ from "lodash";'
  });
  assert.deepEqual(await findPotentiallyUnused(dir, ["left-pad", "lodash"]), ["left-pad"]);
});

test("package.json itself does not count as usage", async () => {
  const dir = await fixture({ "package.json": '{"dependencies":{"foo":"1"}}', "a.js": "const x = 1;" });
  assert.deepEqual(await findPotentiallyUnused(dir, ["foo"]), ["foo"]);
});

test("detects require, dynamic import and subpath imports", async () => {
  const dir = await fixture({
    "a.js": 'const a = require("a-pkg"); const b = await import("b-pkg"); import c from "c-pkg/sub";'
  });
  assert.deepEqual(await findPotentiallyUnused(dir, ["a-pkg", "b-pkg", "c-pkg"]), []);
});

test("does not confuse similarly named packages", async () => {
  const dir = await fixture({ "a.js": 'import x from "react-dom";' });
  assert.deepEqual(await findPotentiallyUnused(dir, ["react"]), ["react"]);
});

test("npm scripts and config files count as usage", async () => {
  const dir = await fixture({ ".eslintrc.json": '{"extends":["plugin:prettier/recommended"],"plugins":["prettier"]}' });
  assert.deepEqual(await findPotentiallyUnused(dir, ["prettier", "eslint"], { lint: "eslint ." }), []);
});

test("scoped packages and @types", async () => {
  const dir = await fixture({ "a.ts": 'import { x } from "@scope/pkg";' });
  assert.deepEqual(await findPotentiallyUnused(dir, ["@scope/pkg", "@types/node"]), []);
});

test("parseArgs", () => {
  assert.equal(parseArgs([]).target, ".");
  assert.equal(parseArgs(["x", "--no-audit", "--fail-on", "high"]).failOn, "high");
  assert.throws(() => parseArgs(["--nope"]));
  assert.throws(() => parseArgs(["--fail-on", "bad"]));
});

test("exceedsThreshold", () => {
  assert.equal(exceedsThreshold({ high: 1 }, "high"), true);
  assert.equal(exceedsThreshold({ moderate: 3 }, "high"), false);
  assert.equal(exceedsThreshold({ critical: 1 }, null), false);
});
