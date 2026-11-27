'use strict';
// Offline smoke test: builds a tiny project, runs depscope, checks the verdicts.
const fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert');
const { spawnSync } = require('child_process');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'depscope-'));
fs.mkdirSync(path.join(dir, 'src'));
fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
  name: 't', scripts: { lint: 'eslint src' },
  dependencies: { chalk: '4.1.2', lodash: '4.17.21' }, devDependencies: { eslint: '8.0.0' },
}));
fs.writeFileSync(path.join(dir, 'src', 'a.js'), "const c = require('chalk');\nconst a = require('axios');\nrequire('fs');\n");
const r = spawnSync('node', [path.join(__dirname, '..', 'bin', 'depscope.js'), dir, '--json', '--no-audit', '--no-outdated', '--no-html'], { encoding: 'utf8' });
assert.strictEqual(r.status, 0, r.stderr);
const out = JSON.parse(r.stdout);
const v = Object.fromEntries(out.packages.map((p) => [p.name, p.verdict]));
assert.deepStrictEqual(v, { chalk: 'keep', lodash: 'remove', eslint: 'keep' });
assert.deepStrictEqual(out.missing.map((m) => m.name), ['axios']);
const f = spawnSync('node', [path.join(__dirname, '..', 'bin', 'depscope.js'), dir, '--no-audit', '--no-outdated', '--no-html', '--fail-on', 'unused'], { encoding: 'utf8' });
assert.strictEqual(f.status, 1);
console.log('ok');