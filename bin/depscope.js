#!/usr/bin/env node
'use strict';

/*
 * depscope - find out what you can safely remove from a Node project, what is
 * vulnerable, and what is outdated, with copy-paste fixes and proof.
 * Zero dependencies. Never edits the project it scans.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync, spawn } = require('child_process');
const { builtinModules } = require('module');

const VERSION = '1.0.0';
const START = Date.now();
const SEV_ORDER = ['low', 'moderate', 'high', 'critical'];

// ---------------------------------------------------------------- CLI ----

const HELP = `
depscope ${VERSION} - dependency cleanup plan for Node.js projects

Usage
  depscope [folder] [options]

Options
  --no-audit            skip npm audit (works offline)
  --no-outdated         skip npm outdated (works offline)
  --no-html             do not write the HTML report
  --out <file>          where to write the report (default: <folder>/depscope-report.html)
  --json                print the full result as JSON to stdout
  --open                open the report in your browser when done
  --fail-on <list>      exit 1 if any of: vuln, unused, missing, any (comma separated)
  --fail-severity <s>   lowest severity that counts for "vuln": low|moderate|high|critical (default high)
  -v, --version         print version
  -h, --help            show this help

Exit codes
  0  done (or nothing tripped --fail-on)
  1  a --fail-on rule tripped
  2  could not run (bad folder, bad package.json, bad option)
`;

function die(msg) {
  console.error('depscope: ' + msg);
  process.exit(2);
}

function parseArgs(argv) {
  const o = {
    target: '.', audit: true, outdated: true, html: true, json: false, open: false,
    out: null, failOn: [], failSeverity: 'high', help: false, version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--no-audit') o.audit = false;
    else if (a === '--no-outdated') o.outdated = false;
    else if (a === '--no-html') o.html = false;
    else if (a === '--json') o.json = true;
    else if (a === '--open') o.open = true;
    else if (a === '--out') o.out = argv[++i] || die('--out needs a file path');
    else if (a === '--fail-on') o.failOn = String(argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--fail-severity') o.failSeverity = String(argv[++i] || '');
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a.startsWith('-')) die(`unknown option ${a}. Run depscope --help.`);
    else o.target = a;
  }
  if (!SEV_ORDER.includes(o.failSeverity)) die('--fail-severity must be low, moderate, high or critical');
  for (const f of o.failOn) if (!['vuln', 'unused', 'missing', 'any'].includes(f)) die(`--fail-on: unknown rule "${f}"`);
  return o;
}

// ------------------------------------------------------------ helpers ----

function readJSON(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8').replace(/^\uFEFF/, '')); } catch { return null; }
}

function plural(n, one, many) { return `${n} ${n === 1 ? one : many || one + 's'}`; }

function runNpm(args, cwd, timeout) {
  const r = spawnSync('npm', args, {
    cwd, encoding: 'utf8', shell: process.platform === 'win32',
    maxBuffer: 64 * 1024 * 1024, timeout: timeout || 120000,
  });
  return r;
}

function parseSemver(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v || ''));
  return m ? [+m[1], +m[2], +m[3]] : null;
}

function bumpType(current, latest) {
  const a = parseSemver(current), b = parseSemver(latest);
  if (!a || !b) return 'unknown';
  if (a[0] !== b[0]) return 'major';
  if (a[0] === 0 && a[1] !== b[1]) return 'major'; // 0.x minors are breaking by convention
  if (a[1] !== b[1]) return 'minor';
  return 'patch';
}

// ------------------------------------------------------- source scanning --

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', 'coverage',
  '.cache', '.turbo', '.vercel', '.output', '.parcel-cache', 'vendor', 'tmp', '.expo',
]);
const JS_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.vue', '.svelte', '.astro', '.html', '.htm', '.mdx']);
const CSS_EXT = new Set(['.css', '.scss', '.sass', '.less']);
const CONFIG_JSON_OK = /^\.|tsconfig|jsconfig|config|rc\b|babel|eslint|prettier|jest|vite|vercel|netlify|turbo|nx\.|renovate|lerna|firebase|angular|workspace/i;

function walk(root) {
  const files = [];
  (function rec(dir) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!IGNORE_DIRS.has(e.name)) rec(p); }
      else if (e.isFile()) files.push(p);
    }
  })(root);
  return files;
}

function classify(p) {
  const base = path.basename(p);
  const ext = path.extname(p).toLowerCase();
  if (/^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|package\.json|depscope-report\.(html|json))$/.test(base)) return null;
  if (/\.config\.|^\.[\w.-]*rc(\.|$)/.test(base) && (JS_EXT.has(ext) || ext === '' || ext === '.json')) return 'config';
  if (JS_EXT.has(ext) || CSS_EXT.has(ext)) return 'src';
  if (/^\.(eslintrc|babelrc|prettierrc|npmrc|browserslistrc|huskyrc|stylelintrc)/.test(base)) return 'config';
  if (['.json', '.yml', '.yaml', '.toml'].includes(ext)) return 'config';
  if (['Dockerfile', 'Makefile', 'Procfile'].includes(base)) return 'config';
  if (p.split(path.sep).includes('.husky')) return 'config';
  return null;
}

function specToPkg(spec, aliasNames) {
  if (!spec || /[\s${}()]/.test(spec)) return null;
  if (/^[.\/~#]/.test(spec) || /^[a-z][a-z0-9+.-]*:/i.test(spec)) return null; // relative, abs, alias, node:, http:
  const seg = spec.split('/');
  let name;
  if (spec[0] === '@') { if (!seg[1]) return null; name = seg[0] + '/' + seg[1]; } else name = seg[0];
  if (!/^(@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i.test(name)) return null;
  if (aliasNames.has(name)) return null;
  return name;
}

const IMPORT_RE = /(?:\bfrom|\bimport|\brequire|\brequire\.resolve|\bimport\.meta\.resolve|\bjest\.(?:mock|requireActual|doMock)|\bvi\.(?:mock|importActual))\s*\(?\s*['"]([^'"\n]+)['"]/g;
const CSS_IMPORT_RE = /@(?:import|use|forward)\s+(?:url\()?\s*['"]?~?([^'")\s;]+)/g;

function lineCounter(text) {
  let pos = 0, line = 1;
  return (idx) => {
    for (; pos < idx; pos++) if (text.charCodeAt(pos) === 10) line++;
    return line;
  };
}

function aliasesFor(name) {
  const full = [name];
  const short = [];
  let m;
  if ((m = name.match(/^eslint-plugin-(.+)$/))) short.push(m[1]);
  if ((m = name.match(/^eslint-config-(.+)$/))) short.push(m[1]);
  if ((m = name.match(/^@([^/]+)\/eslint-plugin(?:-.+)?$/))) short.push('@' + m[1]);
  if ((m = name.match(/^babel-(?:plugin|preset)-(.+)$/))) short.push(m[1]);
  if ((m = name.match(/^prettier-plugin-(.+)$/))) short.push(m[1]);
  return { full, short };
}

function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Packages that tools usually load by name from config, so "no import found" proves little.
const TOOLISH = /^(@types\/|@babel\/|@typescript-eslint\/|@vitejs\/|@testing-library\/|@storybook\/|@jest\/)|-loader$|-plugin$|^(eslint|babel|postcss|webpack|rollup|vite|tailwindcss|autoprefixer|sass|typescript|husky|lint-staged|prettier|ts-|jest|vitest|mocha|cypress|playwright|storybook|nodemon|esbuild|swc|tsx|rimraf|cross-env|concurrently|dotenv-cli|npm-run-all|stylelint|commitlint|semantic-release|turbo|nx)/;

const KNOWN_BINS = {
  typescript: ['tsc', 'tsserver'], '@babel/cli': ['babel'], '@angular/cli': ['ng'], 'ts-node': ['ts-node'],
  '@nestjs/cli': ['nest'], 'webpack-cli': ['webpack'], '@playwright/test': ['playwright'], 'npm-run-all': ['npm-run-all', 'run-s', 'run-p'],
  'lint-staged': ['lint-staged'], '@commitlint/cli': ['commitlint'], 'cross-env': ['cross-env'], 'ts-jest': ['ts-jest'], 'vite': ['vite'],
};

function analyze(target, opts) {
  const pkgPath = path.join(target, 'package.json');
  if (!fs.existsSync(pkgPath)) die(`no package.json in ${target}. Point depscope at a Node project folder.`);
  const pkg = readJSON(pkgPath);
  if (!pkg) die('package.json is not valid JSON. Fix it and run again.');

  const nm = path.join(target, 'node_modules');
  const hasNM = fs.existsSync(nm);

  // 1. What is declared
  const declared = new Map();
  const dupes = [];
  for (const [key, kind] of [['dependencies', 'prod'], ['devDependencies', 'dev'], ['optionalDependencies', 'optional']]) {
    for (const [name, range] of Object.entries(pkg[key] || {})) {
      if (declared.has(name)) dupes.push(name);
      else declared.set(name, { name, kind, range, installed: null, bins: [], peers: [] });
    }
  }
  const peerDeclared = new Set(Object.keys(pkg.peerDependencies || {}));

  // 2. What is installed (versions, bin names, peer requirements)
  const peerOf = new Map();
  for (const d of declared.values()) {
    const ip = readJSON(path.join(nm, ...d.name.split('/'), 'package.json'));
    if (ip) {
      d.installed = ip.version || null;
      const b = ip.bin;
      if (typeof b === 'string') d.bins = [d.name.split('/').pop()];
      else if (b && typeof b === 'object') d.bins = Object.keys(b);
      d.peers = Object.keys(ip.peerDependencies || {});
      for (const p of d.peers) { if (!peerOf.has(p)) peerOf.set(p, []); peerOf.get(p).push(d.name); }
    } else {
      d.bins = KNOWN_BINS[d.name] || [d.name.split('/').pop()];
    }
  }

  // 3. Path aliases (tsconfig/jsconfig) so "@/utils" is not reported as a missing package
  const aliasNames = new Set();
  for (const f of ['tsconfig.json', 'jsconfig.json']) {
    let raw;
    try { raw = fs.readFileSync(path.join(target, f), 'utf8'); } catch { continue; }
    const cfg = (() => { try { return JSON.parse(raw.replace(/\/\*[\s\S]*?\*\/|^\s*\/\/.*$/gm, '').replace(/,\s*([}\]])/g, '$1')); } catch { return null; } })();
    const co = cfg && cfg.compilerOptions;
    if (!co) continue;
    for (const k of Object.keys(co.paths || {})) aliasNames.add(k.replace(/\/?\*$/, ''));
    if (co.baseUrl) {
      try {
        for (const e of fs.readdirSync(path.join(target, co.baseUrl))) aliasNames.add(e.replace(/\.[^.]+$/, ''));
      } catch { /* ignore */ }
    }
  }

  // 4. Scan files
  const files = walk(target);
  const usage = new Map();       // pkg -> [{file,line,kind}]
  const missingHits = new Map(); // pkg -> {file,line}
  const configTexts = [];
  let scanned = 0, hasTS = false;

  const addUse = (name, file, line, kind) => {
    if (!usage.has(name)) usage.set(name, []);
    const arr = usage.get(name);
    if (!arr.some((h) => h.file === file)) arr.push({ file, line, kind });
  };
  const builtins = new Set(builtinModules.map((m) => m.split('/')[0]));

  for (const f of files) {
    const cls = classify(f);
    if (!cls) continue;
    const ext = path.extname(f).toLowerCase();
    if (cls === 'config' && ext === '.json' && !CONFIG_JSON_OK.test(path.basename(f))) continue;
    let st;
    try { st = fs.statSync(f); } catch { continue; }
    if (st.size > 1000000) continue;
    let text;
    try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
    scanned++;
    const rel = path.relative(target, f).split(path.sep).join('/');
    if (['.ts', '.tsx', '.mts', '.cts'].includes(ext)) hasTS = true;

    if (JS_EXT.has(ext)) {
      const lc = lineCounter(text);
      IMPORT_RE.lastIndex = 0;
      let m;
      while ((m = IMPORT_RE.exec(text))) {
        const name = specToPkg(m[1], aliasNames);
        if (!name) continue;
        const line = lc(m.index);
        addUse(name, rel, line, 'import');
        if (!builtins.has(name) && !missingHits.has(name)) missingHits.set(name, { file: rel, line });
      }
    } else if (CSS_EXT.has(ext)) {
      const lc = lineCounter(text);
      CSS_IMPORT_RE.lastIndex = 0;
      let m;
      while ((m = CSS_IMPORT_RE.exec(text))) {
        const name = specToPkg(m[1], aliasNames);
        if (name) addUse(name, rel, lc(m.index), 'import');
      }
    }
    if (cls === 'config') configTexts.push({ rel, text });
  }

  // package.json itself counts as config, minus the dependency lists
  const pkgForConfig = { ...pkg };
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'scripts', 'name', 'version', 'description']) delete pkgForConfig[k];
  configTexts.push({ rel: 'package.json', text: JSON.stringify(pkgForConfig, null, 2) });

  // 5. npm scripts: which tools do they run?
  const scripts = pkg.scripts || {};
  const scriptTokens = new Map(); // token -> script name
  for (const [sname, cmd] of Object.entries(scripts)) {
    for (const tok of String(cmd).split(/[\s;&|()<>"'=]+/)) if (tok && !scriptTokens.has(tok)) scriptTokens.set(tok, sname);
  }

  // 6. Verdict per declared package
  const lineOf = (text, idx) => { let l = 1; for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) l++; return l; };
  const packages = [];
  const sourceCount = scanned;

  for (const d of declared.values()) {
    const evidence = [];
    const imports = usage.get(d.name) || [];
    for (const h of imports.slice(0, 4)) evidence.push({ type: 'import', where: `${h.file}:${h.line}` });
    let verdict = null, reason = '';

    if (imports.length) {
      verdict = 'keep';
      reason = `Imported in ${plural(imports.length, 'file')}.`;
    }

    // scripts
    if (!verdict) {
      for (const b of d.bins) {
        if (scriptTokens.has(b)) {
          verdict = 'keep';
          reason = `Run by the "${scriptTokens.get(b)}" script.`;
          evidence.push({ type: 'script', where: `scripts.${scriptTokens.get(b)}` });
          break;
        }
      }
    }

    // config files
    if (!verdict) {
      const al = aliasesFor(d.name);
      const fullRe = new RegExp('(?<![\\w@/.-])(?:' + al.full.map(escRe).join('|') + ')(?![\\w-])');
      const shortRe = al.short.length
        ? new RegExp('["\'`](?:plugin:|extends:)?(?:' + al.short.map(escRe).join('|') + ')(?:/[^"\'`]*)?["\'`]')
        : null;
      for (const c of configTexts) {
        const m = fullRe.exec(c.text) || (shortRe && shortRe.exec(c.text));
        if (m) {
          verdict = 'keep';
          reason = `Named in ${c.rel}.`;
          evidence.push({ type: 'config', where: `${c.rel}:${lineOf(c.text, m.index)}` });
          break;
        }
      }
    }

    // peer of something installed
    if (!verdict) {
      const owners = (peerOf.get(d.name) || []).filter((n) => n !== d.name);
      if (owners.length) {
        verdict = 'keep';
        reason = `Required as a peer dependency by ${owners.slice(0, 3).join(', ')}.`;
        evidence.push({ type: 'peer', where: owners.join(', ') });
      }
    }

    // @types/*
    if (!verdict && d.name.startsWith('@types/')) {
      const base = d.name.slice(7).replace('__', '/');
      const baseUsed = usage.has(base) || (base === 'node' && (hasTS || declared.has('typescript'))) || (base.startsWith('node') && hasTS);
      if (baseUsed) {
        verdict = 'keep';
        reason = `Type definitions for ${base}, which your code uses.`;
        evidence.push({ type: 'types', where: base });
      } else if (declared.has(base)) {
        verdict = 'remove';
        reason = `Type definitions for ${base}, but nothing in your code imports ${base}.`;
      }
    }

    // nothing found
    if (!verdict) {
      if (sourceCount === 0) {
        verdict = 'review';
        reason = 'No source files were found to check against.';
      } else if (TOOLISH.test(d.name)) {
        verdict = 'review';
        reason = 'No import or script uses it, but tools like this are often loaded by name from config, so this is not proof it is unused.';
      } else if (peerDeclared.has(d.name)) {
        verdict = 'review';
        reason = 'Also listed as a peer dependency of this package, so it may be there on purpose.';
      } else {
        verdict = 'remove';
        reason = 'No import, require, script, config entry or peer requirement points to it.';
      }
    }

    packages.push({
      name: d.name, kind: d.kind, range: d.range, installed: d.installed,
      verdict, reason, evidence,
      latest: null, bump: null, wanted: null,
    });
  }

  // 7. Missing: imported but not declared
  const missing = [];
  const selfName = pkg.name;
  const hasWorkspaces = !!pkg.workspaces;
  if (!hasWorkspaces) {
    for (const [name, hit] of missingHits) {
      if (declared.has(name) || peerDeclared.has(name) || name === selfName || builtins.has(name)) continue;
      if (/^(bun|deno)$/.test(name)) continue;
      const ip = readJSON(path.join(nm, ...name.split('/'), 'package.json'));
      missing.push({ name, where: `${hit.file}:${hit.line}`, installedByAccident: !!ip });
    }
  }

  // 8. Script checks
  const scriptIssues = [];
  for (const need of ['start', 'build', 'test']) {
    if (!scripts[need]) {
      if (need === 'start' && !pkg.main && !pkg.bin && !fs.existsSync(path.join(target, 'index.js'))) continue;
      scriptIssues.push({ level: 'info', text: `No "${need}" script.`, fix: need === 'test' ? 'Add one so CI and other developers know how to run tests.' : null });
    }
  }
  if (scripts.test && /no test specified/.test(scripts.test)) {
    scriptIssues.push({ level: 'warn', text: 'The "test" script is still the npm placeholder.', fix: 'It exits with an error. Replace it with a real test command.' });
  }
  const FILE_ARG = /(?:^|[\s;&|])(?:node|ts-node|tsx|nodemon|bun|deno run)\s+(?:-{1,2}[\w-]+(?:=\S+)?\s+)*([^\s&|;<>"']+\.(?:c|m)?[jt]sx?)/g;
  for (const [sname, cmd] of Object.entries(scripts)) {
    FILE_ARG.lastIndex = 0;
    let m;
    while ((m = FILE_ARG.exec(String(cmd)))) {
      const rel = m[1].replace(/^\.\//, '');
      if (/[*$]/.test(rel)) continue;
      if (!fs.existsSync(path.join(target, rel))) scriptIssues.push({ level: 'warn', text: `Script "${sname}" runs ${m[1]}, which does not exist.`, fix: null });
    }
  }
  if (pkg.main && !fs.existsSync(path.join(target, pkg.main))) scriptIssues.push({ level: 'warn', text: `"main" points to ${pkg.main}, which does not exist.`, fix: null });
  const binFiles = typeof pkg.bin === 'string' ? [pkg.bin] : Object.values(pkg.bin || {});
  for (const b of binFiles) if (!fs.existsSync(path.join(target, b))) scriptIssues.push({ level: 'warn', text: `"bin" points to ${b}, which does not exist.`, fix: null });
  for (const d of dupes) scriptIssues.push({ level: 'warn', text: `${d} is listed in more than one dependency section.`, fix: 'Keep it in one place.' });
  if (!hasNM) scriptIssues.push({ level: 'info', text: 'node_modules is missing, so versions and peer requirements could not be read.', fix: 'Run npm install and scan again for sharper results.' });

  // 9. Outdated
  const checks = { audit: { status: 'skipped', note: '' }, outdated: { status: 'skipped', note: '' } };
  if (opts.outdated) {
    const r = runNpm(['outdated', '--json'], target, 90000);
    let data = null;
    try { data = JSON.parse(r.stdout || '{}'); } catch { /* ignore */ }
    if (r.error || data === null || (data && data.error)) {
      checks.outdated = { status: 'failed', note: (data && data.error && data.error.summary) || (r.error && r.error.message) || 'npm outdated did not return usable output. Are you offline?' };
    } else {
      checks.outdated = { status: 'ok', note: '' };
      for (const p of packages) {
        const o = data[p.name];
        if (!o) continue;
        const o1 = Array.isArray(o) ? o[0] : o;
        p.installed = p.installed || o1.current || null;
        p.latest = o1.latest || null;
        p.wanted = o1.wanted || null;
        p.bump = o1.current && o1.latest && o1.current !== o1.latest ? bumpType(o1.current, o1.latest) : null;
        if (p.bump === 'unknown') p.bump = null;
      }
      if (!hasNM) checks.outdated.note = 'Nothing is installed, so "current" versions are unknown. Run npm install first.';
    }
  }

  // 10. Audit
  const vulns = [];
  let auditCounts = null;
  if (opts.audit) {
    if (!fs.existsSync(path.join(target, 'package-lock.json')) && !fs.existsSync(path.join(target, 'npm-shrinkwrap.json'))) {
      checks.audit = { status: 'failed', note: 'There is no package-lock.json, so npm audit cannot run. This does NOT mean you have 0 vulnerabilities. Run npm install --package-lock-only first.' };
    } else {
      const r = runNpm(['audit', '--json'], target, 120000);
      let data = null;
      try { data = JSON.parse(r.stdout || ''); } catch { /* ignore */ }
      if (r.error || !data || data.error) {
        checks.audit = { status: 'failed', note: (data && data.error && (data.error.summary || data.error.code)) || (r.error && r.error.message) || 'npm audit did not return usable output. Are you offline?' };
      } else {
        checks.audit = { status: 'ok', note: '' };
        auditCounts = (data.metadata && data.metadata.vulnerabilities) || null;
        for (const v of Object.values(data.vulnerabilities || {})) {
          const advisories = (v.via || []).filter((x) => typeof x === 'object');
          const first = advisories[0];
          const via = (v.via || []).filter((x) => typeof x === 'string');
          let fix = { kind: 'none', cmd: null, text: 'No fix is published yet. Consider replacing this package or watching the advisory.' };
          const fa = v.fixAvailable;
          if (fa === true) fix = { kind: 'auto', cmd: 'npm audit fix', text: 'Fixed by npm audit fix, no breaking changes.' };
          else if (fa && typeof fa === 'object') {
            fix = {
              kind: fa.isSemVerMajor ? 'major' : 'direct',
              cmd: `npm install ${fa.name}@${fa.version}`, pkg: fa.name,
              text: fa.isSemVerMajor
                ? `Needs ${fa.name}@${fa.version}, a major upgrade that may break your code.`
                : `Fixed by upgrading ${fa.name} to ${fa.version}.`,
            };
          }
          vulns.push({
            name: v.name, severity: v.severity, direct: !!v.isDirect,
            title: first ? first.title : (via.length ? `Inherited from ${via.join(', ')}` : 'Known vulnerability'),
            url: first && first.url ? first.url : null,
            range: v.range || null, fix,
          });
        }
        vulns.sort((a, b) => SEV_ORDER.indexOf(b.severity) - SEV_ORDER.indexOf(a.severity) || a.name.localeCompare(b.name));
      }
    }
  }

  return {
    project: { name: pkg.name || path.basename(target), version: pkg.version || null, path: target },
    scan: { files: scanned, ms: Date.now() - START, nodeModules: hasNM },
    packages, missing, scriptIssues, vulns, auditCounts, checks,
  };
}

// ------------------------------------------------------- plan + score ----

function buildPlan(r) {
  const plan = [];
  const rem = r.packages.filter((p) => p.verdict === 'remove');
  const removed = new Set(rem.map((p) => p.name));
  // vulnerabilities that disappear once the unused package is gone
  const cleared = r.vulns.filter((v) => removed.has(v.name));
  const live = r.vulns.filter((v) => !removed.has(v.name) && !(v.fix.pkg && removed.has(v.fix.pkg)));
  if (rem.length) {
    plan.push({
      id: 'remove', title: `Remove ${plural(rem.length, 'unused package')}`,
      why: 'Nothing in your code, scripts or config points to them. Skim the list below, then run it.'
        + (cleared.length ? ` This also clears ${plural(cleared.length, 'vulnerability', 'vulnerabilities')}.` : ''),
      cmds: ['npm uninstall ' + rem.map((p) => p.name).join(' ')], risk: 'medium',
    });
  }
  if (r.missing.length) {
    plan.push({
      id: 'missing', title: `Declare ${plural(r.missing.length, 'package')} your code already imports`,
      why: 'They work today only because something else installed them. That can break on a fresh install.',
      cmds: ['npm install ' + r.missing.map((m) => m.name).join(' ')], risk: 'low',
    });
  }
  const auto = live.filter((v) => v.fix.kind === 'auto');
  const direct = live.filter((v) => v.fix.kind === 'direct');
  const major = live.filter((v) => v.fix.kind === 'major');
  if (auto.length || direct.length) {
    const cmds = [];
    if (auto.length) cmds.push('npm audit fix');
    for (const v of direct) if (!cmds.includes(v.fix.cmd)) cmds.push(v.fix.cmd);
    plan.push({
      id: 'vuln', title: `Fix ${plural(auto.length + direct.length, 'vulnerability', 'vulnerabilities')} without breaking changes`,
      why: 'These have a fix inside the version ranges you can safely take.', cmds, risk: 'low',
    });
  }
  if (major.length) {
    plan.push({
      id: 'vuln-major', title: `Fix ${plural(major.length, 'vulnerability', 'vulnerabilities')} that need a major upgrade`,
      why: 'The fix changes a major version, so run your tests after each one.',
      cmds: [...new Set(major.map((v) => v.fix.cmd))], risk: 'high',
    });
  }
  const safeUp = r.packages.filter((p) => p.bump && p.bump !== 'major' && p.wanted && p.installed && p.wanted !== p.installed && !removed.has(p.name));
  if (safeUp.length) {
    plan.push({
      id: 'update', title: `Update ${plural(safeUp.length, 'package')} within your version ranges`,
      why: 'Patch and minor updates your package.json already allows.', cmds: ['npm update'], risk: 'low',
    });
  }
  const majorUp = r.packages.filter((p) => p.bump === 'major' && p.latest && !removed.has(p.name));
  if (majorUp.length) {
    plan.push({
      id: 'major', title: `Major updates available (${majorUp.length})`,
      why: 'Read each changelog first. Do these one at a time.',
      cmds: majorUp.slice(0, 12).map((p) => `npm install ${p.name}@${p.latest}`), risk: 'high',
      more: Math.max(0, majorUp.length - 12),
    });
  }
  return plan;
}

function score(r) {
  const parts = [];
  const sevPts = { critical: 15, high: 8, moderate: 3, low: 1 };
  const vLost = Math.min(40, r.vulns.reduce((s, v) => s + (sevPts[v.severity] || 0), 0));
  parts.push({ label: 'Vulnerabilities', lost: vLost, detail: r.vulns.length ? `${r.vulns.length} found` : 'none found' });
  const rem = r.packages.filter((p) => p.verdict === 'remove').length;
  parts.push({ label: 'Unused packages', lost: Math.min(20, rem * 2), detail: `${rem} to remove` });
  const maj = r.packages.filter((p) => p.bump === 'major').length;
  const mnr = r.packages.filter((p) => p.bump === 'minor' || p.bump === 'patch').length;
  parts.push({ label: 'Outdated', lost: Math.min(15, maj * 2) + Math.min(5, Math.round(mnr * 0.5)), detail: `${maj} major, ${mnr} smaller` });
  parts.push({ label: 'Undeclared imports', lost: Math.min(12, r.missing.length * 3), detail: `${r.missing.length} found` });
  const warn = r.scriptIssues.filter((s) => s.level === 'warn').length;
  parts.push({ label: 'Scripts and metadata', lost: Math.min(8, warn * 2), detail: `${warn} problems` });
  const total = Math.max(0, 100 - parts.reduce((s, p) => s + p.lost, 0));
  const label = total >= 90 ? 'Healthy' : total >= 75 ? 'Mostly fine' : total >= 50 ? 'Needs attention' : 'Needs work';
  return { total, label, parts };
}

// ------------------------------------------------------------- report ----

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function headline(r) {
  const rem = r.packages.filter((p) => p.verdict === 'remove').length;
  const maj = r.packages.filter((p) => p.bump === 'major').length;
  const up = r.packages.filter((p) => p.bump).length;
  const bits = [];
  if (r.vulns.length) bits.push(`${plural(r.vulns.length, 'vulnerability', 'vulnerabilities')} to fix`);
  if (rem) bits.push(`${plural(rem, 'package')} you can probably remove`);
  if (r.missing.length) bits.push(`${plural(r.missing.length, 'undeclared import')}`);
  if (up) bits.push(`${plural(up, 'update')} waiting${maj ? ` (${maj} major)` : ''}`);
  if (!bits.length) return 'Nothing needs fixing. This project looks healthy.';
  if (bits.length === 1) return `Found ${bits[0]}.`;
  return `Found ${bits.slice(0, -1).join(', ')} and ${bits[bits.length - 1]}.`;
}

function renderHTML(r, plan, sc) {
  const cmd = (c) => `<div class="cmd"><code>${esc(c)}</code><button type="button" class="copy" data-copy="${esc(c)}">Copy</button></div>`;
  const verdictLabel = { remove: 'Remove', review: 'Review', keep: 'Keep' };
  const circ = 2 * Math.PI * 52;
  const dash = (sc.total / 100) * circ;
  const ringColor = sc.total >= 75 ? 'var(--keep)' : sc.total >= 50 ? 'var(--review)' : 'var(--remove)';

  const checkChip = (name, c) => {
    const txt = c.status === 'ok' ? 'checked' : c.status === 'skipped' ? 'skipped' : 'could not run';
    return `<span class="chip ${c.status}" title="${esc(c.note)}">${esc(name)}: ${txt}</span>`;
  };
  const checkNotes = ['audit', 'outdated'].filter((k) => r.checks[k].note)
    .map((k) => `<p class="note ${r.checks[k].status}">${esc(r.checks[k].note)}</p>`).join('');

  const planHTML = plan.length ? plan.map((s) => `
    <article class="step risk-${s.risk}">
      <header><h3>${esc(s.title)}</h3><span class="risk">${s.risk === 'low' ? 'low risk' : s.risk === 'medium' ? 'check first' : 'may break things'}</span></header>
      <p>${esc(s.why)}</p>
      ${s.cmds.map(cmd).join('')}
      ${s.more ? `<p class="muted">and ${s.more} more in the table below.</p>` : ''}
    </article>`).join('') : '<p class="empty">No fixes to run. Scan again after your next dependency change.</p>';

  const counts = { all: r.packages.length, remove: 0, review: 0, keep: 0, outdated: 0 };
  for (const p of r.packages) { counts[p.verdict]++; if (p.bump) counts.outdated++; }
  const order = { remove: 0, review: 1, keep: 2 };
  const rows = [...r.packages].sort((a, b) => order[a.verdict] - order[b.verdict] || a.name.localeCompare(b.name)).map((p) => {
    const ver = p.installed
      ? `${esc(p.installed)}${p.latest && p.bump ? ` <span class="arrow">to</span> ${esc(p.latest)} <b class="bump ${p.bump}">${esc(p.bump)}</b>` : ''}`
      : `<span class="muted">${esc(p.range)}</span>`;
    const ev = p.evidence.length ? `<ul class="ev">${p.evidence.map((e) => `<li><span class="evtype">${esc({ import: 'imported at', script: 'used by', config: 'named at', peer: 'peer of', types: 'types for' }[e.type])}</span> <code>${esc(e.where)}</code></li>`).join('')}</ul>` : '';
    const proof = p.verdict === 'keep' ? '' : `<p class="scope">Searched ${plural(r.scan.files, 'file')}, your npm scripts, config files and installed peer requirements.</p>`;
    const act = p.verdict === 'remove' ? cmd(`npm uninstall ${p.name}`) : '';
    return `<details class="row" data-v="${p.verdict}" data-o="${p.bump ? 1 : 0}" data-n="${esc(p.name.toLowerCase())}">
      <summary><span class="name">${esc(p.name)}</span><span class="kind">${esc(p.kind)}</span><span class="ver">${ver}</span><span class="pill ${p.verdict}">${verdictLabel[p.verdict]}</span></summary>
      <div class="proof"><p>${esc(p.reason)}</p>${ev}${proof}${act}</div></details>`;
  }).join('');

  const sevClass = (s) => `sev ${esc(s)}`;
  const vulnHTML = r.checks.audit.status !== 'ok'
    ? `<p class="note ${r.checks.audit.status}">${esc(r.checks.audit.status === 'skipped' ? 'Audit was skipped.' : r.checks.audit.note)}</p>`
    : r.vulns.length === 0 ? '<p class="empty">npm audit found no known vulnerabilities.</p>'
      : r.vulns.map((v) => `<article class="vuln">
        <div class="vhead"><span class="${sevClass(v.severity)}">${esc(v.severity)}</span><h3>${esc(v.name)}</h3><span class="muted">${v.direct ? 'direct dependency' : 'pulled in by another package'}</span></div>
        <p>${esc(v.title)}${v.url ? ` <a href="${esc(v.url)}" rel="noopener noreferrer" target="_blank">advisory</a>` : ''}</p>
        <p class="fix">${esc(v.fix.text)}</p>${v.fix.cmd ? cmd(v.fix.cmd) : ''}</article>`).join('');

  const missingHTML = r.missing.length ? r.missing.map((m) => `<li><code>${esc(m.name)}</code> imported at <code>${esc(m.where)}</code>${m.installedByAccident ? ' <span class="muted">(currently present only as a side effect of another package)</span>' : ''}</li>`).join('') : '';
  const issuesHTML = r.scriptIssues.length ? r.scriptIssues.map((s) => `<li class="${s.level}">${esc(s.text)}${s.fix ? ` <span class="muted">${esc(s.fix)}</span>` : ''}</li>`).join('') : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(r.project.name)} - depscope</title>
<style>
:root{--bg:#0f1424;--panel:#161d33;--panel2:#1d2646;--line:#2b3659;--text:#e9ecf6;--muted:#98a2c4;--accent:#9db0ff;--remove:#ff8da1;--review:#f4c978;--keep:#86d9b4;--crit:#ff6b86;--code:#0b1020;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f4f5fb;--panel:#fff;--panel2:#eef0f9;--line:#d8dcec;--text:#151a30;--muted:#586286;--accent:#3a4fd2;--remove:#bf2f4e;--review:#8f6100;--keep:#12794b;--crit:#b0143a;--code:#f0f2fa;color-scheme:light}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:40px 20px 80px}
h1,h2,h3{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;font-weight:600;line-height:1.2;margin:0}
code,.cmd code{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:.88em}
a{color:var(--accent)}
.muted{color:var(--muted)}
.top{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:.92rem}
.top b{color:var(--text);font-weight:600}
.hero{display:grid;grid-template-columns:1fr auto;gap:32px;align-items:center;padding:36px 0 28px;border-bottom:1px solid var(--line)}
.hero h1{font-size:clamp(1.5rem,3.2vw,2.15rem);max-width:34ch}
.hero .chips{margin-top:18px;display:flex;gap:8px;flex-wrap:wrap}
.chip{font-size:.8rem;padding:3px 10px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}
.chip.ok{color:var(--keep);border-color:color-mix(in srgb,var(--keep) 45%,transparent)}
.chip.failed{color:var(--review);border-color:color-mix(in srgb,var(--review) 55%,transparent)}
.score{text-align:center}
.score svg{display:block}
.score .num{font:600 2.4rem/1 "Iowan Old Style",Georgia,serif;fill:var(--text)}
.score .lbl{margin-top:6px;font-size:.9rem;color:var(--muted)}
.note{margin:12px 0 0;padding:10px 14px;border-left:3px solid var(--review);background:var(--panel);border-radius:0 8px 8px 0;font-size:.92rem}
section{margin-top:52px}
h2{font-size:1.55rem;margin-bottom:6px}
.sub{margin:0 0 20px;color:var(--muted);max-width:62ch}
.step{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:18px 20px;margin-bottom:14px}
.step.risk-low{border-left-color:var(--keep)}.step.risk-medium{border-left-color:var(--review)}.step.risk-high{border-left-color:var(--remove)}
.step header{display:flex;justify-content:space-between;align-items:baseline;gap:10px;flex-wrap:wrap}
.step h3{font-size:1.15rem}.step p{margin:6px 0 12px;color:var(--muted);max-width:68ch}
.risk{font-size:.82rem;color:var(--muted)}
.cmd{display:flex;align-items:center;gap:10px;background:var(--code);border:1px solid var(--line);border-radius:8px;padding:8px 8px 8px 14px;margin-top:8px}
.cmd code{flex:1;overflow-x:auto;white-space:nowrap}
.copy{font:inherit;font-size:.82rem;cursor:pointer;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:4px 12px}
.copy:hover{border-color:var(--accent)}.copy:focus-visible,summary:focus-visible,.f:focus-visible,input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.f{font:inherit;font-size:.88rem;cursor:pointer;background:transparent;color:var(--muted);border:1px solid var(--line);border-radius:99px;padding:4px 14px}
.f[aria-pressed=true]{background:var(--accent);color:var(--bg);border-color:var(--accent)}
input[type=search]{font:inherit;font-size:.9rem;margin-left:auto;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 12px;min-width:200px}
.ledger{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel)}
.row{border-top:1px solid var(--line)}.row:first-child{border-top:0}
.row summary{display:grid;grid-template-columns:minmax(0,2.2fr) 56px minmax(0,1.8fr) 78px;gap:12px;align-items:center;padding:11px 16px;cursor:pointer;list-style:none}
.row summary::-webkit-details-marker{display:none}
.row summary:hover{background:var(--panel2)}
.name{font-family:ui-monospace,Consolas,monospace;font-size:.9rem;overflow-wrap:anywhere}
.kind{color:var(--muted);font-size:.82rem}
.ver{font-size:.88rem;color:var(--muted)}.arrow{opacity:.6}
.bump{font-weight:600;font-size:.78rem;margin-left:4px}.bump.major{color:var(--remove)}.bump.minor{color:var(--review)}.bump.patch{color:var(--keep)}
.pill{justify-self:end;font-size:.8rem;font-weight:600;padding:2px 12px;border-radius:99px;border:1px solid currentColor}
.pill.remove{color:var(--remove)}.pill.review{color:var(--review)}.pill.keep{color:var(--keep)}
.proof{padding:4px 16px 16px;background:var(--panel2)}
.proof p{margin:8px 0}.scope{color:var(--muted);font-size:.86rem}
.ev{margin:6px 0;padding:0;list-style:none}.ev li{padding:2px 0}.evtype{color:var(--muted);font-size:.86rem}
.vuln{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin-bottom:12px}
.vhead{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}.vhead h3{font-size:1.1rem;font-family:ui-monospace,Consolas,monospace;font-weight:600}
.vuln p{margin:8px 0}.fix{color:var(--muted)}
.sev{font-size:.78rem;font-weight:700;padding:2px 10px;border-radius:6px;color:#0f1424}
.sev.critical{background:var(--crit)}.sev.high{background:var(--remove)}.sev.moderate{background:var(--review)}.sev.low{background:var(--keep)}
ul.plain{padding-left:20px}ul.plain li{margin:6px 0}ul.plain li.warn::marker{color:var(--review)}
.breakdown{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.bk{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.bk b{display:block;font-size:.92rem}.bk span{color:var(--muted);font-size:.84rem}.bk em{font-style:normal;float:right;color:var(--remove);font-weight:600}
.empty{color:var(--muted);padding:14px 0}
footer{margin-top:60px;color:var(--muted);font-size:.86rem;border-top:1px solid var(--line);padding-top:16px}
.hide{display:none!important}
@media (max-width:640px){.hero{grid-template-columns:1fr}.score{text-align:left}.row summary{grid-template-columns:1fr auto}.kind,.ver{display:none}input[type=search]{margin-left:0;width:100%}}
@media (prefers-reduced-motion:no-preference){.ring{transition:stroke-dasharray .9s ease}}
</style></head><body><main>
<div class="top"><span><b>${esc(r.project.name)}</b>${r.project.version ? ' v' + esc(r.project.version) : ''}</span><span>scanned ${esc(new Date().toLocaleString())}</span></div>

<div class="hero">
  <div>
    <h1>${esc(headline(r))}</h1>
    <div class="chips">${checkChip('npm audit', r.checks.audit)}${checkChip('npm outdated', r.checks.outdated)}<span class="chip ok">${plural(r.scan.files, 'file')} scanned</span></div>
    ${checkNotes}
  </div>
  <div class="score">
    <svg width="132" height="132" viewBox="0 0 132 132" role="img" aria-label="Health score ${sc.total} out of 100">
      <circle cx="66" cy="66" r="52" fill="none" stroke="var(--line)" stroke-width="10"/>
      <circle class="ring" cx="66" cy="66" r="52" fill="none" stroke="${ringColor}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${dash.toFixed(1)} ${circ.toFixed(1)}" transform="rotate(-90 66 66)"/>
      <text class="num" x="66" y="76" text-anchor="middle">${sc.total}</text>
    </svg>
    <div class="lbl">${esc(sc.label)}</div>
  </div>
</div>

<section id="plan"><h2>Fix it</h2><p class="sub">Run these in your project folder, top to bottom. Highest priority first.</p>${planHTML}</section>

<section id="packages"><h2>Every package, with proof</h2>
<p class="sub">Open a row to see why depscope decided what it did. "Remove" means nothing points to it. "Review" means it could not tell, so check by hand.</p>
<div class="bar" role="group" aria-label="Filter packages">
  <button class="f" type="button" data-f="all" aria-pressed="true">All ${counts.all}</button>
  <button class="f" type="button" data-f="remove" aria-pressed="false">Remove ${counts.remove}</button>
  <button class="f" type="button" data-f="review" aria-pressed="false">Review ${counts.review}</button>
  <button class="f" type="button" data-f="keep" aria-pressed="false">Keep ${counts.keep}</button>
  <button class="f" type="button" data-f="outdated" aria-pressed="false">Outdated ${counts.outdated}</button>
  <input type="search" id="q" placeholder="Search packages" aria-label="Search packages">
</div>
<div class="ledger" id="ledger">${rows || '<p class="empty">This project has no dependencies.</p>'}</div>
<p class="empty hide" id="none">No packages match.</p>
</section>

<section id="security"><h2>Security</h2><p class="sub">Known vulnerabilities from npm audit, in plain words, with the command that fixes each one.</p>${vulnHTML}</section>
${r.missing.length ? `<section><h2>Imported but not declared</h2><p class="sub">Your code uses these, but package.json does not list them.</p><ul class="plain">${missingHTML}</ul></section>` : ''}
${r.scriptIssues.length ? `<section><h2>Scripts and metadata</h2><ul class="plain">${issuesHTML}</ul></section>` : ''}

<section><h2>How the score works</h2><p class="sub">Starts at 100 and loses points for each problem. Nothing is hidden.</p>
<div class="breakdown">${sc.parts.map((p) => `<div class="bk"><b>${esc(p.label)}${p.lost ? `<em>-${p.lost}</em>` : ''}</b><span>${esc(p.detail)}</span></div>`).join('')}</div></section>

<footer>depscope ${VERSION}. Scanned ${plural(r.scan.files, 'file')} in ${(r.scan.ms / 1000).toFixed(1)}s. Unused-package detection is a static search, so it can miss packages loaded dynamically or by plugins. This report never changes your project.</footer>
</main>
<script>
(function(){
  function copy(t,b){
    function done(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o},1400)}
    if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done,fallback)}else fallback();
    function fallback(){var a=document.createElement('textarea');a.value=t;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(a)}
  }
  document.addEventListener('click',function(e){var b=e.target.closest('.copy');if(b)copy(b.getAttribute('data-copy'),b)});
  var rows=[].slice.call(document.querySelectorAll('.row')),btns=[].slice.call(document.querySelectorAll('.f')),q=document.getElementById('q'),none=document.getElementById('none'),cur='all';
  function apply(){
    var s=q.value.trim().toLowerCase(),n=0;
    rows.forEach(function(r){
      var ok=(cur==='all'||(cur==='outdated'?r.dataset.o==='1':r.dataset.v===cur))&&(!s||r.dataset.n.indexOf(s)>-1);
      r.classList.toggle('hide',!ok);if(ok)n++;
    });
    none.classList.toggle('hide',n>0);
  }
  btns.forEach(function(b){b.addEventListener('click',function(){cur=b.dataset.f;btns.forEach(function(x){x.setAttribute('aria-pressed',x===b)});apply()})});
  q.addEventListener('input',apply);
})();
</script></body></html>`;
}

// ------------------------------------------------------------ terminal ----

function terminalSummary(r, plan, sc, reportPath) {
  const tty = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
  const out = [];
  out.push('');
  out.push(c(1, `depscope ${VERSION}`) + c(2, `  ${r.project.name}`));
  out.push(c(2, `Scanned ${plural(r.scan.files, 'file')} in ${(r.scan.ms / 1000).toFixed(1)}s`));
  out.push('');
  const col = sc.total >= 75 ? 32 : sc.total >= 50 ? 33 : 31;
  out.push(`Health  ${c(col + ';1', sc.total + '/100')}  ${sc.label}`);
  out.push('');

  const rem = r.packages.filter((p) => p.verdict === 'remove');
  const rev = r.packages.filter((p) => p.verdict === 'review');
  if (rem.length) out.push(`${c(31, 'Remove')}   ${rem.length}  ${c(2, rem.map((p) => p.name).join(', '))}`);
  if (rev.length) out.push(`${c(33, 'Review')}   ${rev.length}  ${c(2, rev.map((p) => p.name).join(', '))}`);
  if (r.missing.length) out.push(`${c(33, 'Missing')}  ${r.missing.length}  ${c(2, r.missing.map((m) => m.name).join(', '))}`);

  if (r.checks.audit.status === 'ok') {
    if (r.vulns.length) {
      const by = {};
      for (const v of r.vulns) by[v.severity] = (by[v.severity] || 0) + 1;
      out.push(`${c(31, 'Vulns')}    ${r.vulns.length}  ${c(2, SEV_ORDER.slice().reverse().filter((s) => by[s]).map((s) => `${by[s]} ${s}`).join(', '))}`);
    } else out.push(`${c(32, 'Vulns')}    0`);
  } else out.push(`${c(33, 'Vulns')}    ${c(2, r.checks.audit.status === 'skipped' ? 'skipped' : 'could not check: ' + r.checks.audit.note)}`);

  if (r.checks.outdated.status === 'ok') {
    const o = r.packages.filter((p) => p.bump);
    out.push(`Outdated  ${o.length}  ${c(2, `${o.filter((p) => p.bump === 'major').length} major`)}`);
  } else if (r.checks.outdated.status === 'failed') out.push(`Outdated  ${c(2, 'could not check: ' + r.checks.outdated.note)}`);

  if (plan.length) {
    out.push('');
    out.push(c(1, 'Fix it'));
    for (const s of plan) {
      out.push('  ' + c(2, s.title));
      for (const cm of s.cmds.slice(0, 3)) out.push('    ' + cm);
      if (s.cmds.length > 3) out.push(c(2, `    ... and ${s.cmds.length - 3} more in the report`));
    }
  }
  if (reportPath) { out.push(''); out.push('Report  ' + reportPath); }
  out.push('');
  console.log(out.join('\n'));
}

function openFile(p) {
  const win = process.platform === 'win32';
  const cmd = win ? 'cmd' : process.platform === 'darwin' ? 'open' : 'xdg-open';
  const args = win ? ['/c', 'start', '""', p] : [p];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* ignore */ }
}

// --------------------------------------------------------------- main ----

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { console.log(HELP); return; }
  if (opts.version) { console.log(VERSION); return; }

  const target = path.resolve(opts.target);
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) die(`${target} is not a folder.`);

  const r = analyze(target, opts);
  const plan = buildPlan(r);
  const sc = score(r);
  r.plan = plan; r.score = sc;

  let reportPath = null;
  if (opts.html) {
    reportPath = path.resolve(opts.out || path.join(target, 'depscope-report.html'));
    try { fs.writeFileSync(reportPath, renderHTML(r, plan, sc)); } catch (e) { die(`could not write report: ${e.message}`); }
  }

  if (opts.json) console.log(JSON.stringify(r, null, 2));
  else terminalSummary(r, plan, sc, reportPath);

  if (opts.open && reportPath) openFile(reportPath);

  // CI exit code
  const rules = new Set(opts.failOn);
  const minSev = SEV_ORDER.indexOf(opts.failSeverity);
  const tripped = [];
  if ((rules.has('vuln') || rules.has('any')) && r.vulns.some((v) => SEV_ORDER.indexOf(v.severity) >= minSev)) tripped.push('vulnerabilities');
  if ((rules.has('unused') || rules.has('any')) && r.packages.some((p) => p.verdict === 'remove')) tripped.push('unused packages');
  if ((rules.has('missing') || rules.has('any')) && r.missing.length) tripped.push('undeclared imports');
  if (tripped.length) {
    console.error(`depscope: failing because of ${tripped.join(', ')} (--fail-on ${opts.failOn.join(',')})`);
    process.exit(1);
  }
}

main();
