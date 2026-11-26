#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { scanProject } from "../lib/scanner.js";
import { writeReport } from "../lib/report.js";

const SEVERITIES = ["low", "moderate", "high", "critical"];
const VERSION = JSON.parse(
  fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")
).version;

function usage() {
  console.log(`
DEPSCOPE ${VERSION} — dependency health scanner

Usage:
  depscope [project-directory] [options]      (defaults to current directory)

Options:
  --no-audit            Skip npm audit (security check)
  --no-outdated         Skip npm outdated (version check)
  --json                Print results as JSON to stdout (no HTML report)
  --output <file>       Write the HTML report to <file>
  --fail-on <severity>  Exit 1 if a vulnerability of this severity or higher
                        is found (low | moderate | high | critical) — for CI
  --version, -v         Print version
  --help, -h            Show this help

Examples:
  depscope .
  depscope ../my-app --no-audit
  depscope . --json > deps.json
  depscope . --fail-on high --output reports/deps.html
`);
}

export function parseArgs(argv) {
  const opts = { audit: true, outdated: true, json: false, output: null, failOn: null, target: ".", help: false, version: false };
  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--help": case "-h": opts.help = true; break;
      case "--version": case "-v": opts.version = true; break;
      case "--no-audit": opts.audit = false; break;
      case "--no-outdated": opts.outdated = false; break;
      case "--json": opts.json = true; break;
      case "--output": case "-o":
        if (!argv[i + 1] || argv[i + 1].startsWith("-")) throw new Error(`${a} needs a file path`);
        opts.output = argv[++i];
        break;
      case "--fail-on": {
        const v = argv[++i];
        if (!SEVERITIES.includes(v)) throw new Error(`--fail-on must be one of: ${SEVERITIES.join(", ")}`);
        opts.failOn = v;
        break;
      }
      default:
        if (a.startsWith("-")) throw new Error(`Unknown option: ${a} (see --help)`);
        positional.push(a);
    }
  }

  if (positional.length > 1) throw new Error("Only one project directory can be scanned at a time");
  if (positional[0]) opts.target = positional[0];
  return opts;
}

export function exceedsThreshold(severityCounts = {}, failOn) {
  if (!failOn) return false;
  const from = SEVERITIES.indexOf(failOn);
  return SEVERITIES.slice(from).some((s) => Number(severityCounts[s] ?? 0) > 0);
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`\n  DEPSCOPE error: ${error.message}\n`);
    process.exit(2);
  }

  if (opts.help) return usage();
  if (opts.version) return console.log(VERSION);

  const target = path.resolve(process.cwd(), opts.target);
  // In --json mode stdout must stay machine-readable, so progress goes to stderr
  const log = opts.json ? console.error : console.log;

  log("\n  DEPSCOPE  ·  Project health scanner");
  log("  -----------------------------------");
  log(`  Scanning: ${target}\n`);

  try {
    const result = await scanProject(target, { audit: opts.audit, outdated: opts.outdated });
    const { summary, checks, checkErrors } = result;

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      const reportPath = await writeReport(result, target, opts.output);
      log("  Scan complete.\n");
      log(`  Dependencies:          ${summary.total}`);
      log(`  Potentially unused:    ${summary.potentiallyUnused}`);
      log(`  Outdated:              ${checks.outdated === "completed" ? summary.outdated : `n/a (${checks.outdated})`}`);
      log(`  Vulnerabilities:       ${checks.audit === "completed" ? summary.vulnerabilities : `n/a (${checks.audit})`}`);
      if (summary.healthScore != null) log(`  Health score:          ${summary.healthScore}/100`);
      log(`\n  HTML report: ${reportPath}\n`);
    }

    for (const [check, message] of Object.entries(checkErrors ?? {})) {
      console.error(`  ! ${check} could not complete: ${message}`);
    }
    log("  Note: unused-package detection is heuristic. Review findings before removing packages.\n");

    if (exceedsThreshold(summary.vulnerabilitiesBySeverity, opts.failOn)) {
      console.error(`  Failing: vulnerabilities at or above "${opts.failOn}" severity found.\n`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`\n  DEPSCOPE error: ${error.message}\n`);
    process.exit(1);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  main();
}
