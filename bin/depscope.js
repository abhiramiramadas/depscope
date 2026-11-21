#!/usr/bin/env node
import path from "node:path";
import { pathToFileURL } from "node:url";
import { scanProject } from "../lib/scanner.js";
import { writeReport } from "../lib/report.js";

function usage() {
  console.log(`
DEPSCOPE — dependency health scanner

Usage:
  depscope <project-directory> [options]

Options:
  --no-audit     Skip npm audit (security check)
  --no-outdated  Skip npm outdated (version check)
  --help         Show this help

Examples:
  depscope .
  depscope ../my-app --no-audit
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.length === 0) {
    usage();
    process.exit(args.length === 0 ? 1 : 0);
  }

  const flags = new Set(args.filter((a) => a.startsWith("--")));
  const targetArg = args.find((a) => !a.startsWith("--"));
  if (!targetArg) {
    usage();
    process.exit(1);
  }

  const target = path.resolve(process.cwd(), targetArg);
  console.log("\n  DEPSCOPE  ·  Project health scanner");
  console.log("  -----------------------------------");
  console.log(`  Scanning: ${target}\n`);

  try {
    const result = await scanProject(target, {
      audit: !flags.has("--no-audit"),
      outdated: !flags.has("--no-outdated")
    });
    const reportPath = await writeReport(result, target);
    const { summary } = result;

    console.log("  Scan complete.\n");
    console.log(`  Dependencies:          ${summary.total}`);
    console.log(`  Potentially unused:    ${summary.potentiallyUnused}`);
    console.log(`  Outdated:              ${summary.outdated}`);
    console.log(`  Vulnerabilities:       ${summary.vulnerabilities}`);
    console.log(`\n  HTML report: ${reportPath}\n`);
    console.log("  Note: unused-package detection is heuristic. Review findings before removing packages.\n");
  } catch (error) {
    console.error(`\n  DEPSCOPE error: ${error.message}\n`);
    process.exit(1);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main();
}
