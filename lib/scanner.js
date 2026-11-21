
import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "coverage",
  ".turbo", ".vercel", "vendor", "out"
]);

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
  ".html", ".json", ".md"
]);

function run(command, args, cwd, timeoutMs = 45000) {
  return new Promise((resolve) => {
    const isWindows = process.platform === "win32";

    const child = isWindows
      ? spawn(
          process.env.ComSpec || "cmd.exe",
          ["/d", "/s", "/c", `${command} ${args.join(" ")}`],
          { cwd, windowsHide: true }
        )
      : spawn(command, args, { cwd });

    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => child.kill(), timeoutMs);

    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ ok: false, stdout, stderr: error.message });
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, code, stdout, stderr });
    });
  });
}

async function collectSourceFiles(dir, base = dir, found = []) {
  let entries;

  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return found;
  }

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) {
        await collectSourceFiles(path.join(dir, entry.name), base, found);
      }
    } else if (
      entry.isFile() &&
      SOURCE_EXTENSIONS.has(path.extname(entry.name))
    ) {
      found.push(path.join(dir, entry.name));
    }
  }

  return found;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function findPotentiallyUnused(projectDir, dependencyNames) {
  const files = await collectSourceFiles(projectDir);
  const contents = [];

  for (const file of files) {
    try {
      contents.push(await fs.readFile(file, "utf8"));
    } catch {}
  }

  const corpus = contents.join("\n");

  return dependencyNames.filter((name) => {
    const escaped = escapeRegExp(name);

    const pattern = new RegExp(
      `(?:from\\s*|import\\s*\\(|require\\s*\\(|"${escaped}"|'${escaped}'|${escaped}/)`,
      "m"
    );

    return !pattern.test(corpus);
  });
}

function parseJson(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    return null;
  }
}

// Calculate dependency health score out of 100
function calculateHealthScore(severityCounts, outdatedCount, unusedCount) {
  const securityPenalty =
    (severityCounts.critical * 25) +
    (severityCounts.high * 10) +
    (severityCounts.moderate * 5) +
    (severityCounts.low * 2);

  const outdatedPenalty = outdatedCount;
  const unusedPenalty = unusedCount * 2;

  return Math.max(
    0,
    100 - securityPenalty - outdatedPenalty - unusedPenalty
  );
}

export async function scanProject(projectDir, options = {}) {
  const packagePath = path.join(projectDir, "package.json");
  let pkg;

  try {
    pkg = JSON.parse(await fs.readFile(packagePath, "utf8"));
  } catch {
    throw new Error(
      "No valid package.json found. Run DEPSCOPE on a Node.js project directory."
    );
  }

  const dependencies = pkg.dependencies ?? {};
  const devDependencies = pkg.devDependencies ?? {};
  const optionalDependencies = pkg.optionalDependencies ?? {};

  const allDeps = {
    ...dependencies,
    ...devDependencies,
    ...optionalDependencies
  };

  const dependencyNames = Object.keys(allDeps);

  const [auditRun, outdatedRun] = await Promise.all([
    options.audit === false
      ? Promise.resolve({ skipped: true })
      : run("npm", ["audit", "--json"], projectDir),

    options.outdated === false
      ? Promise.resolve({ skipped: true })
      : run("npm", ["outdated", "--json"], projectDir)
  ]);

  const auditData = auditRun.skipped
    ? null
    : parseJson(auditRun.stdout);

  const outdatedData = outdatedRun.skipped
    ? null
    : parseJson(outdatedRun.stdout);

  const potentiallyUnused = await findPotentiallyUnused(
    projectDir,
    dependencyNames
  );

  // Security vulnerability information
  const vulnerabilities = [];

  const vulnCounts =
    auditData?.metadata?.vulnerabilities ?? {};

  // Vulnerability severity breakdown
  const severityCounts = {
    info: Number(vulnCounts.info ?? 0),
    low: Number(vulnCounts.low ?? 0),
    moderate: Number(vulnCounts.moderate ?? 0),
    high: Number(vulnCounts.high ?? 0),
    critical: Number(vulnCounts.critical ?? 0)
  };

  if (auditData?.vulnerabilities) {
    for (const [name, item] of Object.entries(
      auditData.vulnerabilities
    )) {
      vulnerabilities.push({
        name,
        severity: item.severity ?? "unknown",
        direct: Boolean(item.isDirect),
        range: item.range ?? "",
        fixAvailable: item.fixAvailable ?? false,
        via: (item.via ?? [])
          .map((v) => typeof v === "string" ? v : v.name)
          .filter(Boolean)
      });
    }
  }

  // Outdated dependencies
  const outdated = Object.entries(outdatedData ?? {}).map(
    ([name, item]) => ({
      name,
      current: item.current ?? "unknown",
      wanted: item.wanted ?? "unknown",
      latest: item.latest ?? "unknown",
      type: item.type ?? "dependency"
    })
  );

  // Findings
  const findings = [];

  for (const name of potentiallyUnused) {
    findings.push({
      type: "Potentially unused",
      severity: "info",
      package: name,
      detail:
        "No obvious import or reference was found in the scanned source files. This is a heuristic, not proof."
    });
  }

  for (const item of outdated) {
    findings.push({
      type: "Outdated package",
      severity: "warning",
      package: item.name,
      detail:
        `Installed: ${item.current} · Wanted: ${item.wanted} · Latest: ${item.latest}`
    });
  }

  for (const item of vulnerabilities) {
    findings.push({
      type: "Security vulnerability",
      severity: item.severity,
      package: item.name,
      detail:
        `Affected range: ${item.range || "not provided"}${item.fixAvailable ? " · A fix may be available" : ""}`
    });
  }

  // Check whether the scans completed successfully
  const auditStatus =
    options.audit === false
      ? "skipped"
      : auditRun.ok || auditData
        ? "completed"
        : "could not complete";

  const outdatedStatus =
    options.outdated === false
      ? "skipped"
      : outdatedRun.ok || outdatedData
        ? "completed"
        : "could not complete";

  // Calculate health score only when both scans completed
  const healthScore =
    auditStatus === "completed" && outdatedStatus === "completed"
      ? calculateHealthScore(
          severityCounts,
          outdated.length,
          potentiallyUnused.length
        )
      : null;

  return {
    project: {
      name: pkg.name ?? path.basename(projectDir),
      version: pkg.version ?? "not specified",
      path: projectDir,
      scannedAt: new Date().toISOString(),
      packageManager: "npm"
    },

    dependencies: Object.entries(allDeps).map(([name, version]) => ({
      name,
      version,
      kind:
        name in dependencies
          ? "production"
          : name in devDependencies
            ? "development"
            : "optional"
    })),

    potentiallyUnused,
    outdated,
    vulnerabilities,
    findings,

    checks: {
      audit: auditStatus,
      outdated: outdatedStatus
    },

    scanNotes: [
      "Unused dependency detection is heuristic and may miss dynamic imports, plugins, CLI tools, framework conventions and configuration-only usage.",
      "npm audit and npm outdated may need an internet connection.",
      "Review all findings before changing package.json or uninstalling packages.",
      "The dependency health score is a heuristic indicator, not a guarantee of project security."
    ],

    // Summary
    summary: {
      total: dependencyNames.length,
      potentiallyUnused: potentiallyUnused.length,
      outdated: outdated.length,

      // Total vulnerabilities reported by npm
      vulnerabilities: Number(
        vulnCounts.total ?? vulnerabilities.length
      ),

      // Number of affected package entries
      affectedPackages: vulnerabilities.length,

      // Vulnerability severity breakdown
      vulnerabilitiesBySeverity: severityCounts,

      // Overall dependency health score
      healthScore
    }
  };
}
