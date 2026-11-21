
import fs from "node:fs/promises";
import path from "node:path";

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function badge(text, kind = "neutral") {
  return `<span class="badge ${kind}">${esc(text)}</span>`;
}

export async function writeReport(result, projectDir) {
  const output = path.join(projectDir, "depscope-report.html");

  const summary = result.summary ?? {};
  const severity = summary.vulnerabilitiesBySeverity ?? {};

  const totalVulnerabilities = Number(summary.vulnerabilities ?? 0);
  const affectedPackages = Number(
    summary.affectedPackages ?? result.vulnerabilities?.length ?? 0
  );

  const severityItems = [
    { name: "Critical", value: Number(severity.critical ?? 0), kind: "critical" },
    { name: "High", value: Number(severity.high ?? 0), kind: "high" },
    { name: "Moderate", value: Number(severity.moderate ?? 0), kind: "moderate" },
    { name: "Low", value: Number(severity.low ?? 0), kind: "low" },
    { name: "Info", value: Number(severity.info ?? 0), kind: "info" }
  ];

  const severityRows = severityItems.map((item) => `
    <div class="severity-row">
      <div class="severity-label">
        ${badge(item.name, item.kind)}
        <strong>${item.value}</strong>
      </div>
      <div class="bar-track">
        <div class="bar-fill ${item.kind}"
          style="width:${totalVulnerabilities > 0
            ? Math.min((item.value / totalVulnerabilities) * 100, 100)
            : 0}%">
        </div>
      </div>
    </div>
  `).join("");

  const securityStatus = totalVulnerabilities === 0
    ? badge("NO VULNERABILITIES FOUND", "success")
    : badge("VULNERABILITIES DETECTED", "danger");

  const rows = result.findings?.length
    ? result.findings.map((f) => `<tr>
        <td>${badge(
          f.type,
          f.type === "Security vulnerability"
            ? "danger"
            : f.type === "Outdated package"
              ? "warning"
              : "neutral"
        )}</td>
        <td><code>${esc(f.package)}</code></td>
        <td>${esc(f.detail)}</td>
      </tr>`).join("")
    : `<tr><td colspan="3" class="empty">
        No findings from the checks that completed. Nice!
      </td></tr>`;

  const deps = (result.dependencies ?? []).map((d) => `<tr>
    <td><code>${esc(d.name)}</code></td>
    <td>${esc(d.version)}</td>
    <td>${esc(d.kind)}</td>
  </tr>`).join("");

  const notes = (result.scanNotes ?? [])
    .map((n) => `<li>${esc(n)}</li>`)
    .join("");

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DEPSCOPE · ${esc(result.project.name)}</title>

<style>
:root {
  color-scheme: dark;
  --bg: #0b1020;
  --panel: #121a2b;
  --line: #26334a;
  --text: #edf2ff;
  --muted: #9eacc4;
  --accent: #a3e635;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 15px/1.55 Inter, ui-sans-serif, system-ui, sans-serif;
}

main {
  max-width: 1050px;
  margin: 0 auto;
  padding: 44px 22px 70px;
}

.top {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: flex-start;
}

h1 {
  font-size: 30px;
  margin: 0;
  letter-spacing: -1px;
}

.brand {
  color: var(--accent);
  font-weight: 800;
  letter-spacing: 2px;
  font-size: 12px;
}

.sub {
  color: var(--muted);
  margin: 6px 0 26px;
}

.grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin: 22px 0 32px;
}

.card, section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 14px;
}

.card { padding: 18px; }

.label {
  color: var(--muted);
  font-size: 12px;
}

.number {
  font-size: 30px;
  font-weight: 750;
  margin-top: 6px;
}

section {
  padding: 20px;
  margin: 18px 0;
}

h2 {
  font-size: 17px;
  margin: 0 0 14px;
}

table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

th, td {
  padding: 11px 10px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}

th {
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
}

tr:last-child td { border-bottom: 0; }

code {
  color: #d9f99d;
  background: #1b2940;
  padding: 2px 5px;
  border-radius: 5px;
}

.badge {
  display: inline-block;
  border-radius: 20px;
  padding: 3px 9px;
  font-size: 11px;
  white-space: nowrap;
}

.neutral { background: #26334a; color: #d5deed; }
.warning { background: #493719; color: #ffd58a; }
.danger { background: #4a2029; color: #ffb5bd; }
.success { background: #193b2a; color: #a3e6b8; }

.critical { background: #67202c; color: #ff9da9; }
.high { background: #57252b; color: #ffb5bd; }
.moderate { background: #493719; color: #ffd58a; }
.low { background: #263b56; color: #a8d2ff; }
.info { background: #26334a; color: #d5deed; }

.severity-row { margin: 17px 0; }

.severity-label {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.bar-track {
  height: 9px;
  background: #26334a;
  border-radius: 20px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: 20px;
  min-width: 0;
}

.bar-fill.critical { background: #ef6678; }
.bar-fill.high { background: #e77b63; }
.bar-fill.moderate { background: #e9b75d; }
.bar-fill.low { background: #65a8ed; }
.bar-fill.info { background: #8497b5; }

.security-status {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 22px;
}

.security-total {
  font-size: 36px;
  font-weight: 800;
}

.empty {
  color: var(--accent);
  padding: 20px;
}

.muted { color: var(--muted); }
li { margin: 8px 0; }

.foot {
  color: var(--muted);
  font-size: 12px;
  margin-top: 26px;
}

@media(max-width:700px) {
  .grid { grid-template-columns: repeat(2, 1fr); }
  .top { display: block; }
  table { font-size: 13px; }
  th, td { padding: 8px 5px; }
}
</style>
</head>

<body>
<main>

<div class="top">
  <div>
    <div class="brand">DEPSCOPE / PROJECT HEALTH</div>
    <h1>${esc(result.project.name)}</h1>
    <p class="sub">
      Version ${esc(result.project.version)}
      · Scanned ${esc(new Date(result.project.scannedAt).toLocaleString())}
    </p>
  </div>
  ${badge("LOCAL SCAN", "neutral")}
</div>

<div class="grid">
  <div class="card">
    <div class="label">Dependencies</div>
    <div class="number">${Number(summary.total ?? 0)}</div>
  </div>

  <div class="card">
    <div class="label">Potentially unused</div>
    <div class="number">${Number(summary.potentiallyUnused ?? 0)}</div>
  </div>

  <div class="card">
    <div class="label">Outdated</div>
    <div class="number">${Number(summary.outdated ?? 0)}</div>
  </div>

  <div class="card">
    <div class="label">Affected packages</div>
    <div class="number">${affectedPackages}</div>
  </div>
</div>

<section>
  <h2>Security overview</h2>

  <div class="security-status">
    <div>
      <div class="label">Total vulnerabilities</div>
      <div class="security-total">${totalVulnerabilities}</div>
    </div>
    ${securityStatus}
  </div>

  ${severityRows}

  <p class="muted">
    Severity counts are provided by npm audit.
    Affected packages and total vulnerabilities are separate metrics.
  </p>
</section>

<section>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>Type</th><th>Package</th><th>Details</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</section>

<section>
  <h2>Dependency inventory</h2>
  <table>
    <thead>
      <tr><th>Package</th><th>Declared version</th><th>Type</th></tr>
    </thead>
    <tbody>
      ${deps || '<tr><td colspan="3">No dependencies declared.</td></tr>'}
    </tbody>
  </table>
</section>

<section>
  <h2>Scan status</h2>
  <p>
    npm audit:
    ${badge(
      result.checks.audit,
      result.checks.audit === "completed" ? "neutral" : "warning"
    )}
  </p>
  <p>
    npm outdated:
    ${badge(
      result.checks.outdated,
      result.checks.outdated === "completed" ? "neutral" : "warning"
    )}
  </p>
</section>

<section>
  <h2>Important notes</h2>
  <ul>${notes}</ul>
</section>

<div class="foot">
  Generated by DEPSCOPE · Review findings before removing or upgrading packages.
</div>

</main>
</body>
</html>`;

  await fs.writeFile(output, html, "utf8");
  return output;
}
