# DEPSCOPE

A local dependency health scanner for Node.js projects. It creates an HTML report covering dependency inventory, potentially unused packages, outdated packages and npm audit vulnerabilities.

## Requirements

- Node.js 18+
- npm
- Internet connection for `npm audit` and `npm outdated` (optional checks)

## Run locally

```bash
git clone https://github.com/abhiramiramadas/depscope.git
cd depscope
npm link
depscope /path/to/your/node-project
```

Or run without linking:

```bash
node ./bin/depscope.js /path/to/your/node-project
```

Use in CI / scripts:

```
node ./bin/depscope.js . --json > deps.json          # machine-readable output
node ./bin/depscope.js . --fail-on high              # exit 1 on high+ vulnerabilities
node ./bin/depscope.js . --output reports/deps.html  # custom report path
```

Skip network-dependent checks:

```bash
node ./bin/depscope.js /path/to/your/node-project --no-audit --no-outdated
```

The report is written to `depscope-report.html` inside the target project.

## What it checks

- Reads `dependencies`, `devDependencies` and `optionalDependencies` from `package.json`.
- Runs `npm audit --json` and `npm outdated --json`.
- Scans source files (imports, `require`, dynamic `import()`), config files and npm scripts to flag dependencies with no obvious reference. `package.json` and lockfiles are ignored so they can't count as usage.
- Generates a self-contained HTML report.

## Important limitations

The unused-package check is deliberately labelled **potentially unused**. Static text scanning cannot reliably detect dynamic imports, plugins, framework conventions, build-time tools, package names referenced only in configuration, or dependencies used by scripts. Treat it as a review hint, not an instruction to uninstall.

The npm checks may fail when offline, behind a restrictive proxy, or when the target project has an incompatible lockfile. DEPSCOPE reports the check status rather than claiming a clean result.

## Roadmap

- Optional Knip integration for stronger unused-export/dependency analysis.
- Python project support.
- Markdown report format.
- Ready-made GitHub Action.
- Interactive dependency review and safe fix suggestions.

## License

MIT
