# depscope

Point it at a Node.js project and get a cleanup plan: what you can remove (with proof), what is vulnerable, what is outdated, and the exact commands to fix it. One HTML report, no account, no dependencies, never edits your project.

## Run

```bash
node bin/depscope.js /path/to/project --open
# or: npm link && depscope /path/to/project
```

Needs Node 18+. `npm audit` and `npm outdated` need internet and a `package-lock.json`; use `--no-audit --no-outdated` to run fully offline.

## What you get

- **Fix it**: ordered, copy-paste commands with a risk label. Removing an unused package also drops its fix command and counts the vulnerabilities it clears.
- **Every package, with proof**: Keep / Remove / Review. Each verdict shows the `file:line` that uses it, or what was searched when nothing was found.
- **Plain-English vulnerabilities**: severity, direct or inherited, and the command that fixes each.
- **Imported but not declared**: packages your code uses that package.json does not list.
- **Scripts and metadata**: scripts pointing at missing files, placeholder `test`, bad `main` or `bin`, duplicate dependency entries.
- **Health score** with the full breakdown of lost points.

## Options

| Option | What it does |
|---|---|
| `--no-audit`, `--no-outdated` | skip those npm checks |
| `--out <file>` | report path (default `<project>/depscope-report.html`) |
| `--json` | print the full result as JSON |
| `--no-html` | do not write the report |
| `--open` | open the report in your browser |
| `--fail-on vuln,unused,missing,any` | exit 1 if a rule trips (for CI) |
| `--fail-severity high` | lowest severity counted by `vuln` |

Exit codes: `0` ok, `1` a `--fail-on` rule tripped, `2` could not run.

## How "unused" is decided

A package counts as used if it is imported or required (including `import()`, `jest.mock`, CSS `@import`), run by an npm script, named in a config file (eslint, babel, tsconfig, CI workflows...), required as a peer by an installed package, or is the `@types/*` for something you use. Tools that are normally loaded by name from config (plugins, loaders, linters) get **Review** instead of **Remove** when nothing points to them. It is a static search, so dynamic `require(variable)` can be missed.

## Test

```bash
npm test
```

MIT
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
