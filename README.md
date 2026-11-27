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