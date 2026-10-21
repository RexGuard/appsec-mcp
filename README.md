# AppSec MCP

An MCP server that checks your app for security problems, explains them in plain language,
shows exactly what it read, and can fix some of them for you (only after you approve).

Works inside Claude Code, Claude Desktop, Cursor and any other MCP client. Everything runs
locally: your code never leaves your machine.

## What it does

- **Finds problems** in TypeScript/JavaScript, HTML, Python, Java and C/C++ projects
  - code bugs: SQL injection, XSS, `eval`, command injection, buffer overflows, format strings
  - leaked secrets: Stripe, AWS, GitHub, Google keys, passwords in code, committed `.env`
  - config: debug mode, CORS `*`, missing security headers, missing CSRF protection
  - vulnerable dependencies (with OSV-Scanner installed)
- **Maps your app**: entry points, routes, data stores, external services, secrets, dependencies
- **Ranks by evidence, not guesses**: an evidence gate gives every finding a tier (pattern,
  reachable, corroborated, confirmed) and never ranks a lone pattern match as critical
- **Links findings into attack chains**: e.g. route → SQL injection → MySQL, or leaked Stripe key →
  Stripe API
- **Learns from you**: mark a finding as a false positive and later scans hide it
- **Shows its work**: an audit ledger lists every file read (with SHA-256), every file skipped and
  why, and every rule and scanner that ran
- **Fixes, with your OK**: proposes a diff, applies it only with the proposal token, backs up
  first, and can revert byte for byte
- **Adds a security layer**: recipes for security headers, rate limiting, CSRF, `.env` setup and
  request size limits (Express, Next.js, Flask, FastAPI, Spring Boot)
- **Checks a live site you own**: HTTPS certificate, security headers and cookie flags (GET only)

## Quick start

```bash
pipx install "C:/path/to/SAP"
```

```bash
claude mcp add --scope user appsec -- appsec-mcp serve
```

Then ask your assistant: *"scan this project for security problems"*.

See [docs/getting-started.md](docs/getting-started.md) for the full setup, including the optional
scanners (Semgrep, gitleaks, OSV-Scanner) and other MCP clients.

## Tools

| Tool | What it does |
|---|---|
| `scan_project` | Scan a folder (read-only) and return a score and counts |
| `get_findings` | Findings, worst first, each with a plain-language explanation |
| `explain_finding` | What it is, why it matters, how to fix it |
| `get_system_map` | What the app is made of, with the risky spots |
| `get_audit_ledger` | Exactly what was read, skipped and checked |
| `get_attack_chains` | Attack paths from outside input or a leaked key to what it reaches |
| `mark_false_positive` / `unmark_false_positive` / `list_false_positives` | Hide findings you rejected from later scans |
| `list_scans` | Scan history and scores |
| `list_recipes` / `propose_hardening` | "Add a security layer" recipes |
| `propose_patch` | A fix as a diff; writes nothing |
| `apply_patch` / `revert_patch` | Apply an approved fix; undo it |
| `check_website` | Passive check of a site you own |

## CLI

```bash
appsec-mcp scan . --fail-on high
```

```bash
appsec-mcp view
```

`scan` prints results and exits 1 when anything at or above `--fail-on` is found (use it in CI or a
git hook). `view` opens the local viewer with the Findings, Map and Ledger tabs.

## Docs

- [Getting started](docs/getting-started.md)
- [MCP client setup](docs/clients.md)
- [What it reads (the audit ledger)](docs/what-it-reads.md)
- [Patching and hardening](docs/patching.md)
- [Evidence tiers, attack chains and false positives](docs/evidence-and-chains.md)
- [Contributing: rules, explanations and recipes](CONTRIBUTING.md)

## Limits

It is a fast first pass, not a penetration test. The built-in rules are pattern-based, so they can
miss issues and occasionally flag safe code; Semgrep adds deeper analysis when installed. Silence a
reviewed line with an `appsec-ignore` comment, or skip paths with a `.appsecignore` file
(`.gitignore` syntax).

MIT licensed.
