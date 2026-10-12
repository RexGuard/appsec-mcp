# Getting started

About 10 minutes from nothing to your first scan and fix.

## 1. Install

You need Python 3.12 or newer.

```bash
pipx install "C:/path/to/SAP"
```

Or run it without installing, with uv:

```bash
uvx --from "C:/path/to/SAP" appsec-mcp --version
```

From a clone, for development:

```bash
uv venv --python 3.12
```

```bash
uv pip install -e ".[dev]"
```

## 2. Connect it to your AI assistant

Claude Code:

```bash
claude mcp add --scope user appsec -- appsec-mcp serve
```

Other clients (Claude Desktop, Cursor): see [clients.md](clients.md).

## 3. First scan

Ask: *"scan this project for security problems"*. The assistant calls `scan_project`, then
`get_findings`, and reads you the results ranked by severity.

Then try:

- *"what does finding 3 mean?"* (`explain_finding`)
- *"show me how my app is structured"* (`get_system_map`)
- *"what exactly did you read?"* (`get_audit_ledger`)

## 4. First fix

Ask: *"fix the hard-coded secret"*. The assistant shows you a diff from `propose_patch`. Nothing is
written until you say yes; then it calls `apply_patch` and re-scans to confirm the finding is fixed.
If something breaks: *"undo that fix"* (`revert_patch`).

## 5. Optional: more scanners

The built-in scanner always runs. These add depth when they are on your PATH, and the scan result
tells you which ones were skipped and how to install them.

| Scanner | Adds | Windows | macOS | Linux |
|---|---|---|---|---|
| Semgrep | deeper code analysis | `pip install semgrep` (native beta) or WSL | `brew install semgrep` | `pipx install semgrep` |
| gitleaks | more secret types | `winget install gitleaks` | `brew install gitleaks` | release binary |
| OSV-Scanner | vulnerable dependencies | `winget install Google.OSVScanner` | `brew install osv-scanner` | release binary |

Semgrep uses the rule pack bundled with this tool (offline). To add registry packs, set
`APPSEC_MCP_SEMGREP_CONFIGS=p/owasp-top-ten,p/secrets` (this downloads rules from semgrep.dev).

## 6. The viewer

```bash
appsec-mcp view
```

This opens `http://127.0.0.1:<port>/#token=...` with three tabs: Findings, Map and Ledger. The link
only works on your machine and only for this session.

## Where data lives

`~/.appsec-mcp/` (change it with the `APPSEC_MCP_HOME` environment variable):

- `appsec.db`: scans, findings, map and ledger (SQLite)
- `backups/<patch id>/`: original files from before each applied patch
- `logs/appsec-mcp.log`: rotating log
