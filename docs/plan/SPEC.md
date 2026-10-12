# Technical Spec

> Source: Chaika plan `2026-10-12-to-create-an-mcp-to-secure-application-f`, copied verbatim.
> Implementation note: the plan names the SDK's `FastMCP`. In `mcp` 2.x that class is
> `mcp.server.mcpserver.MCPServer` (same API, renamed), which is what this project uses.

## Stack
| Layer | Choice | Why |
|---|---|---|
| MCP server | Python 3.12, official `mcp` SDK (FastMCP), stdio transport | Mature SDK; stdio works in every MCP client |
| Models | Pydantic v2 | Validated tool inputs and outputs, JSON schema for free |
| Storage | SQLite via stdlib `sqlite3`, parameterised queries | Zero setup, local-first, single file |
| Scanners | Semgrep OSS, gitleaks, OSV-Scanner (subprocess, JSON output) | Proven, free, cover TS/JS/HTML/Java/Python/C++ |
| Mapping | Python heuristics + `tree-sitter-language-pack` for route/import extraction | Multi-language parsing without per-language toolchains |
| Website check | `httpx` (GET/HEAD only) | Timeouts, TLS info, simple API |
| Local HTTP API | Starlette + uvicorn, bound to 127.0.0.1 | Small; serves the viewer and JSON |
| Viewer | TypeScript (strict), Vite, plain HTML + Tailwind, Cytoscape.js for the graph, Zod for API validation | No framework needed for 3 views; builds to static files shipped inside the Python package |
| Tooling | ruff, pytest, pytest-asyncio; vitest for the viewer | Matches the developer's standards |
| Packaging | `pyproject.toml` (hatchling), installable via `pipx` / `uvx` | One-command install |

## Architecture
```
MCP client (Claude Code / Cursor)
        │ stdio (JSON-RPC)
        ▼
┌──────────────────── appsec_mcp ────────────────────┐
│ server.py      FastMCP tool definitions (thin)      │
│   │                                                 │
│   ▼                                                 │
│ services/                                           │
│   scan_service ──► walker ──► ledger (files_read)   │
│        │           └► language detection            │
│        ├──► scanners/ (adapter interface)           │
│        │      semgrep · gitleaks · osv · builtin    │
│        ├──► mapper/ (nodes + edges)                 │
│        └──► explain/ (plain-language templates)     │
│   patch_service ──► recipes/ · diff · backups       │
│   web_check_service ──► httpx (SSRF-guarded)        │
│   │                                                 │
│   ▼                                                 │
│ storage/ (SQLite repository classes)                │
│   ▲                                                 │
│ http_api.py (Starlette, 127.0.0.1, token) ◄── viewer│
└─────────────────────────────────────────────────────┘
```
**Data flow (scan):**
1. `scan_project(path)` resolves and validates the root, then creates a `scans` row.
2. The walker yields files lazily (O(n) over files). It honours `.gitignore` and default excludes (`node_modules`, `.git`, `build`, `dist`, `venv`, `target`) and a size cap. Each file is recorded in `files_read` as read or skipped, with a reason.
3. Scanner adapters run in parallel threads, each with its own timeout. Each adapter returns `RawFinding`s and records the rules it applied in `rules_applied`.
4. A normaliser deduplicates findings (by file, line and CWE) and maps severity to critical/high/medium/low/info. Explain templates attach plain-language text.
5. The mapper builds nodes and edges from parsed files and attaches finding counts per node.
6. Results are persisted, and a compact summary is returned to the AI.

**Data flow (patch):** proposal → diff stored with the SHA-256 of each target file → apply checks the hashes are unchanged → originals copied to `~/.appsec-mcp/backups/<patch_id>/` → files written → status `applied`.

## Database schema
```
projects
  id INTEGER PK
  root_path TEXT UNIQUE NOT NULL        -- resolved absolute path
  name TEXT NOT NULL
  created_at TEXT NOT NULL              -- ISO-8601 UTC

scans
  id INTEGER PK
  project_id INTEGER FK→projects.id
  started_at TEXT NOT NULL
  finished_at TEXT
  status TEXT CHECK IN ('running','completed','failed','partial')
  score INTEGER                         -- 0..100
  summary_json TEXT                     -- counts by severity, scanners run/skipped

files_read
  id INTEGER PK
  scan_id INTEGER FK→scans.id
  rel_path TEXT NOT NULL
  language TEXT
  size_bytes INTEGER
  sha256 TEXT
  status TEXT CHECK IN ('read','skipped')
  skip_reason TEXT                      -- gitignored | too_large | binary | excluded_dir | symlink_outside_root

rules_applied
  id INTEGER PK
  scan_id INTEGER FK→scans.id
  scanner TEXT NOT NULL                 -- semgrep | gitleaks | osv | builtin
  rule_id TEXT NOT NULL
  scanner_version TEXT
  files_matched INTEGER NOT NULL DEFAULT 0

findings
  id INTEGER PK
  scan_id INTEGER FK→scans.id
  fingerprint TEXT NOT NULL             -- stable hash(rule_id, rel_path, normalized snippet) for diffing
  scanner TEXT NOT NULL
  rule_id TEXT NOT NULL
  severity TEXT CHECK IN ('critical','high','medium','low','info')
  cwe TEXT
  rel_path TEXT
  line_start INTEGER
  line_end INTEGER
  snippet_redacted TEXT                 -- secrets masked
  title TEXT NOT NULL
  plain_explanation TEXT NOT NULL
  fix_hint TEXT
  patchable INTEGER NOT NULL DEFAULT 0  -- bool
  status TEXT CHECK IN ('new','existing','fixed') -- relative to previous scan

map_nodes
  id INTEGER PK
  scan_id INTEGER FK→scans.id
  kind TEXT CHECK IN ('component','entry_point','route','data_store','external_service','secret','dependency')
  label TEXT NOT NULL
  rel_path TEXT
  meta_json TEXT
  finding_count INTEGER NOT NULL DEFAULT 0

map_edges
  id INTEGER PK
  scan_id INTEGER FK→scans.id
  source_node_id INTEGER FK→map_nodes.id
  target_node_id INTEGER FK→map_nodes.id
  kind TEXT CHECK IN ('imports','calls','handles','reads','depends_on')

patches
  id INTEGER PK
  project_id INTEGER FK→projects.id
  finding_id INTEGER FK→findings.id NULL
  recipe TEXT NULL
  proposal_token TEXT UNIQUE NOT NULL   -- random 32 bytes, url-safe
  diff TEXT NOT NULL
  file_hashes_json TEXT NOT NULL        -- {rel_path: sha256_before}
  status TEXT CHECK IN ('proposed','applied','reverted','expired')
  created_at TEXT NOT NULL
  applied_at TEXT
  backup_dir TEXT

Indexes: findings(scan_id, severity), files_read(scan_id), map_nodes(scan_id), findings(fingerprint)
```

## API contract

### MCP tools (stdio)
All tools return Pydantic-serialised JSON. Errors are returned as MCP tool errors with a `code` and a plain-language `message`.

| Tool | Request | Response | Errors |
|---|---|---|---|
| `scan_project` | `{path: str, scanners?: list["semgrep","gitleaks","osv","builtin"], max_file_kb?: int=1024}` | `{scan_id, status, score, counts: {critical,high,medium,low,info}, new, fixed, scanners_run, scanners_skipped: [{name, reason, install_hint}], files_read, files_skipped, duration_s}` | `PATH_NOT_FOUND`, `PATH_NOT_DIRECTORY`, `PATH_FORBIDDEN` (system dirs), `SCAN_IN_PROGRESS` |
| `get_findings` | `{scan_id: int, min_severity?: str="low", limit?: int=50, offset?: int=0}` | `{total, items: [{id, severity, title, rel_path, line_start, plain_explanation, patchable, status}]}` | `SCAN_NOT_FOUND` |
| `explain_finding` | `{finding_id: int}` | `{id, title, severity, cwe, what, why_it_matters, how_to_fix, snippet_redacted, references: [url]}` | `FINDING_NOT_FOUND` |
| `get_system_map` | `{scan_id: int, format?: "summary"\|"graph"="summary"}` | summary: `{components, entry_points, routes, data_stores, external_services, secrets_locations, dependencies_count, hotspots: [{node, finding_count}]}`; graph: `{nodes, edges}` | `SCAN_NOT_FOUND` |
| `get_audit_ledger` | `{scan_id: int, section?: "files"\|"rules"\|"all"="all", limit?: int=200, offset?: int=0}` | `{files: {read, skipped, items}, rules: [{scanner, rule_id, files_matched}], scanners: [{name, version, duration_s}]}` | `SCAN_NOT_FOUND` |
| `list_recipes` | `{scan_id: int}` | `{recipes: [{id, title, description, applicable: bool, reason}]}` | `SCAN_NOT_FOUND` |
| `propose_patch` | `{finding_id: int}` | `{patch_id, proposal_token, summary, diff, files: [rel_path], expires_at}` | `FINDING_NOT_FOUND`, `NOT_PATCHABLE` |
| `propose_hardening` | `{scan_id: int, recipe: str}` | same as `propose_patch` | `RECIPE_NOT_FOUND`, `RECIPE_NOT_APPLICABLE` |
| `apply_patch` | `{proposal_token: str}` | `{patch_id, status: "applied", files_changed, backup_dir}` | `TOKEN_INVALID`, `PROPOSAL_EXPIRED` (30 min), `FILES_CHANGED_SINCE_PROPOSAL`, `WRITE_FAILED` (auto-rollback) |
| `revert_patch` | `{patch_id: int}` | `{patch_id, status: "reverted", files_restored}` | `PATCH_NOT_FOUND`, `NOT_APPLIED`, `FILES_CHANGED_SINCE_APPLY` (needs `force: true`) |
| `check_website` | `{url: str, allow_private?: bool=false}` | `{url, final_url, tls: {valid, expires, protocol}, headers: [{name, present, value, verdict, plain_explanation}], cookies: [{name, secure, httponly, samesite}], score}` | `URL_INVALID`, `URL_PRIVATE_BLOCKED`, `TIMEOUT`, `TLS_ERROR` |
| `list_scans` | `{project_path?: str, limit?: int=20}` | `{items: [{scan_id, project, started_at, score, counts}]}` | none |

### CLI
- `appsec-mcp serve`: start the MCP stdio server (the default command).
- `appsec-mcp scan <path> [--json] [--fail-on high]`: headless scan for CI. The exit code is non-zero at or above the threshold.
- `appsec-mcp view [--port 0]`: start the local HTTP API and viewer, then print the URL with its token.

### Local HTTP API (viewer only; 127.0.0.1; header `X-AppSec-Token` required)
| Method | Path | Response | Errors |
|---|---|---|---|
| GET | `/api/scans?limit=` | `{items: ScanSummary[]}` | 401 |
| GET | `/api/scans/{id}` | `ScanSummary` | 401, 404 |
| GET | `/api/scans/{id}/findings?min_severity=&limit=&offset=` | `{total, items: Finding[]}` | 401, 404, 422 |
| GET | `/api/findings/{id}` | `FindingDetail` | 401, 404 |
| GET | `/api/scans/{id}/map` | `{nodes, edges}` | 401, 404 |
| GET | `/api/scans/{id}/ledger?section=&limit=&offset=` | Ledger | 401, 404, 422 |
| GET | `/` and `/assets/*` | Static viewer | none |

The HTTP API is read-only. Patching is only possible through MCP, so the user approves it in the AI conversation.

## Security and error handling
- **The tool's own attack surface**
  - **Path confinement:** the scan root is resolved with `Path.resolve()`. Every read and write must stay under that root. Symlinks that point outside the root are skipped and logged.
  - **Forbidden roots:** the filesystem root, the home directory itself, `C:\Windows`, `/etc` and `/usr`.
  - **Subprocess safety:** list-form args only, never `shell=True`. Paths are passed after `--`. Each scanner has a timeout (default 300 s) and an output size cap.
  - **Secrets redaction:** secret values in snippets and the DB are masked as `sk_live_****abcd`. Raw secrets never leave the process.
  - **Patching:** proposals are bound to file hashes and expire after 30 minutes. Backups are written before any write. If a multi-file apply fails partway, it rolls back.
  - **Website check:** HTTPS/HTTP only, GET and HEAD only, at most 5 redirects, 10 s timeout. DNS is resolved first and private, loopback and link-local IPs are blocked unless `allow_private`. The redirect target is re-checked.
  - **HTTP API:** binds only to 127.0.0.1, uses a random per-session token, sends a strict CSP, and is read-only.
  - **SQL:** parameterised queries only.
- **Errors**
  - Domain exceptions (`AppSecError` subclasses) carry a `code` and a plain-language message. They are logged before being converted to MCP errors.
  - A failed scanner does not fail the scan. The scan status becomes `partial` and the skipped scanner is reported with a reason and an install hint.
  - Logs go to stderr (stdout is reserved for the MCP protocol) and to a rotating file in `~/.appsec-mcp/logs/`.

## Testing strategy
- **Unit (pytest):** walker, ledger, normaliser, severity mapping, redaction, mapper heuristics, recipe diff generation, SSRF guard, path confinement. External binaries and the network are mocked via adapter interfaces and recorded JSON outputs.
- **Fixtures:** `tests/fixtures/vuln_apps/` holds small deliberately vulnerable apps:
  - `express_app` (TS): SQL injection, XSS, hard-coded secret, CORS `*`
  - `flask_app` (Py): debug mode, `eval`, missing CSRF
  - `spring_app` (Java): SQL string concat, insecure deserialisation
  - `cpp_cli` (C++): `strcpy`/`gets`, format string
  - `static_site` (HTML): inline secrets, mixed content

  Each fixture has an `expected.json` listing its planted vulnerabilities.
- **Integration (marked `@pytest.mark.scanners`, skipped if the binaries are absent):** real Semgrep, gitleaks and OSV runs on the fixtures, asserting full recall on `expected.json`.
- **MCP contract tests:** an in-process FastMCP client calls each tool and checks the response against the Pydantic schemas.
- **Patch tests:** propose → apply → re-scan shows `fixed` → revert gives byte-identical files.
- **Viewer:** vitest for the Zod schemas and data transforms, plus a manual checkpoint review.
- **Self-scan in CI:** `appsec-mcp scan . --fail-on high` runs on its own repo.

## Risks and open questions
- **Semgrep rule quality and noise.** Mitigation: a curated rule pack (`p/owasp-top-ten`, `p/secrets`, language packs) and a severity floor. *Open:* should a user-tunable ignore file (`.appsecignore`) ship in v1?
- **External binaries on Windows.** Semgrep on native Windows is limited. *Open:* fall back to WSL or Docker, or recommend `pipx install semgrep` within WSL? Need to test on the MSI laptop early (T8).
- **Mapper accuracy across 5 languages.** Heuristics will miss framework-specific routing. v1 supports Express, Next.js, Flask, FastAPI, Spring and `main()`. Other frameworks show as "component" only.
- **Patch safety.** Automated edits can break builds. Patches stay narrow, diffs are always shown first, and nothing is applied without the token.
- **Explanation coverage.** Rules without a curated template fall back to the scanner message plus a generic CWE explanation.
- **Legal and ethical:** `check_website` must not become a scanner for other people's sites. Passive-only checks and a "you own this site" note in the tool description reduce misuse. *Open:* require explicit domain confirmation?
