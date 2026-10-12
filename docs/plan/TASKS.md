# Tasks

## Phase 1: Skeleton, models and viewer with mock data
- [x] T1: Create the Python project skeleton with a working MCP server
  Goal: An installable `appsec-mcp` package (src layout) whose MCP server starts over stdio and exposes a `ping` tool. ruff and pytest are configured.
  Files: `pyproject.toml`, `src/appsec_mcp/__init__.py`, `src/appsec_mcp/server.py`, `src/appsec_mcp/cli.py`, `src/appsec_mcp/errors.py`, `tests/test_server.py`, `.gitignore`, `README.md` (stub), `LICENSE` (MIT)
  Done when: `pip install -e .[dev]` works; `appsec-mcp serve` starts without writing to stdout outside the protocol; an in-process FastMCP client test calls `ping` and gets `"pong"`; `ruff check` and `ruff format --check` pass; `pytest` is green.

- [x] T2: Define the domain models and vulnerable fixture apps
  Goal: Pydantic models for every MCP request and response in SPEC.md, plus five small vulnerable fixture apps, each with an `expected.json`.
  Files: `src/appsec_mcp/models/{scan.py,finding.py,system_map.py,ledger.py,patch.py,web_check.py}`, `tests/fixtures/vuln_apps/{express_app,flask_app,spring_app,cpp_cli,static_site}/**`, `tests/fixtures/vuln_apps/*/expected.json`, `tests/models/test_models.py`
  Done when: the models validate the sample payloads and reject bad severities, negative ids and unknown fields; each fixture's `expected.json` lists its planted issues (rule category, file, line); the tests pass.

- [x] T3: Scaffold the TypeScript viewer with a findings page on mock data
  Goal: A Vite + strict TypeScript + Tailwind viewer showing a scan summary (score and severity counts) and a filterable findings list loaded from `mock/scan.json`, with a detail panel showing the plain-language explanation.
  Files: `viewer/package.json`, `viewer/tsconfig.json` (strict), `viewer/vite.config.ts`, `viewer/index.html`, `viewer/src/main.ts`, `viewer/src/api/schemas.ts` (Zod), `viewer/src/views/findings.ts`, `viewer/src/mock/scan.json`, `viewer/src/api/schemas.test.ts`
  Done when: `npm run dev` shows the findings page; filtering by severity works; the Zod schemas parse the mock data; `npm test` (vitest) passes; `npm run build` emits static files.

- [x] T4: Add the system map and audit ledger views to the viewer (mock data)
  Goal: A Map tab (Cytoscape graph, nodes coloured by kind, risky nodes highlighted, click a node to see its files and findings) and a Ledger tab (files read/skipped with reasons, rules applied per scanner, paginated).
  Files: `viewer/src/views/map.ts`, `viewer/src/views/ledger.ts`, `viewer/src/mock/map.json`, `viewer/src/mock/ledger.json`, `viewer/src/router.ts`, `viewer/src/views/*.test.ts`
  Done when: all three tabs render from mock data; the graph is usable with 200 or more nodes; the ledger paginates; vitest covers the data transforms; the build passes.

- [~] T5: Checkpoint: developer reviews the running UI
  Goal: The developer runs the viewer and approves or adjusts the layout, wording and information shown before backend work starts.
  Files: `docs/ui-review.md` (notes and decisions)
  Done when: the developer has clicked through Findings, Map and Ledger; requested changes are applied or logged as issues; `docs/ui-review.md` records the decisions; the mock JSON shapes are frozen as the API contract.

## Phase 2: Storage and scan engine
- [x] T6: Implement SQLite storage with migrations and repositories
  Goal: A local DB at `~/.appsec-mcp/appsec.db` (overridable via the `APPSEC_MCP_HOME` env var) with every table from SPEC.md and one repository class per aggregate.
  Files: `src/appsec_mcp/storage/{db.py,migrations.py,project_repo.py,scan_repo.py,finding_repo.py,map_repo.py,patch_repo.py}`, `tests/storage/test_*.py`
  Done when: migrations are idempotent; CRUD works for every repository against a tmp-path DB; all SQL is parameterised (verified with a grep-based test); the indexes exist.

- [ ] T7: Build the file walker and audit ledger
  Goal: A lazy (generator) walker that confines itself to the root, honours `.gitignore` and default excludes, detects language and binary files, applies the size cap, handles symlinks, and records every file as read or skipped with a reason.
  Files: `src/appsec_mcp/scan/walker.py`, `src/appsec_mcp/scan/language.py`, `src/appsec_mcp/scan/ledger.py`, `src/appsec_mcp/security/paths.py`, `tests/scan/test_walker.py`, `tests/security/test_paths.py`
  Done when: on the fixtures, the ledger accounts for 100% of files; a symlink escaping the root is skipped as `symlink_outside_root`; forbidden roots raise `PATH_FORBIDDEN`; a 10k-file synthetic tree walks in under 5 s.

- [ ] T8: Add the scanner adapter interface and the Semgrep adapter
  Goal: A `ScannerAdapter` protocol (`is_available()`, `version()`, `run(root, files) -> AdapterResult`), a Semgrep adapter using the curated rule packs, safe subprocess execution with a timeout, and a normaliser to severity/CWE plus fingerprints.
  Files: `src/appsec_mcp/scanners/{base.py,semgrep.py,normalize.py,_subprocess.py}`, `src/appsec_mcp/scanners/rules/semgrep.yml`, `tests/scanners/test_semgrep.py` (mocked from recorded JSON), `tests/integration/test_semgrep_fixtures.py`
  Done when: the unit tests pass with a mocked subprocess; the integration test finds every Semgrep-category issue in `expected.json` (skipped if Semgrep is absent); a missing binary returns a skip reason with an install hint; tested on Windows (or WSL fallback documented).

- [ ] T9: Add the gitleaks, OSV-Scanner and built-in config check adapters, plus redaction
  Goal: Secret, dependency and config findings (debug mode, CORS `*`, committed `.env`, missing header middleware), with secrets masked everywhere.
  Files: `src/appsec_mcp/scanners/{gitleaks.py,osv.py,builtin.py}`, `src/appsec_mcp/security/redact.py`, `tests/scanners/test_{gitleaks,osv,builtin}.py`, `tests/security/test_redact.py`
  Done when: each adapter has mocked unit tests; no raw secret from the fixtures appears in any stored row or tool output (asserted by a test); the built-in checks catch all config issues in `expected.json`.

- [ ] T10: Implement the system mapper
  Goal: Extract components, entry points, routes (Express, Next.js, Flask, FastAPI, Spring), data stores, external services (HTTP calls, SDK imports), secret locations and dependencies into nodes and edges, with a finding count per node.
  Files: `src/appsec_mcp/mapper/{builder.py,extractors/js_ts.py,extractors/python.py,extractors/java.py,extractors/cpp.py,extractors/html.py}`, `tests/mapper/test_*.py`
  Done when: for each fixture, the expected routes and entry points appear in the map (asserted); edges are deduplicated; unsupported frameworks fall back to `component` nodes without errors.

- [ ] T11: Wire the scan service and expose the read-only MCP tools
  Goal: `scan_project`, `get_findings`, `explain_finding`, `get_system_map`, `get_audit_ledger` and `list_scans` work end to end with persistence, parallel adapters, score calculation, new/fixed diffing against the previous scan, and plain-language explanation templates.
  Files: `src/appsec_mcp/services/scan_service.py`, `src/appsec_mcp/explain/{templates.py,catalog.yml}`, `src/appsec_mcp/scoring.py`, `src/appsec_mcp/server.py`, `src/appsec_mcp/cli.py` (`scan` command), `tests/services/test_scan_service.py`, `tests/test_server_tools.py`
  Done when: the MCP contract tests pass for all six tools; a re-scan after deleting a vulnerable line marks it `fixed`; `appsec-mcp scan <fixture> --fail-on high` exits non-zero; every finding has non-empty plain-language text of 120 words or fewer.

## Phase 3: Real data in the viewer, patching and website checks
- [ ] T12: Serve the viewer from a local HTTP API backed by real data
  Goal: `appsec-mcp view` starts Starlette on 127.0.0.1 with a per-session token, serves the built viewer, and the viewer fetches real scans instead of mock JSON.
  Files: `src/appsec_mcp/http_api.py`, `src/appsec_mcp/cli.py` (`view`), `viewer/src/api/client.ts`, `viewer/src/main.ts`, `pyproject.toml` (include the built viewer assets), `tests/test_http_api.py`
  Done when: requests without a token return 401; the server binds only to localhost (tested); the viewer shows a real fixture scan with all three tabs; Zod rejects malformed responses with a visible error state; the CSP header is set.

- [ ] T13: Implement the patch engine (propose, apply, revert)
  Goal: Safe, approval-gated patching for patchable findings (hard-coded secret → env var, Flask debug off, CORS `*` → allow-list, `strcpy` → `strncpy`/`snprintf`, SQL concat → parameterised query for the supported patterns).
  Files: `src/appsec_mcp/patching/{engine.py,diff.py,backups.py,fixers/*.py}`, `src/appsec_mcp/services/patch_service.py`, `src/appsec_mcp/server.py`, `tests/patching/test_*.py`
  Done when: propose writes nothing to disk (asserted); apply fails with `FILES_CHANGED_SINCE_PROPOSAL` if a file was edited; expired tokens are rejected; a forced failure mid-way through a multi-file apply rolls back; revert restores byte-identical files; re-scan marks the patched finding `fixed`.

- [ ] T14: Add hardening recipes ("add a security layer")
  Goal: `list_recipes` and `propose_hardening` for security headers, rate limiting, CSRF, input validation scaffolding and `.env` + `.gitignore` setup, for Express, Next.js, Flask, FastAPI and Spring Boot. Applicability is detected from the system map.
  Files: `src/appsec_mcp/recipes/{registry.py,security_headers.py,rate_limit.py,csrf.py,env_secrets.py,input_validation.py}`, `src/appsec_mcp/server.py`, `tests/recipes/test_*.py`
  Done when: each recipe produces a valid diff on its matching fixture; non-applicable recipes report the reason; applying `security_headers` to `express_app` clears the missing-headers finding on re-scan.

- [ ] T15: Implement the passive website check with an SSRF guard
  Goal: `check_website(url)` reports TLS validity and expiry, security headers and cookie flags in plain language, using GET/HEAD only.
  Files: `src/appsec_mcp/services/web_check_service.py`, `src/appsec_mcp/security/ssrf.py`, `src/appsec_mcp/server.py`, `tests/services/test_web_check.py` (respx-mocked), `tests/security/test_ssrf.py`
  Done when: private, loopback and link-local targets and redirects to them are blocked unless `allow_private`; only GET/HEAD are ever sent (asserted); timeouts and TLS errors map to their error codes; the tool description states "only check sites you own."

## Phase 4: Hardening and docs
- [ ] T16: Harden the tool and add CI with a self-scan
  Goal: The tool's own security and reliability are verified: logging only to stderr and a file, custom exceptions logged before conversion, scanner output size caps, and a concurrency guard (`SCAN_IN_PROGRESS`).
  Files: `src/appsec_mcp/logging_setup.py`, `src/appsec_mcp/errors.py`, `.github/workflows/ci.yml` (ruff, pytest, vitest, viewer build, self-scan on Ubuntu, Windows and macOS), `tests/test_errors.py`
  Done when: CI is green on all three OSes; `appsec-mcp scan . --fail-on high` passes on its own repo; a fuzz-style test of tool inputs (random paths, huge limits, unicode) produces only typed errors and no crashes.

- [ ] T17: Write user docs and packaging for non-technical users
  Goal: A clear README and docs so a vibe coder can install, connect and complete the first scan and fix in under 10 minutes.
  Files: `README.md`, `docs/getting-started.md` (pipx/uvx install, installing the scanners per OS), `docs/clients.md` (config snippets for Claude Code, Claude Desktop and Cursor), `docs/what-it-reads.md` (ledger explained), `docs/patching.md`, `CONTRIBUTING.md` (adding rules, explanations and recipes), `pyproject.toml` (metadata, version)
  Done when: a fresh machine can follow `getting-started.md` to a first scan; `pipx install .` and `uvx appsec-mcp` both work; three non-security testers complete Flows 1 and 3 without help (results noted in `docs/ui-review.md`).
