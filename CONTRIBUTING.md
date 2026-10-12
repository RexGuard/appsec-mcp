# Contributing

## Setup

```bash
uv venv --python 3.12
```

```bash
uv pip install -e ".[dev]"
```

```bash
cd viewer && npm ci
```

Checks (CI runs the same on Windows, macOS and Linux):

```bash
uv run ruff check src tests
```

```bash
uv run pytest -q
```

```bash
uv run appsec-mcp scan . --fail-on high
```

```bash
cd viewer && npm run typecheck && npm test && npm run build
```

## Layout

- `src/appsec_mcp/server.py`: MCP tools (thin; they call services)
- `services/`: scan, query, patch and web-check services
- `scanners/`: adapters (`builtin`, `semgrep`, `gitleaks`, `osv`) and the normaliser
- `mapper/`: per-language extractors and the graph builder
- `patching/` and `recipes/`: fixers, the patch engine and hardening recipes
- `storage/`: SQLite repositories (parameterised SQL only; a test enforces it)
- `viewer/`: TypeScript viewer, built into `src/appsec_mcp/viewer_dist`

## Adding a built-in rule

1. Add a `LineRule` to `scanners/builtin_rules.py` with an id (`builtin.<lang>.<name>`), languages,
   regex, severity, CWE and a one-line message. Set `fix_kind` only if a fixer handles it.
2. Plant an example in a fixture app under `tests/fixtures/vuln_apps/` and list it in that
   fixture's `expected.json` (category, CWE, file, line).
3. Run `pytest tests/scanners`; the recall test fails until the rule finds it.

## Adding a Semgrep rule

Add it to `scanners/rules/semgrep.yml`. Use dashes only in the id, put the CWE in
`metadata.cwe`, and `metadata.appsec_fix` if a fixer can patch it.

## Adding an explanation

`explain/catalog.yml` is keyed by CWE: `title`, `what`, `why`, `fix`, `references`. Keep `what` and
`why` short and free of jargon; the combined text must stay under 120 words.

## Adding a fixer

Write `fix_<name>(ws, target) -> FixOutcome | None` in `patching/fixers/`, register it in
`patching/fixers/__init__.py`, and return `None` for shapes you cannot rewrite safely. Fixers edit a
`Workspace` in memory; they never touch disk. Add a test in `tests/patching/` that proposes,
applies, re-scans and checks the finding is fixed.

## Adding a recipe

Implement `check(ctx)` and `build(ctx)` (see `recipes/security_headers.py`), register it in
`recipes/registry.py`, and add a case to `tests/recipes/test_recipes.py`.
