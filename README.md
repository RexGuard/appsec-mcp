# AppSec MCP

An MCP server that checks your app's source code for security problems, explains each one in plain
language, maps what your app is made of, and shows exactly what it read. It can propose fixes, but
never writes anything without your approval.

Status: early development. The plan lives in [`docs/plan/`](docs/plan/) (PRD, SPEC, TASKS).

## Try it

```bash
pip install -e ".[dev]"
appsec-mcp serve      # starts the MCP server over stdio
```

Add it to Claude Code:

```bash
claude mcp add appsec -- appsec-mcp serve
```

The viewer (findings, system map, audit ledger) is in [`viewer/`](viewer/):

```bash
cd viewer && npm install && npm run dev
```

## License

MIT
