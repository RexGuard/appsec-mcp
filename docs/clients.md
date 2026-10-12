# MCP client setup

The server speaks MCP over stdio. The command is `appsec-mcp serve` (or just `appsec-mcp`).
If the command is not on your PATH, use its full path, for example
`C:\Users\you\Projects\SAP\.venv\Scripts\appsec-mcp.exe` on Windows.

## Claude Code

```bash
claude mcp add --scope user appsec -- appsec-mcp serve
```

## Claude Desktop

Edit `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "appsec": {
      "command": "appsec-mcp",
      "args": ["serve"]
    }
  }
}
```

## Cursor

`.cursor/mcp.json` in your project, or `~/.cursor/mcp.json` for all projects:

```json
{
  "mcpServers": {
    "appsec": {
      "command": "appsec-mcp",
      "args": ["serve"]
    }
  }
}
```

## Optional environment variables

| Variable | Default | Meaning |
|---|---|---|
| `APPSEC_MCP_HOME` | `~/.appsec-mcp` | Where the database, backups and logs live |
| `APPSEC_MCP_SEMGREP_CONFIGS` | (none) | Extra Semgrep configs, comma separated |
