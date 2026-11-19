# Security

Glasswing is read-only by default (`scan` and `report` never modify anything)
and local-only by default (no telemetry, no update pings, and no network call of
any kind during `scan --no-ai`). The only command that edits anything is
`track enable` (Phase 3, not yet shipped), which backs up configs first and is
undone by `track disable`.

## Reporting a vulnerability

Please open a private security advisory on GitHub
(`Security` tab → `Report a vulnerability`) rather than a public issue, or email
the maintainers listed in the repository. Include:

- The glasswing version (`glasswing --version`)
- Your OS
- Steps to reproduce
- What you expected vs. what happened

We'll acknowledge within a few days.

## What glasswing reads

Everything below is read for analysis; nothing is modified, and no file content
is ever sent anywhere (only file *paths* and structured findings are, and only
if you explicitly opt into a cloud AI summary).

- Claude Desktop: `claude_desktop_config.json`, its MCP log files
- Claude Code: `~/.claude.json`, `~/.claude/settings*.json`, project `.mcp.json`
  and `.claude/settings*.json`, and `~/.claude/projects/**/*.jsonl` session
  transcripts
- Cursor: `~/.cursor/mcp.json`, project `.cursor/mcp.json`
- VS Code: user and workspace `mcp.json`
- Windsurf: `~/.codeium/windsurf/mcp_config.json`
- Gemini CLI: `~/.gemini/settings.json`
- Codex CLI: `~/.codex/config.toml`
- Continue: `~/.continue/config.yaml` / `config.json`
- Project directories under `~/code`, `~/projects`, `~/dev`, `~/Documents`,
  `~/Desktop` (configurable), plus Claude Code's own known-project list

See [`src/glasswing/registry/apps.yaml`](src/glasswing/registry/apps.yaml) for
the exact, current list — it's the single source of truth and may grow over
time.

## Secret handling

Detected API keys/tokens are masked immediately (e.g. `sk-ant-…a1b2`) and the
full value is never written to disk, printed, or included in any report or AI
summary payload. See
[`src/glasswing/parsers/secrets.py`](src/glasswing/parsers/secrets.py) and
[`src/glasswing/summary/redact.py`](src/glasswing/summary/redact.py).
