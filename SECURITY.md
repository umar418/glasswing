# Security

Glasswing only reads. `scan` and `report` never change a file, and
`scan --no-ai` opens no network connection. Both properties are covered by
automated tests.

## Reporting a problem

Please report privately: on GitHub, open the **Security** tab and choose
**Report a vulnerability**. Include the version (`glasswing --version`), your
operating system, and steps to reproduce.

These count as security bugs and are treated as urgent:

- A credential appearing unmasked in any output.
- Content from a settings file running as code in the HTML report.
- A settings file that crashes or hangs the scan.
- Any network connection during `scan --no-ai`.
- A finding that states something untrue about a configuration.

## Files Glasswing reads

The complete, current list is
[`src/glasswing/registry/apps.yaml`](src/glasswing/registry/apps.yaml). In summary:

- Claude Desktop: `claude_desktop_config.json`
- Claude Code: `~/.claude.json`, `~/.claude/settings.json`,
  `~/.claude/settings.local.json`, the system-wide `managed-settings.json`, and
  in each project `.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`
- Cursor: `~/.cursor/mcp.json`, project `.cursor/mcp.json`
- VS Code: `~/.copilot/mcp-config.json`, the user `mcp.json`, workspace
  `.vscode/mcp.json`
- Windsurf / Devin Desktop: `mcp_config.json` in its current and legacy locations
- Gemini CLI: `~/.gemini/settings.json`, project `.gemini/settings.json`
- Codex CLI: `~/.codex/config.toml`, project `.codex/config.toml`
- Continue: `~/.continue/config.yaml`, `~/.continue/config.json`

Project folders are looked for under `~/code`, `~/projects`, `~/dev`, `~/src`,
`~/Documents` and `~/Desktop` (three levels deep), in every project Claude Code
has recorded, and in any folder you add. Glasswing does not open your documents;
it looks only for the settings files named above. Files larger than 5 MB are
skipped.

## Files Glasswing writes

Only its own: reports in `~/.glasswing/reports/` and its settings in
`~/.glasswing/config.json`. API keys are never stored there.

## How credentials are handled

Settings files are treated as untrusted input. Every piece of text taken from
one passes through a redaction step before it is shown, and the finished output
is then checked once more against every credential found during the scan. See
[`parsers/secrets.py`](src/glasswing/parsers/secrets.py) and
[`report/safe_view.py`](src/glasswing/report/safe_view.py).

Masking has limits. A short, ordinary-looking password that sits somewhere with
no hint that it is a credential (for example, used as a folder name) cannot be
told apart from normal text and will not be masked.
