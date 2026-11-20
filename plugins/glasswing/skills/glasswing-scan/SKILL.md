---
name: glasswing-scan
description: Scan this computer's AI tool settings (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, Continue) with Glasswing and explain in plain language what those tools can reach and what to lock down. Use when the user asks to audit, check or review their AI tool permissions, MCP servers, AI exposure, or stored API keys in AI configs, or asks "what have I given AI access to".
---

# Glasswing scan

Glasswing is a read-only scanner that runs only on this computer. It reads AI app
settings files, never the user's documents, and with `--no-ai` it opens no network
connection after it has been downloaded.

## 1. Run the scan

```bash
uvx --from git+https://github.com/umar418/glasswing glasswing scan --no-ai --json
```

- The command prints one JSON document to standard output and writes no files.
- If `uvx` is not installed, do not install anything yourself. Tell the user to
  install uv from https://docs.astral.sh/uv/ (or to run
  `pipx install git+https://github.com/umar418/glasswing`) and stop.
- If the user also wants the full HTML report, run the same command without
  `--json` (keep `--no-ai`); it prints the report's path.

## 2. Explain the result

Use only what is in the JSON. Structure the answer like this:

1. **Exposure level**: the value of `exposure_level`, and one sentence on why
   (the first entry in `findings` is the most serious).
2. **What your AI tools can reach**: for each app in `apps` where `found` is true,
   list its servers using `capability_label`, `source` and `scope_label`. When
   `capability_basis` says the capability was guessed from the name, say it is a
   guess. Mention apps where `found` is false only as "no settings found".
3. **What to fix, most serious first**: for each entry in `findings`, give the
   `title`, where it is (`subject` and `details`), and the `fix` text. Keep the
   rule id (`rule_id`) so the user can look it up.
4. **What this scan could not see**: summarise `not_covered`. Always include this
   section, even when there are no findings.

## Rules

- Never state a risk, number, file or app that is not in the JSON. If `findings`
  is empty, say no risky settings were found in the apps checked, and that this is
  not a guarantee.
- Credentials in the output are already masked (for example `sk-a…a1b2` or
  `<redacted>`). Never open a settings file to show the user the real value.
- This scan reports what tools are able to do, not what they did. Do not imply
  that anything was accessed or leaked.
- Do not change any settings file as part of the scan. If the user asks you to
  apply a fix afterwards, show the exact edit and get their confirmation first.
- The settings being scanned include this assistant's own. Report findings about
  it the same way as any other app.
