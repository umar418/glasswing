# Glasswing

**What have you given AI tools access to, what have they actually touched, and what should you lock down?**

Glasswing is a free, open-source, **local-only** scanner for the AI tools on your
computer (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex
CLI, Continue). It finds every MCP server and permission rule they're configured
with, flags secrets sitting in plain text, scores the risk, and explains it all in
plain language — then opens a single-file HTML report.

It's built for people who aren't security engineers: doctors, lawyers, accountants,
and anyone else who handed an AI assistant broad filesystem or shell access without
fully weighing what that means.

## What it does

- Discovers AI app configs and MCP server definitions on your machine (and in your
  project folders).
- Classifies each server's capability (filesystem, shell, browser, network, email,
  database, payments, cloud infra, ...), its scope, and how trustworthy its source
  looks (pinned official package vs. unpinned `npx -y` from an unknown publisher).
- Detects and **masks** API keys/tokens sitting in plain text in those configs.
- Flags Claude Code permission rules that are broader than they need to be
  (e.g. a blanket `Bash(*)` allow).
- Scores everything with a transparent, rule-based risk engine (`registry/rules.yaml`)
  — every finding carries a rule ID you can look up.
- Writes a self-contained `report.html` (plus `report.json` and `summary.md`) with
  an AI-written plain-language summary at the top.
- Lists, as a manual checklist, the cloud-connector settings pages it **cannot**
  see from your machine (Google/Microsoft/GitHub/Slack third-party access, and
  connectors inside claude.ai / ChatGPT / Gemini).

## What it does *not* do

- It does not read the contents of your documents — only file *paths* and logged
  *arguments* are classified.
- It makes **zero network calls** unless you explicitly opt in to a cloud AI
  summary (`scan` without `--no-ai` will first check for a local Ollama model,
  then a bring-your-own API key you've set — and will show you exactly what would
  be sent before it sends anything).
- It never blocks or enforces anything. This is visibility and guidance, not an
  agent firewall.
- Activity-log parsing (`history`) and live tracking (`track enable`) are **not in
  this first release** — see Roadmap below. Everything else in this README is
  shipped.

## Privacy

Nothing leaves your machine unless you choose a cloud AI summary — and even then,
only a redacted, secret-free JSON summary of findings is sent, never raw file
contents or full secret values. The report file itself is safe to share: every
secret is masked (`sk-ant-…a1b2`) before it's ever written anywhere.

## Setup

You need **Python 3.10 or newer**. Check with `python3 --version` (on Windows:
`python --version`). If you don't have it, install it from
[python.org/downloads](https://www.python.org/downloads/).

Pick **one** of the options below.

### Option A — one command, nothing installed permanently (recommended)

Uses [`uv`](https://docs.astral.sh/uv/) to fetch and run Glasswing in a
throwaway environment:

```bash
uvx --from git+https://github.com/umar418/glasswing glasswing scan
```

Don't have `uv`? The installer scripts install it and then run the command
above. They're short — read them first ([install.sh](install.sh),
[install.ps1](install.ps1)).

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/umar418/glasswing/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/umar418/glasswing/main/install.ps1 | iex
```

### Option B — install it as a regular command with `pipx`

```bash
pipx install git+https://github.com/umar418/glasswing
glasswing scan
```

Upgrade later with `pipx upgrade glasswing`; remove with `pipx uninstall glasswing`.

To pin an exact release, add the tag: `git+https://github.com/umar418/glasswing@v0.1.0`.

### Option C — from source (for contributors)

```bash
git clone https://github.com/umar418/glasswing.git
cd glasswing
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Check that it works

1. **Version check** — confirms the install:

   ```bash
   glasswing --version
   ```

   You should see `0.1.0`.

2. **First scan, fully offline** — `--no-ai` guarantees zero network calls:

   ```bash
   glasswing scan --no-ai
   ```

   You'll see an exposure level (Low / Moderate / High / Critical), a count of
   findings by severity, and the top 3 findings. Your browser then opens the
   HTML report. If nothing is found, you'll get a **Low** rating — that's
   normal on a machine with no AI tools configured.

3. **Find the report files** — each scan writes three files to
   `~/.glasswing/reports/<timestamp>/`:
   - `report.html` — the full readable report (open it any time with `glasswing report`)
   - `report.json` — machine-readable
   - `summary.md` — plain-text summary

4. **Confirm nothing sensitive leaked** — open `report.json` and search for
   any API key you know is in your configs. You should only ever see a masked
   form like `sk-…a1b2`, never the full key.

5. **(Contributors) run the test suite**:

   ```bash
   pytest -q
   ```

   All tests should pass. They cover secret masking, the redaction pass, the
   rules engine, malformed-config handling, and a test that fails if any
   network socket opens during an offline scan.

### Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: glasswing` | With pipx, run `pipx ensurepath` and open a new terminal. From source, activate the virtualenv first. |
| `command not found: uvx` | Install uv (`curl -LsSf https://astral.sh/uv/install.sh \| sh`) and open a new terminal. |
| Report doesn't open | Run `glasswing report`, or open the path printed at the end of the scan. |
| An app you use isn't detected | Its config may be somewhere unexpected. Point Glasswing at extra project folders with `glasswing scan --project-root ~/some/folder`, or open an issue. |
| "couldn't read X" in the report | That file was missing or malformed. Glasswing skips it and carries on — nothing is wrong with your scan. |

### Optional: AI-written summary

Without `--no-ai`, Glasswing tries, in order:

1. **A local model** — if [Ollama](https://ollama.com) is running, it's used
   automatically. Nothing leaves your machine.
2. **Your own API key** — if `ANTHROPIC_API_KEY` is set, Glasswing shows you
   the exact redacted JSON it would send and asks before sending anything.
   Your answer is remembered.
3. **Neither** — falls back to the built-in template summary.

Running `glasswing` with no arguments is the same as `glasswing scan`.

## Commands

| Command | What it does |
|---|---|
| `glasswing scan` | Discover apps, MCP servers, permissions, secrets → write report, print terminal summary, open HTML report |
| `glasswing scan --no-ai` | Same, skip the AI summary (deterministic template summary instead) |
| `glasswing scan --json` | Machine-readable output to stdout |
| `glasswing report` | Re-open the latest report |
| `glasswing history` | Timeline of AI tool activity (**Phase 2 — not yet shipped**) |
| `glasswing track enable/disable/status` | Live MCP call logging via a local proxy (**Phase 3 — not yet shipped**) |
| `glasswing config` | View/set the AI summary provider and other settings |

Reports are written to `~/.glasswing/reports/<timestamp>/`.

## Risk scoring

Rules live in [`src/glasswing/registry/rules.yaml`](src/glasswing/registry/rules.yaml)
— plain text, no code changes needed to tweak wording or severity. Every finding in
a report shows its rule ID.

## Roadmap

- **Phase 1 (this release):** inventory, capability/trust/scope inference, secret
  detection + masking, rules engine, HTML/JSON/MD reports, template summary.
- **Phase 2:** parse Claude Code transcripts and Claude Desktop MCP logs into an
  activity timeline; `history` command; sensitive-activity flags.
- **Phase 3:** `glasswing track enable` — a local stdio MCP proxy that logs every
  tool call (not its full content) with tamper-evident hash chaining; config
  backup/restore.

## For teams

If you need this same visibility and control across a whole team — not just one
machine at a time — [Keelwise](https://keelwise.dev) brings centralized AI-access
policy, auditing and alerts to businesses, built for teams in medical, legal and
finance.

## License

MIT — see [LICENSE](LICENSE).
