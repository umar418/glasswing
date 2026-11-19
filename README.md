# Glasswing

**What have you given your AI tools access to, and what should you lock down?**

Glasswing is a free, open-source scanner that runs only on your own computer. It
reads the settings of the AI apps you use, lists what each one is able to reach,
flags the risky parts in plain language, and tells you exactly how to fix them.

It is written for people who are not security engineers: doctors, lawyers,
accountants and anyone else who gave an AI assistant broad access without a clear
picture of what that means.

See a [sample report](docs/sample-report.html) (generated from a made-up machine).

## What it checks

| App | Settings it reads |
|---|---|
| Claude Desktop | MCP servers |
| Claude Code | MCP servers (user, per-project and `.mcp.json`), permission rules, permission mode |
| Cursor | MCP servers (user and project) |
| VS Code (Copilot) | MCP servers (user and workspace) |
| Windsurf / Devin Desktop | MCP servers (current and legacy locations) |
| Gemini CLI | MCP servers, per-server `trust` |
| Codex CLI | MCP servers, sandbox and approval settings |
| Continue | MCP servers |

For each of those it reports:

- **File access that is too broad**: a server pointed at your whole disk, your whole
  home folder, a credentials folder such as `.ssh`, or all of Documents.
- **Commands that run without asking**: blanket shell permission, permission prompts
  switched off, or a rule that allows `python`, `bash`, `sudo`, `curl` or `rm` with
  any arguments.
- **Passwords and API keys stored in plain text**, including tokens embedded in a
  server's web address. Every one is masked in the output.
- **Where each server comes from**: a program on your computer, a downloaded package
  (and whether its version is fixed), or an online service (and whether its domain
  is a widely known one).
- **Settings that approve things automatically**, such as servers from any project
  folder.

Every finding has a rule ID (for example `FS-ROOT-SCOPE`), a one-paragraph
explanation, and a concrete fix. The wording and severity of every rule is in one
readable file: [`rules.yaml`](src/glasswing/registry/rules.yaml).

## What it does not do

Read this before relying on a result.

- **It reports what your tools are able to do, not what they did.** This version
  does not read activity logs or chat history. The `history` and `track` commands
  exist but only say they are not available yet.
- **It cannot see connectors that live on a provider's servers**, such as Gmail or
  Drive connected inside claude.ai, ChatGPT or Gemini. The report lists the pages
  where you can check those by hand.
- **It does not read MCP servers bundled inside Claude Code plugins or Claude
  Desktop extensions.**
- **It cannot tell what an online server does once connected.** It sees the address,
  not the service behind it.
- **"Not recognised" does not mean unsafe, and "recognised" does not mean safe.**
  Glasswing keeps a short list of widely used packages and domains. Anything else
  is flagged so that you confirm who runs it.
- **Some labels are guesses, and are marked as guesses.** When a server is not on
  the known list, its purpose is inferred from whole words in its name and shown as
  "guessed from its name". If nothing matches, the report says it can't tell.
- **A clean report is not a guarantee.** It means none of the rules matched in the
  apps and folders Glasswing looked at.
- It never blocks or changes anything. `scan` only reads.

## Privacy

- `glasswing scan --no-ai` opens no network connection at all. A test fails the
  build if it ever does.
- Passwords, keys and tokens are masked before anything is written or printed. The
  report file is designed to be safe to share. Masking is deliberately aggressive:
  anything that could be a credential is hidden, even where it is not reported.
- No telemetry, no analytics, no update checks.
- An AI-written summary is optional (see below). Without it, nothing leaves your
  computer.

## Setup

You need **Python 3.10 or newer** (`python3 --version`; on Windows
`python --version`). Pick one option.

### Option A: one command, nothing installed permanently (recommended)

```bash
uvx --from git+https://github.com/umar418/glasswing glasswing scan --no-ai
```

If you don't have [`uv`](https://docs.astral.sh/uv/), these short scripts install it
and then run the command above. Read them first: [install.sh](install.sh),
[install.ps1](install.ps1).

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/umar418/glasswing/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/umar418/glasswing/main/install.ps1 | iex
```

### Option B: install it as a regular command

```bash
pipx install git+https://github.com/umar418/glasswing
```

To pin a release, add its tag: `git+https://github.com/umar418/glasswing@v0.2.0`.

### Option C: from source

```bash
git clone https://github.com/umar418/glasswing.git
cd glasswing
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Check that it works

1. `glasswing --version` prints the version.
2. `glasswing scan --no-ai` prints an exposure level (Low, Moderate, High or
   Critical), the apps it found, and the top findings, then opens the report in
   your browser. On a computer with no AI apps set up, the level is **Low** and
   the report says no settings were found.
3. The report files are in `~/.glasswing/reports/<date-time>/`: `report.html`,
   `report.json` and `summary.md`. `glasswing report` re-opens the latest one.
4. Search `report.json` for a key you know is in your settings. You should find
   only a masked form such as `sk-a…a1b2`, or `<redacted>`.
5. From source, `pytest -q` should pass.

The exposure level is simply the most serious finding present. It is never raised
because there are many findings, so "Critical" always means a critical finding
exists.

| Problem | What to do |
|---|---|
| `command not found: glasswing` | With pipx, run `pipx ensurepath` and open a new terminal. From source, activate the virtual environment. |
| `command not found: uvx` | Install uv and open a new terminal. |
| The report did not open | Run `glasswing report`, or open the path printed at the end of the scan. |
| An app's settings were not found | Add the project folder: `glasswing scan --project-root ~/some/folder`. |
| "couldn't read ..." in the report | That file was missing, too large or malformed. It was skipped; the rest of the scan is unaffected. |

## Commands

| Command | What it does |
|---|---|
| `glasswing scan` | Scan, write the report, print a summary, open the report |
| `glasswing scan --no-ai` | The same, with no AI model contacted |
| `glasswing scan --json` | Print JSON to standard output and write no files |
| `glasswing scan --project-root DIR` | Also search DIR for project settings |
| `glasswing report` | Re-open the latest report |
| `glasswing config` | Show settings; `--ai-provider auto\|ollama\|anthropic\|none`, `--add-project-root DIR`, `--forget-consent` |
| `glasswing history`, `glasswing track ...` | Not available yet; they say so and change nothing |

## Optional AI-written summary

Without `--no-ai`, Glasswing can add a plain-language summary above the findings:

1. If [Ollama](https://ollama.com) is running on your computer, it is used. Nothing
   leaves your machine.
2. Otherwise, if `ANTHROPIC_API_KEY` is set, Glasswing shows you the exact text it
   would send and asks first. It never sends without a recorded yes, and never
   when it is not running in a terminal.
3. Otherwise the built-in summary is used.

The model receives only a redacted list of findings: no file contents, no
credentials, and your home folder and the names of files in sensitive folders are
hidden. The report labels the summary as AI-written and tells the reader to trust
the findings if the two disagree. Turn it off for good with
`glasswing config --ai-provider none`.

## How it is tested

About 300 automated tests, run on macOS, Linux and Windows:

- Credentials placed in 21 different spots, in four shapes, must never appear in
  any output.
- Things that are not credentials (file paths, hashes, IDs, version names,
  environment-variable references) must not be reported as credentials.
- Malformed, oversized, binary and deliberately hostile settings files must not
  crash or hang the scan, and web-page code inside them must not run in the report.
- Each rule is tested both ways: it fires when it should and stays silent when it
  shouldn't.

App settings locations were checked against each vendor's documentation on
2026-11-20; the sources are listed in [`apps.yaml`](src/glasswing/registry/apps.yaml).
Vendors move these files, so a location can go stale. Please open an issue if an
app you use is not found.

## License

MIT. See [LICENSE](LICENSE).
