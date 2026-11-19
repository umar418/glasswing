from __future__ import annotations

import json
import sys
import tempfile
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from glasswing import __version__
from glasswing import config as cfg
from glasswing.parsers.secrets import scrub
from glasswing.report import render_all
from glasswing.report.safe_view import safe_scan
from glasswing.scanner import run_scan
from glasswing.summary import providers
from glasswing.summary.redact import build_redacted_payload
from glasswing.summary.template import build_template_summary

app = typer.Typer(
    name="glasswing",
    help="See what you've given AI tools access to and what to lock down. Runs only on this computer.",
    add_completion=False,
)
out = Console()  # results
err = Console(stderr=True)  # progress and notes, so --json output on stdout stays pure JSON


def _ai_summary(data: dict, raw_secrets: set[str], no_ai: bool, interactive: bool) -> Optional[str]:
    """Returns AI-written markdown, or None to use the built-in summary. Never raises."""
    settings = cfg.load_config()
    choice = settings["ai_provider"]
    if no_ai or choice == "none":
        return None
    payload = json.loads(scrub(json.dumps(build_redacted_payload(data)), raw_secrets))

    if choice in ("auto", "ollama"):
        model = providers.detect_ollama_model()
        if model:
            err.print(f"[dim]Writing the summary with your local model ({escape(model)}). Nothing leaves this computer.[/dim]")
            text = providers.call_ollama(model, payload)
            if text:
                return text
            err.print("[yellow]The local model did not answer; using the built-in summary.[/yellow]")
            return None
        if choice == "ollama":
            err.print("[yellow]No local Ollama model found; using the built-in summary.[/yellow]")
            return None

    key = providers.anthropic_key()
    if not key:
        return None
    if "anthropic" not in settings["consented_providers"]:
        if not interactive:
            err.print("[dim]A cloud AI key is set but has not been approved for Glasswing; using the built-in summary.[/dim]")
            return None
        err.print("\n[bold]Send a redacted summary to Anthropic for a plain-language write-up?[/bold]")
        err.print("This is exactly what would be sent (no file contents, no passwords or keys):\n")
        err.print(escape(json.dumps(payload, indent=2)), highlight=False)
        if not typer.confirm("\nSend this?", default=False, err=True):
            err.print("[dim]Not sent. Using the built-in summary.[/dim]")
            return None
        cfg.mark_consented("anthropic")
    text = providers.call_anthropic(key, payload)
    if not text:
        err.print("[yellow]The cloud model did not answer; using the built-in summary.[/yellow]")
    return text


def _write_reports(data: dict, started_at, files: dict[str, str]) -> Path:
    stamp = started_at.strftime("%Y%m%dT%H%M%S")
    for base in (cfg.reports_dir(), Path(tempfile.gettempdir()) / "glasswing-reports"):
        try:
            target = base / stamp
            target.mkdir(parents=True, exist_ok=True)
            for name, content in files.items():
                (target / name).write_text(content, encoding="utf-8")
            return target
        except OSError:
            continue
    raise typer.Exit(2)


def _print_summary(data: dict) -> None:
    out.print(f"\n[bold]Exposure level: {data['exposure_level']}[/bold]")
    found = [a["app_name"] for a in data["apps"] if a["found"]]
    out.print(f"Apps with settings found: {escape(', '.join(found)) if found else 'none'}")
    if data["severity_counts"]:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity")
        table.add_column("Findings")
        for sev in ("critical", "high", "medium", "low", "info"):
            if data["severity_counts"].get(sev):
                table.add_row(sev.upper(), str(data["severity_counts"][sev]))
        out.print(table)
        out.print("[bold]Top findings:[/bold]")
        for f in data["findings"][:3]:
            times = f" (x{f['count']})" if f["count"] > 1 else ""
            out.print(escape(f"  [{f['severity'].upper()}] {f['title']}{times} - {f['subject']}"), highlight=False)
    else:
        out.print("No risky settings found in the apps checked.")
    if data["warnings"]:
        out.print(f"[yellow]{len(data['warnings'])} file(s) could not be read; see the report.[/yellow]")


@app.command()
def scan(
    no_ai: bool = typer.Option(False, "--no-ai", help="Never contact any AI model; use the built-in summary."),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON to stdout and write no files."),
    extra_root: list[str] = typer.Option([], "--project-root", help="Extra folder to search for project settings (repeatable)."),
    open_report: bool = typer.Option(True, help="Open the HTML report when done."),
):
    """Find AI apps, their MCP servers, permissions and stored credentials; score the risk; write a report."""
    roots = list(extra_root) + list(cfg.load_config()["extra_project_roots"])
    result = run_scan(roots or None)
    raw = result.raw_secrets
    data = safe_scan(result)
    summary = build_template_summary(data)
    ai_text = _ai_summary(data, raw, no_ai, interactive=not json_out and sys.stdin.isatty())
    data, summary, files = render_all(result, ai_text)

    if json_out:
        sys.stdout.write(files["report.json"] + "\n")
        return
    try:
        target = _write_reports(data, result.started_at, files)
    except typer.Exit:
        err.print("[red]Could not write the report files (no writable folder).[/red]")
        _print_summary(data)
        raise
    _print_summary(data)
    report = target / "report.html"
    out.print("\nReport written to:")
    out.print(escape(str(report)), highlight=False, soft_wrap=True)
    if open_report:
        try:
            webbrowser.open(report.resolve().as_uri())
        except Exception:
            pass


@app.command()
def report():
    """Re-open the most recent report."""
    base = cfg.reports_dir()
    latest = sorted((d for d in base.iterdir() if (d / "report.html").is_file()), reverse=True) if base.is_dir() else []
    if not latest:
        err.print("[yellow]No report found yet. Run 'glasswing scan' first.[/yellow]")
        raise typer.Exit(1)
    path = latest[0] / "report.html"
    webbrowser.open(path.resolve().as_uri())
    out.print(escape(str(path)), highlight=False, soft_wrap=True)


@app.command()
def history():
    """Timeline of AI tool activity. Not available yet."""
    err.print("Glasswing does not read activity logs yet. This version reports what your AI tools are able to do, not what they did.")
    raise typer.Exit(1)


track_app = typer.Typer(help="Live logging of MCP tool calls. Not available yet.")
app.add_typer(track_app, name="track")


def _track_unavailable():
    err.print("Live tracking is not available yet. No settings were changed.")
    raise typer.Exit(1)


track_app.command("enable")(_track_unavailable)
track_app.command("disable")(_track_unavailable)
track_app.command("status")(_track_unavailable)


@app.command()
def config(
    ai_provider: Optional[str] = typer.Option(None, "--ai-provider", help="auto | ollama | anthropic | none"),
    add_project_root: Optional[str] = typer.Option(None, "--add-project-root", help="Always search this folder for project settings."),
    forget_consent: bool = typer.Option(False, "--forget-consent", help="Ask again before any cloud AI call."),
):
    """Show or change Glasswing's own settings (~/.glasswing/config.json)."""
    settings = cfg.load_config()
    changed = False
    if ai_provider is not None:
        if ai_provider.lower() not in cfg.AI_PROVIDERS:
            err.print(f"[red]Unknown provider. Choose one of: {', '.join(cfg.AI_PROVIDERS)}[/red]")
            raise typer.Exit(2)
        settings["ai_provider"], changed = ai_provider.lower(), True
    if add_project_root:
        if add_project_root not in settings["extra_project_roots"]:
            settings["extra_project_roots"].append(add_project_root)
        changed = True
    if forget_consent:
        settings["consented_providers"], changed = [], True
    if changed:
        cfg.save_config(settings)
    out.print(escape(str(cfg.config_path())), highlight=False)
    out.print(escape(json.dumps(settings, indent=2)), highlight=False)


@app.command()
def version():
    """Print the glasswing version."""
    out.print(__version__)


def _version_callback(value: bool):
    if value:
        out.print(__version__)
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    show_version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Print the version and exit."),
):
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan, no_ai=False, json_out=False, extra_root=[], open_report=True)


if __name__ == "__main__":
    app()
