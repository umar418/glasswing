from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from glasswing import __version__
from glasswing.config import CONFIG_PATH, REPORTS_DIR, load_config, mark_consented, save_config
from glasswing.report.html import render_html
from glasswing.report.json_report import render_json
from glasswing.report.md_report import render_markdown
from glasswing.scanner import run_scan
from glasswing.summary import providers as providers_mod
from glasswing.summary.redact import build_redacted_payload
from glasswing.summary.template import build_template_summary

app = typer.Typer(
    name="glasswing",
    help="See what you've given AI tools access to, what they've touched, and what to lock down. Local-only.",
    no_args_is_help=False,
    add_completion=False,
)
console = Console()


def _latest_report_dir() -> Optional[Path]:
    if not REPORTS_DIR.is_dir():
        return None
    candidates = sorted([d for d in REPORTS_DIR.iterdir() if d.is_dir()], reverse=True)
    return candidates[0] if candidates else None


def _resolve_ai_summary(scan, no_ai: bool) -> tuple[Optional[str], Optional[dict]]:
    template_summary = build_template_summary(scan)
    if no_ai:
        return None, template_summary

    payload = build_redacted_payload(scan)

    model = providers_mod.detect_ollama_model()
    if model:
        console.print(f"[dim]Using local Ollama model '{model}' for the AI summary (nothing leaves your machine).[/dim]")
        text = providers_mod.call_ollama(model, payload)
        if text:
            return text, template_summary
        console.print("[yellow]Local model call failed; falling back to the built-in template summary.[/yellow]")
        return None, template_summary

    byo = providers_mod.available_byo_provider()
    if byo:
        provider, api_key = byo
        if provider != "anthropic":
            console.print(
                f"[yellow]{provider.title()} key found, but that provider isn't wired up yet in this release. "
                "Falling back to the built-in template summary.[/yellow]"
            )
            return None, template_summary

        config = load_config()
        if provider not in config.get("consented_providers", []):
            console.print("\n[bold]Cloud AI summary[/bold]")
            console.print(f"An {provider.title()} API key was found. Exactly this redacted JSON would be sent:\n")
            console.print(json.dumps(payload, indent=2)[:4000])
            if not typer.confirm(f"\nSend this to {provider.title()} for a plain-language summary?", default=False):
                console.print("[dim]Skipping cloud summary; using the built-in template summary instead.[/dim]")
                return None, template_summary
            mark_consented(provider)

        text = providers_mod.call_anthropic(api_key, payload)
        if text:
            return text, template_summary
        console.print("[yellow]Cloud call failed; falling back to the built-in template summary.[/yellow]")
        return None, template_summary

    console.print("[dim]No local model or API key found; using the built-in template summary (--no-ai to skip this check).[/dim]")
    return None, template_summary


def _write_reports(scan, ai_summary_markdown, template_summary) -> Path:
    timestamp = scan.started_at.strftime("%Y%m%dT%H%M%S")
    out_dir = REPORTS_DIR / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "report.html").write_text(render_html(scan, ai_summary_markdown, template_summary), encoding="utf-8")
    (out_dir / "report.json").write_text(render_json(scan, ai_summary_markdown, template_summary), encoding="utf-8")
    (out_dir / "summary.md").write_text(render_markdown(scan, ai_summary_markdown, template_summary), encoding="utf-8")
    return out_dir


def _print_terminal_summary(scan) -> None:
    console.print(f"\n[bold]Exposure level: {scan.exposure_level}[/bold]")
    counts: dict[str, int] = {}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count")
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            table.add_row(sev.upper(), str(counts[sev]))
    console.print(table)

    if scan.findings:
        console.print("\n[bold]Top findings:[/bold]")
        for f in sorted(scan.findings, key=lambda x: x.severity, reverse=True)[:3]:
            console.print(f"  [{f.severity.upper()}] {f.title} — {f.subject}")


@app.command()
def scan(
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip any AI summary; use the deterministic template summary."),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON to stdout instead of a human summary."),
    extra_root: list[str] = typer.Option([], "--project-root", help="Additional project directory to scan for configs (repeatable)."),
    open_report: bool = typer.Option(True, help="Open the HTML report when done."),
):
    """Discover AI apps, MCP servers, permissions and secrets; score risk; write a report."""
    if json_out:
        result = run_scan(extra_root or None)
        ai_summary_markdown, template_summary = (None, build_template_summary(result)) if no_ai else _resolve_ai_summary(result, no_ai)
        print(render_json(result, ai_summary_markdown, template_summary))
        return

    with console.status("[bold]Scanning your AI tools...[/bold]"):
        result = run_scan(extra_root or None)
    ai_summary_markdown, template_summary = _resolve_ai_summary(result, no_ai)
    out_dir = _write_reports(result, ai_summary_markdown, template_summary)

    _print_terminal_summary(result)
    console.print(f"\nReport written to [bold]{out_dir / 'report.html'}[/bold]")

    if open_report:
        webbrowser.open(f"file://{out_dir / 'report.html'}")


@app.command()
def report():
    """Re-open the most recent report."""
    latest = _latest_report_dir()
    if not latest:
        console.print("[yellow]No report found yet. Run 'glasswing scan' first.[/yellow]")
        raise typer.Exit(1)
    webbrowser.open(f"file://{latest / 'report.html'}")
    console.print(f"Opened {latest / 'report.html'}")


@app.command()
def history(
    since: str = typer.Option("7d", help="Lookback window, e.g. 7d, 30d."),
    app_filter: Optional[str] = typer.Option(None, "--app", help="Filter to one app id."),
):
    """Timeline of AI tool activity found in local logs. (Coming in a later release.)"""
    console.print(
        "[yellow]Activity-log parsing (Claude Code transcripts, Claude Desktop MCP logs) isn't in this release yet.[/yellow]\n"
        "Phase 1 covers inventory + risk scoring; 'history' ships in Phase 2. See the project README for the roadmap."
    )


track_app = typer.Typer(help="Live MCP call logging via a local proxy. (Coming in a later release.)")
app.add_typer(track_app, name="track")


@track_app.command("enable")
def track_enable():
    console.print("[yellow]Live tracking (the MCP logging proxy) isn't in this release yet -- it ships in Phase 3.[/yellow]")


@track_app.command("disable")
def track_disable():
    console.print("[yellow]Live tracking isn't in this release yet -- nothing to disable.[/yellow]")


@track_app.command("status")
def track_status():
    console.print("[yellow]Live tracking isn't in this release yet.[/yellow]")


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Print the current config."),
    set_provider: Optional[str] = typer.Option(None, "--ai-provider", help="ollama | anthropic | openai | gemini | none"),
):
    """View or change settings (AI summary provider, project roots, etc.) stored in ~/.glasswing/config.json."""
    cfg = load_config()
    if set_provider is not None:
        cfg["ai_provider"] = None if set_provider.lower() == "none" else set_provider.lower()
        save_config(cfg)
        console.print(f"Saved ai_provider = {cfg['ai_provider']}")
        return
    console.print(f"Config file: {CONFIG_PATH}")
    console.print(json.dumps(cfg, indent=2))


@app.command()
def version():
    """Print the glasswing version."""
    console.print(__version__)


def _version_callback(value: bool):
    if value:
        console.print(__version__)
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    show_version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True, help="Print the version and exit."),
):
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


if __name__ == "__main__":
    app()
