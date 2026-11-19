"""The AI summary is optional, consent-gated, and can never see or leak a secret."""
import json

import pytest
from typer.testing import CliRunner

from conftest import ANTHROPIC_KEY
from glasswing.cli import app
from glasswing.summary import providers


@pytest.fixture
def machine(home):
    home.cursor({"notes": {"command": "node", "args": ["s.js"], "env": {"API_KEY": ANTHROPIC_KEY}}})
    return home


def _report(home) -> str:
    folder = next((home.root / ".glasswing" / "reports").iterdir())
    return (folder / "report.html").read_text(encoding="utf-8")


def test_local_model_is_used_and_gets_only_redacted_data(machine, monkeypatch):
    sent = {}
    monkeypatch.setattr(providers, "detect_ollama_model", lambda: "test-model")
    monkeypatch.setattr(providers, "call_ollama", lambda model, payload: sent.update(p=payload) or "## Overall exposure\nHigh because of **one** key.")
    assert CliRunner().invoke(app, ["scan", "--no-open-report"]).exit_code == 0
    assert ANTHROPIC_KEY not in json.dumps(sent["p"]) and str(machine.root) not in json.dumps(sent["p"])
    assert "<strong>one</strong>" in _report(machine) and "AI-written summary" in _report(machine)


def test_model_output_that_repeats_a_secret_or_adds_html_is_neutralised(machine, monkeypatch):
    monkeypatch.setattr(providers, "detect_ollama_model", lambda: "test-model")
    monkeypatch.setattr(providers, "call_ollama", lambda m, p: f"Your key is {ANTHROPIC_KEY} <script>alert(1)</script>")
    CliRunner().invoke(app, ["scan", "--no-open-report"])
    html = _report(machine)
    assert ANTHROPIC_KEY not in html and "<script>alert(1)" not in html


def test_no_ai_flag_never_touches_any_provider(machine, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("provider contacted despite --no-ai")

    for name in ("detect_ollama_model", "call_ollama", "call_anthropic"):
        monkeypatch.setattr(providers, name, boom)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "set")
    assert CliRunner().invoke(app, ["scan", "--no-ai", "--no-open-report"]).exit_code == 0


def test_cloud_key_is_never_used_without_recorded_consent(machine, monkeypatch):
    monkeypatch.setattr(providers, "detect_ollama_model", lambda: None)
    monkeypatch.setattr(providers, "call_anthropic", lambda *a: (_ for _ in ()).throw(AssertionError("sent without consent")))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "set")
    assert CliRunner().invoke(app, ["scan", "--no-open-report"]).exit_code == 0  # not a terminal: must not send
    assert CliRunner().invoke(app, ["scan", "--no-open-report"], input="n\n").exit_code == 0


def test_cloud_call_happens_after_consent_and_provider_none_disables_ai(machine, monkeypatch):
    calls = []
    monkeypatch.setattr(providers, "detect_ollama_model", lambda: None)
    monkeypatch.setattr(providers, "call_anthropic", lambda key, payload: calls.append(payload) or "## Overall exposure\nok")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "set")
    machine.write(".glasswing/config.json", {"consented_providers": ["anthropic"]})
    CliRunner().invoke(app, ["scan", "--no-open-report"])
    assert len(calls) == 1 and ANTHROPIC_KEY not in json.dumps(calls[0])
    assert CliRunner().invoke(app, ["config", "--ai-provider", "none"]).exit_code == 0
    CliRunner().invoke(app, ["scan", "--no-open-report"])
    assert len(calls) == 1


def test_failed_model_call_falls_back_to_built_in_summary(machine, monkeypatch):
    monkeypatch.setattr(providers, "detect_ollama_model", lambda: "m")
    monkeypatch.setattr(providers, "call_ollama", lambda m, p: None)
    assert CliRunner().invoke(app, ["scan", "--no-open-report"]).exit_code == 0
    assert "Fix these first" in _report(machine)
