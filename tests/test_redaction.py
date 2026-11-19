import datetime as dt
from pathlib import Path

from glasswing.analysis.models import AppInventory, Finding, ScanResult
from glasswing.summary.redact import build_redacted_payload, redact_path


def test_redact_path_replaces_home_dir():
    home = str(Path.home())
    result = redact_path(f"{home}/projects/app/file.txt")
    assert home not in result
    assert result.startswith("~/")


def test_redact_path_hashes_filenames_in_sensitive_folders():
    home = str(Path.home())
    result = redact_path(f"{home}/Documents/legal/case-smith-vs-jones.pdf")
    assert "case-smith-vs-jones" not in result
    assert result.endswith(".pdf")
    assert "<redacted-" in result


def test_build_redacted_payload_contains_no_raw_home_paths():
    home = str(Path.home())
    scan = ScanResult(version="0.1.0", started_at=dt.datetime.now(), os_name="macos")
    scan.apps = [AppInventory(app_id="claude-code", app_name="Claude Code", found=True)]
    scan.findings = [
        Finding(
            rule_id="FS-ROOT-SCOPE",
            severity="critical",
            title="t",
            explanation="e",
            fix="f",
            subject=f"Claude Code → fs ({home}/secrets/.env)",
        )
    ]
    payload = build_redacted_payload(scan)
    serialized = str(payload)
    assert home not in serialized
