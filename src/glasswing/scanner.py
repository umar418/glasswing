"""Orchestrates discovery -> capability/trust inference -> rules -> a
finished ScanResult. No AI calls happen in here -- that's the CLI's job,
since it needs to ask for consent before any cloud call.
"""
from __future__ import annotations

import datetime as dt

from glasswing import __version__
from glasswing.analysis.capabilities import analyze_server
from glasswing.analysis.models import ScanResult
from glasswing.analysis.rules import compute_exposure_level, evaluate
from glasswing.discovery import discover_apps
from glasswing.discovery.paths import current_os


def run_scan(extra_roots: list[str] | None = None) -> ScanResult:
    started = dt.datetime.now()
    scan = ScanResult(version=__version__, started_at=started, os_name=current_os())

    apps = discover_apps(extra_roots)
    for app in apps:
        for server in app.servers:
            analyze_server(server)
        scan.warnings.extend(f"{app.app_name}: {err}" for err in app.errors)
    scan.apps = apps

    scan.findings = evaluate(apps)
    scan.exposure_level = compute_exposure_level(scan.findings)
    scan.finished_at = dt.datetime.now()
    return scan
