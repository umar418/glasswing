"""Builds the safe, shareable view of a scan: nothing here should ever
contain a raw secret value, even if the live McpServer object (in memory,
never serialized directly) still holds one in `env` or `raw`.
"""
from __future__ import annotations

from glasswing.analysis.models import AppInventory, McpServer, ScanResult
from glasswing.parsers.secrets import redact_url_path_ids, safe_arg as _safe_arg, scan_text


def _safe_url(url: str | None) -> str | None:
    if not url:
        return url
    if scan_text(url, source_path="<url>"):
        return "<redacted: looks like a secret>"
    return redact_url_path_ids(url)


def safe_server(server: McpServer) -> dict:
    return {
        "name": server.name,
        "app_name": server.app_name,
        "config_path": server.config_path,
        "command": server.command,
        "args": [_safe_arg(a) for a in server.args],
        "url": _safe_url(server.url),
        "transport": server.transport,
        "capability": server.capability,
        "scope_paths": server.scope_paths,
        "scope_is_root_or_home": server.scope_is_root_or_home,
        "trust": server.trust,
        "env_var_names": sorted(server.env.keys()),
        "secret_count": len(server.secrets),
        "secrets": [
            {"pattern": s.pattern_name, "masked_value": s.masked_value, "key_hint": s.key_hint}
            for s in server.secrets
        ],
    }


def safe_app(app: AppInventory) -> dict:
    return {
        "app_id": app.app_id,
        "app_name": app.app_name,
        "found": app.found,
        "config_paths": app.config_paths,
        "servers": [safe_server(s) for s in app.servers],
        "permissions": [
            {"rule": p.rule, "kind": p.kind, "broad": p.broad, "config_path": p.config_path} for p in app.permissions
        ],
        "secrets": [
            {"pattern": s.pattern_name, "masked_value": s.masked_value, "source_path": s.source_path}
            for s in app.secrets
        ],
        "errors": app.errors,
    }


def safe_scan(scan: ScanResult) -> dict:
    return {
        "version": scan.version,
        "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duration_seconds": scan.duration_seconds,
        "os": scan.os_name,
        "exposure_level": scan.exposure_level,
        "apps": [safe_app(a) for a in scan.apps],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "explanation": f.explanation,
                "fix": f.fix,
                "subject": f.subject,
                "detail": f.detail,
            }
            for f in scan.findings
        ],
        "activity": [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "app": e.app,
                "server": e.server,
                "tool": e.tool,
                "action_type": e.action_type,
                "target": e.target,
                "args_summary": e.args_summary,
                "result_status": e.result_status,
                "sensitive_flags": e.sensitive_flags,
            }
            for e in scan.activity
        ],
        "warnings": scan.warnings,
    }
