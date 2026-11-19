"""The safe, shareable view of a scan. Everything any report shows comes from
here, and every string from a config file passes through redact_text() on
the way out. The live objects (which still hold raw values) are never
serialized directly.
"""
from __future__ import annotations

from glasswing.analysis.models import AppInventory, McpServer, ScanResult
from glasswing.parsers.secrets import redact_text, redact_url, safe_args

CAPABILITY_LABELS = {
    "filesystem": "reads and writes files",
    "shell": "runs commands",
    "browser": "controls a web browser",
    "network": "fetches from the internet",
    "email_or_chat": "email or chat",
    "calendar": "calendar",
    "drive": "cloud documents",
    "crm": "customer records (CRM)",
    "database": "database",
    "payments": "payments or accounting",
    "cloud_infra": "code hosting or cloud infrastructure",
    "remote": "online service",
    "other": "utility (no sensitive access known)",
    "unknown": "unknown",
}
SCOPE_LABELS = {
    "disk": "entire disk",
    "all-users": "all users' folders",
    "home": "entire home folder",
    "credential-folder": "includes a credentials folder",
    "personal-folder": "an entire personal folder",
}


def _source(s: McpServer) -> str:
    if s.url:
        via = " (through the mcp-remote helper)" if s.via_mcp_remote else ""
        kind = {"local-service": "a service on this computer", "recognised-service": "a widely known online service",
                "unrecognised-service": "an online service Glasswing doesn't recognise"}.get(s.trust, "an online service")
        return f"{kind}{via}"
    if s.package:
        known = "widely used package" if s.trust == "recognised-package" else "package Glasswing doesn't recognise"
        version = {True: "fixed version", False: "no fixed version", None: "version unknown"}[s.pinned]
        return f"{known} via {s.runner} ({version})"
    if s.command:
        return "a program or script on this computer"
    return "unknown"


def safe_server(s: McpServer) -> dict:
    return {
        "name": redact_text(s.name),
        "app_name": s.app_name,
        "config_path": redact_text(s.config_path),
        "also_defined_in_count": len(s.also_defined_in),
        "command": redact_text(s.command) if s.command else None,
        "args": safe_args(s.args),
        "url": redact_url(s.url) if s.url else None,
        "remote_host": s.remote_host,
        "transport": s.transport,
        "package": redact_text(s.package) if s.package else None,
        "version_pinned": s.pinned,
        "source": _source(s),
        "capability": s.capability,
        "capability_label": CAPABILITY_LABELS.get(s.capability, s.capability),
        "capability_basis": s.capability_basis,
        "scope_paths": [redact_text(p) for p in s.scope_paths],
        "scope_level": s.scope_level,
        "scope_label": SCOPE_LABELS.get(s.scope_level or "", None),
        "auto_trusted": s.auto_trusted,
        "env_var_names": sorted(redact_text(k) for k in s.env),
        "header_names": sorted(redact_text(k) for k in s.headers),
        "credential_count": len(s.secrets),
        "notes": s.parse_notes,
    }


def safe_app(app: AppInventory) -> dict:
    copies = sum(len(v) for v in app.identical_copies.values())
    by_kind: dict[str, int] = {}
    for p in app.permissions:
        by_kind[p.kind] = by_kind.get(p.kind, 0) + 1
    return {
        "app_id": app.app_id,
        "app_name": app.app_name,
        "found": app.found,
        "config_paths": [redact_text(p) for p in app.config_paths],
        "identical_copy_count": copies,
        "servers": [safe_server(s) for s in app.servers],
        "permission_rule_counts": by_kind,
        "permission_rules": [
            {"rule": redact_text(p.rule), "kind": p.kind, "config_path": redact_text(p.config_path)} for p in app.permissions
        ],
        "errors": [redact_text(e) for e in app.errors],
    }


def safe_scan(scan: ScanResult) -> dict:
    counts: dict[str, int] = {}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "version": scan.version,
        "started_at": scan.started_at.isoformat(timespec="seconds"),
        "duration_seconds": round(scan.duration_seconds, 3),
        "os": scan.os_name,
        "files_read": scan.files_read,
        "exposure_level": scan.exposure_level,
        "severity_counts": counts,
        "apps": [safe_app(a) for a in scan.apps],
        "findings": [
            {
                "rule_id": f.rule_id, "severity": f.severity, "title": f.title,
                "explanation": f.explanation, "fix": f.fix,
                "subject": redact_text(f.subject),
                "details": [redact_text(d) for d in f.details[:8]],
                "more_details": max(0, len(f.details) - 8),
                "count": f.count,
            }
            for f in scan.findings
        ],
        "activity": [],
        "warnings": [redact_text(w) for w in scan.warnings],
        "not_covered": NOT_COVERED,
    }


NOT_COVERED = [
    "Connectors that run on a provider's own servers (for example Gmail or Drive connected inside claude.ai, ChatGPT or Gemini). Use the checklist in this report.",
    "MCP servers bundled inside Claude Code plugins and Claude Desktop extensions.",
    "What your AI tools actually did. This version reads settings only; it does not read activity logs or chat history.",
    "The contents of your files. Glasswing looks at AI tool settings, never at your documents.",
    "Organisation-managed settings pushed by an administrator through device management.",
    "Any AI app that is not listed under 'Apps checked', and project folders outside the locations it searched.",
    "What an online (remote) server can do once connected. Glasswing sees the address, not the service behind it.",
]
