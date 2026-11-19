"""Rule-based, transparent risk scoring. Every finding carries the rule id
from registry/rules.yaml so a user can look it up.
"""
from __future__ import annotations

from glasswing.analysis.models import AppInventory, Finding, McpServer
from glasswing.discovery.registry import load_rules
from glasswing.parsers.secrets import redact_url_path_ids, safe_command_line

SENSITIVE_PATH_KEYWORDS = [
    "medical", "health", "patient", "hipaa", "legal", "client", "case",
    "contract", "tax", "payroll", "bank", "statement", "invoice",
    "passport", "ssn", "password", ".env", "secrets", ".ssh", ".aws",
    "keychain", "wallet",
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_BY_RANK = {0: "Low", 1: "Low", 2: "Moderate", 3: "High", 4: "Critical"}


def _finding(rule_id: str, subject: str, detail: str | None = None) -> Finding:
    meta = load_rules()[rule_id]
    return Finding(
        rule_id=rule_id,
        severity=meta["severity"],
        title=meta["title"],
        explanation=meta["explanation"].strip(),
        fix=meta["fix"].strip(),
        subject=subject,
        detail=detail,
    )


def _path_is_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(kw in lowered for kw in SENSITIVE_PATH_KEYWORDS)


def _check_server(server: McpServer) -> list[Finding]:
    findings: list[Finding] = []
    subject = f"{server.app_name} → {server.name}"

    if server.capability == "filesystem" and server.scope_is_root_or_home:
        findings.append(_finding("FS-ROOT-SCOPE", subject, detail=", ".join(server.scope_paths) or None))

    if server.trust == "unpinned-unknown":
        findings.append(
            _finding("MCP-UNPINNED-UNKNOWN-PUBLISHER", subject, detail=f"command: {safe_command_line(server.command, server.args)}")
        )

    if server.trust == "unknown-domain":
        findings.append(_finding("MCP-REMOTE-UNKNOWN-DOMAIN", subject, detail=redact_url_path_ids(server.url) if server.url else None))

    for secret in server.secrets:
        findings.append(_finding("SECRET-PLAINTEXT-CONFIG", subject, detail=f"{secret.pattern_name}: {secret.masked_value}"))

    return findings


def _check_permissions(app: AppInventory) -> list[Finding]:
    findings: list[Finding] = []
    for rule in app.permissions:
        if rule.kind != "allow" or not rule.broad:
            continue
        subject = f"{app.app_name} ({rule.config_path})"
        lowered = rule.rule.lower()
        if "bash" in lowered or lowered.strip() in {"*"} or "bypasspermissions" in lowered:
            findings.append(_finding("SHELL-BLANKET-ALLOW", subject, detail=rule.rule))
        elif "write" in lowered:
            findings.append(_finding("PERMISSIONS-BROAD-WRITE", subject, detail=rule.rule))
    return findings


def _check_exfil_combo(app: AppInventory) -> list[Finding]:
    findings: list[Finding] = []
    has_sensitive_fs = any(
        s.capability == "filesystem" and (s.scope_is_root_or_home or any(_path_is_sensitive(p) for p in s.scope_paths))
        for s in app.servers
    )
    has_network = any(s.capability in {"network", "browser"} for s in app.servers)
    if has_sensitive_fs and has_network:
        findings.append(_finding("EXFIL-PATH-READ-AND-NETWORK", app.app_name))
    return findings


def _check_app_secrets(app: AppInventory) -> list[Finding]:
    return [
        _finding("SECRET-PLAINTEXT-CONFIG", f"{app.app_name} ({secret.source_path})", detail=f"{secret.pattern_name}: {secret.masked_value}")
        for secret in app.secrets
    ]


def evaluate(apps: list[AppInventory]) -> list[Finding]:
    findings: list[Finding] = []
    for app in apps:
        if not app.found:
            continue
        for server in app.servers:
            findings.extend(_check_server(server))
        findings.extend(_check_permissions(app))
        findings.extend(_check_exfil_combo(app))
        findings.extend(_check_app_secrets(app))
    return findings


def compute_exposure_level(findings: list[Finding]) -> str:
    if not findings:
        return "Low"
    max_rank = max(SEVERITY_RANK[f.severity] for f in findings)
    high_or_above = sum(1 for f in findings if SEVERITY_RANK[f.severity] >= 3)
    if high_or_above >= 3 and max_rank < SEVERITY_RANK["critical"]:
        max_rank = min(max_rank + 1, SEVERITY_RANK["critical"])
    return LEVEL_BY_RANK[max_rank]
