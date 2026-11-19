"""Rule-based, transparent risk scoring. Each finding carries the rule id
from registry/rules.yaml. Findings are grouped so one problem is one row,
however many times it repeats.
"""
from __future__ import annotations

import re

from glasswing.analysis.models import AppInventory, Finding, McpServer, PermissionRule
from glasswing.discovery.paths import classify_scope
from glasswing.discovery.registry import load_rules
from glasswing.parsers.secrets import redact_text, redact_url, safe_command_line

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_BY_RANK = {0: "Low", 1: "Low", 2: "Moderate", 3: "High", 4: "Critical"}

_SCOPE_WORDS = {
    "disk": "your entire disk",
    "all-users": "every user's home folder",
    "home": "your entire home folder",
    "credential-folder": "a credentials folder",
    "personal-folder": "an entire personal folder",
}
_INTERPRETERS = r"(?:sudo|su|doas|bash|sh|zsh|fish|pwsh|powershell|cmd|python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php|osascript|eval|exec|env|xargs|npx|uvx|pipx|docker|ssh)"
_NETWORK_TOOLS = r"(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp)"
_DESTRUCTIVE = r"(?:rm|rmdir|dd|mkfs|shred|chmod|chown)"
_ANY_ARGS = r"(?::\*|\s+\*|\*)\)$"  # "python:*)", "python *)", "python*)"


def rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)


def _f(rule_id: str, subject: str, detail: str | None = None) -> Finding:
    meta = load_rules()[rule_id]
    return Finding(
        rule_id=rule_id, severity=meta["severity"], title=meta["title"],
        explanation=" ".join(meta["explanation"].split()), fix=" ".join(meta["fix"].split()),
        subject=redact_text(subject), details=[detail] if detail else [],
    )


def _check_server(s: McpServer) -> list[Finding]:
    """Findings are filed under the app; each detail line names the server and file."""
    raw: list[Finding] = []
    out = _ServerFindings(raw, s)
    subject = s.app_name

    if s.scope_level in ("disk", "all-users", "home"):
        out.append(_f("FS-ROOT-SCOPE", subject, f"covers {_SCOPE_WORDS[s.scope_level]}: {', '.join(s.scope_paths)}"))
    elif s.scope_level == "credential-folder":
        out.append(_f("FS-CREDENTIAL-FOLDER", subject, ", ".join(s.scope_paths)))
    elif s.scope_level == "personal-folder":
        out.append(_f("FS-PERSONAL-FOLDER", subject, ", ".join(s.scope_paths)))

    if s.package and s.pinned is False:
        rule = "MCP-UNPINNED-RECOGNISED" if s.trust == "recognised-package" or s.via_mcp_remote else "MCP-UNPINNED-UNRECOGNISED"
        out.append(_f(rule, subject, f"package {s.package}, launched with: {safe_command_line(s.command, s.args)}"))

    if s.url and s.trust != "local-service":
        if s.url.lower().startswith("http://"):
            out.append(_f("MCP-REMOTE-INSECURE-HTTP", subject, redact_url(s.url)))
        if s.trust == "unrecognised-service":
            out.append(_f("MCP-REMOTE-UNRECOGNISED", subject, f"domain {s.remote_host} ({redact_url(s.url)})"))

    if s.auto_trusted:
        out.append(_f("MCP-SERVER-TRUST-BYPASS", subject, '"trust": true'))

    for secret in s.secrets:
        rule = {"url": "SECRET-IN-URL", "possible": "SECRET-POSSIBLE"}.get(secret.confidence, "SECRET-PLAINTEXT-CONFIG")
        out.append(_f(rule, subject, f"{secret.pattern_name} ({secret.key_hint.split(', ', 1)[-1]}): {secret.masked_value}"))
    return raw


class _ServerFindings:
    """Prefixes each detail with the server name and suffixes the config file."""

    def __init__(self, sink: list[Finding], server: McpServer):
        self.sink, self.server = sink, server

    def append(self, finding: Finding) -> None:
        s = self.server
        extra = f" (+{len(s.also_defined_in)} more files)" if s.also_defined_in else ""
        body = f": {finding.details[0]}" if finding.details else ""
        finding.details = [redact_text(f"server '{s.name}'{body} — in {s.config_path}{extra}")]
        self.sink.append(finding)


def _path_scope(pattern: str) -> str | None:
    """Scope of a Claude Code Read/Edit path pattern (gitignore-style)."""
    p = pattern.strip()
    if p in ("", "*", "**", "/**", "**/*"):
        return None  # relative to the project / settings folder: not machine-wide
    if p.startswith("//"):
        p = p[1:]
    elif not p.startswith("~"):
        return None  # "/x" and "x" are relative to the project or settings file
    base = re.sub(r"/?[*?\[].*$", "", p) or "/"  # the fixed folder before any wildcard
    return classify_scope(base)


def classify_permission(rule: str) -> tuple[str, str] | None:
    """-> (rule_id, reason) for a risky 'allow' rule, else None."""
    r = rule.strip()
    if r in ("Bash", "*") or re.fullmatch(r"Bash\(\s*(?:\*|:\*|\*:\*|\*\*)\s*\)", r):
        return "SHELL-BLANKET-ALLOW", r
    m = re.fullmatch(r"(Edit|Write|MultiEdit|NotebookEdit|Read)(?:\((.*)\))?", r, re.S)
    if m:
        tool, pattern = m.group(1), m.group(2)
        if pattern is None:
            return None  # a bare tool name: the docs don't define its reach, so Glasswing doesn't claim one
        level = _path_scope(pattern)
        if tool == "Read":
            return ("PERMISSIONS-BROAD-READ", r) if level else None
        return ("PERMISSIONS-BROAD-WRITE", r) if level in ("disk", "all-users", "home") else None
    if r.startswith("Bash("):
        body = r[5:]
        if re.match(_INTERPRETERS + _ANY_ARGS, body):
            return "SHELL-INTERPRETER-WILDCARD", r
        if re.match(_NETWORK_TOOLS + _ANY_ARGS, body):
            return "SHELL-NETWORK-WILDCARD", r
        if re.match(_DESTRUCTIVE + _ANY_ARGS, body):
            return "SHELL-DESTRUCTIVE-WILDCARD", r
    return None


def _check_permissions(app: AppInventory) -> list[Finding]:
    out: list[Finding] = []
    by_file: dict[str, list[PermissionRule]] = {}
    for p in app.permissions:
        by_file.setdefault(p.config_path, []).append(p)
    for path, rules in by_file.items():
        shell_denied = any(p.kind == "deny" and classify_permission(p.rule) and classify_permission(p.rule)[0] == "SHELL-BLANKET-ALLOW" for p in rules)
        for p in rules:
            if p.kind != "allow":
                continue
            hit = classify_permission(p.rule)
            if not hit:
                continue
            if shell_denied and hit[0].startswith("SHELL-"):
                continue  # deny beats allow, so the rule has no effect
            out.append(_f(hit[0], app.app_name, redact_text(f"{p.rule} — in {path}")))
    return out


def _check_exfil(app: AppInventory) -> list[Finding]:
    broad = [s for s in app.servers if s.capability == "filesystem" and s.scope_level]
    outward = [s for s in app.servers if s.capability in ("network", "browser") or (s.url and s.trust != "local-service")]
    if broad and outward:
        return [_f("EXFIL-PATH", app.app_name, f"file access: {broad[0].name}; reaches the internet: {', '.join(sorted({s.name for s in outward})[:5])}")]
    return []


def group(findings: list[Finding]) -> list[Finding]:
    """One row per (rule, subject); repeats become a count plus a few examples."""
    merged: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.subject)
        if key in merged:
            g = merged[key]
            g.count += 1
            for d in f.details:
                if d not in g.details:
                    g.details.append(d)
        else:
            merged[key] = f
    out = list(merged.values())
    out.sort(key=lambda f: (-rank(f.severity), f.rule_id, f.subject))
    return out


def evaluate(apps: list[AppInventory]) -> list[Finding]:
    findings: list[Finding] = []
    for app in apps:
        if not app.found:
            continue
        for server in app.servers:
            findings.extend(_check_server(server))
        findings.extend(_check_permissions(app))
        findings.extend(_check_exfil(app))
        for flag in app.flags:
            findings.append(_f(flag.rule_id, app.app_name, redact_text(f"{flag.detail} — in {flag.config_path}")))
        for secret in app.secrets:
            findings.append(_f("SECRET-PLAINTEXT-CONFIG", app.app_name, redact_text(f"{secret.pattern_name} ({secret.key_hint}): {secret.masked_value} — in {secret.source_path}")))
    return group(findings)


def compute_exposure_level(findings: list[Finding]) -> str:
    """The level is simply the most serious finding present. It is never raised
    by sheer count: 'Critical' always means a critical finding exists."""
    if not findings:
        return "Low"
    return LEVEL_BY_RANK[max(rank(f.severity) for f in findings)]
