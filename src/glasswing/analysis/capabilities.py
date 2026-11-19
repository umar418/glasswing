"""Infer what an MCP server can actually do: capability class, filesystem
scope, and publisher trust -- from its command/args/package name plus the
known-server table in registry/servers.yaml.
"""
from __future__ import annotations

import re
from pathlib import Path

from glasswing.analysis.models import McpServer
from glasswing.discovery.registry import load_servers_table

ROOT_LIKE = {"/", "\\", "C:\\", "C:/"}

FILESYSTEM_HINTS = ["filesystem", "fs-server", "file-server", "@modelcontextprotocol/server-filesystem"]
SHELL_HINTS = ["shell", "bash", "exec", "command", "terminal", "run-command"]
BROWSER_HINTS = ["puppeteer", "playwright", "browser", "selenium"]
NETWORK_HINTS = ["fetch", "http", "curl", "search", "brave-search", "web-search"]
EMAIL_HINTS = ["gmail", "outlook", "slack", "mail", "imap", "smtp"]
CALENDAR_HINTS = ["calendar", "gcal"]
DRIVE_HINTS = ["gdrive", "drive", "dropbox", "onedrive", "sharepoint"]
CRM_HINTS = ["hubspot", "salesforce", "crm"]
DATABASE_HINTS = ["postgres", "mysql", "sqlite", "mongodb", "database", "redis"]
PAYMENTS_HINTS = ["stripe", "paypal", "payment", "billing"]
CLOUD_HINTS = ["aws", "gcp", "azure", "kubernetes", "terraform", "github", "gitlab", "vercel"]

HINT_TABLE = [
    (FILESYSTEM_HINTS, "filesystem"),
    (SHELL_HINTS, "shell"),
    (BROWSER_HINTS, "browser"),
    (EMAIL_HINTS, "email_or_chat"),
    (CALENDAR_HINTS, "calendar"),
    (DRIVE_HINTS, "drive"),
    (CRM_HINTS, "crm"),
    (DATABASE_HINTS, "database"),
    (PAYMENTS_HINTS, "payments"),
    (CLOUD_HINTS, "cloud_infra"),
    (NETWORK_HINTS, "network"),
]

KNOWN_VENDOR_DOMAINS = {
    "anthropic.com",
    "modelcontextprotocol.io",
    "github.com",
    "githubusercontent.com",
    "openai.com",
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "slack.com",
    "stripe.com",
}


def _server_identity_text(server: McpServer) -> str:
    parts = [server.name or "", server.command or "", " ".join(server.args), server.url or ""]
    return " ".join(parts).lower()


def infer_capability(server: McpServer) -> str:
    text = _server_identity_text(server)
    for row in load_servers_table():
        if row["match"].lower() in text:
            return row["capability"]
    for hints, capability in HINT_TABLE:
        if any(h in text for h in hints):
            return capability
    return "other" if (server.command or server.url) else "unknown"


def infer_trust(server: McpServer) -> str:
    text = _server_identity_text(server)
    for row in load_servers_table():
        if row["match"].lower() in text:
            return row["trust"]

    command = (server.command or "").lower()
    args_joined = " ".join(server.args).lower()

    if command in {"node", "python", "python3"} and any(a.startswith(("./", "/", "~")) for a in server.args):
        return "local-script"

    if command in {"npx"} and "-y" in server.args:
        return "unpinned-unknown" if "@" not in args_joined.split(" ")[-1] else "unpinned-unknown"
    if command in {"uvx"}:
        return "unpinned-unknown"

    if server.url:
        domain_match = re.search(r"https?://([^/]+)/?", server.url)
        if domain_match:
            domain = domain_match.group(1).split(":")[0]
            if any(domain == d or domain.endswith("." + d) for d in KNOWN_VENDOR_DOMAINS):
                return "official"
            return "unknown-domain"
    return "unknown"


def _extract_candidate_paths(server: McpServer) -> list[str]:
    candidates = []
    for arg in server.args:
        if any(sep in arg for sep in ("/", "\\")) or arg in ("~",):
            candidates.append(arg)
    return candidates


def infer_scope(server: McpServer) -> tuple[list[str], bool]:
    if server.capability != "filesystem":
        return [], False
    paths = _extract_candidate_paths(server)
    root_like = False
    home = str(Path.home())
    for p in paths:
        expanded = p.replace("~", home)
        if expanded.rstrip("/\\") in {"", "/", home} or re.fullmatch(r"[A-Za-z]:\\?", expanded):
            root_like = True
    return paths, root_like


def analyze_server(server: McpServer) -> McpServer:
    server.capability = infer_capability(server)
    server.trust = infer_trust(server)
    scope_paths, root_like = infer_scope(server)
    server.scope_paths = scope_paths
    server.scope_is_root_or_home = root_like
    return server
