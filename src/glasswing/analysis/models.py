"""Shared data model for everything a scan collects."""
from __future__ import annotations

import dataclasses
import datetime as dt
from typing import Any, Optional


@dataclasses.dataclass
class SecretFinding:
    pattern_id: str
    pattern_name: str
    source_path: str
    masked_value: str
    key_hint: Optional[str] = None
    # known-format | named-field | url | possible
    confidence: str = "known-format"
    # The real value. Held in memory only so output can be scrubbed; never serialized.
    raw: str = dataclasses.field(default="", repr=False)


@dataclasses.dataclass
class McpServer:
    name: str
    app_id: str
    app_name: str
    config_path: str
    command: Optional[str] = None
    args: list[str] = dataclasses.field(default_factory=list)
    url: Optional[str] = None
    transport: str = "stdio"  # stdio | http | sse
    env: dict[str, str] = dataclasses.field(default_factory=dict)
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    auto_trusted: bool = False  # the app skips confirmation prompts for this server
    also_defined_in: list[str] = dataclasses.field(default_factory=list)
    parse_notes: list[str] = dataclasses.field(default_factory=list)

    # filled in by analysis
    runner: Optional[str] = None  # npx | uvx | docker | local | remote | ...
    package: Optional[str] = None
    pinned: Optional[bool] = None  # None = not applicable / unknown
    via_mcp_remote: bool = False
    remote_host: Optional[str] = None
    capability: str = "unknown"
    capability_basis: str = "unknown"  # recognised package | guessed from name | remote | unknown
    scope_paths: list[str] = dataclasses.field(default_factory=list)
    scope_level: Optional[str] = None  # disk | all-users | home | credential-folder | personal-folder
    trust: str = "unknown"  # recognised-package | unrecognised-package | local | recognised-service | unrecognised-service | local-service
    secrets: list[SecretFinding] = dataclasses.field(default_factory=list)

    @property
    def is_remote(self) -> bool:
        return bool(self.url)


@dataclasses.dataclass
class PermissionRule:
    app_id: str
    app_name: str
    config_path: str
    rule: str
    kind: str = "allow"  # allow | ask | deny
    user_level: bool = False


@dataclasses.dataclass
class SettingFlag:
    """A risky app-level setting (not tied to one MCP server)."""
    rule_id: str
    config_path: str
    detail: str


@dataclasses.dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    explanation: str
    fix: str
    subject: str
    details: list[str] = dataclasses.field(default_factory=list)
    count: int = 1


@dataclasses.dataclass
class AppInventory:
    app_id: str
    app_name: str
    found: bool
    config_paths: list[str] = dataclasses.field(default_factory=list)
    identical_copies: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    servers: list[McpServer] = dataclasses.field(default_factory=list)
    permissions: list[PermissionRule] = dataclasses.field(default_factory=list)
    flags: list[SettingFlag] = dataclasses.field(default_factory=list)
    secrets: list[SecretFinding] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ScanResult:
    version: str
    started_at: dt.datetime
    finished_at: Optional[dt.datetime] = None
    os_name: str = ""
    apps: list[AppInventory] = dataclasses.field(default_factory=list)
    findings: list[Finding] = dataclasses.field(default_factory=list)
    activity: list[Any] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    exposure_level: str = "Low"
    files_read: int = 0

    @property
    def raw_secrets(self) -> set[str]:
        out: set[str] = set()
        for app in self.apps:
            out.update(s.raw for s in app.secrets)
            for server in app.servers:
                out.update(s.raw for s in server.secrets)
        return out

    @property
    def duration_seconds(self) -> float:
        if not self.finished_at:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()
