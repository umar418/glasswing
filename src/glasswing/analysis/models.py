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
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)

    # filled in by analysis
    capability: str = "unknown"
    scope_paths: list[str] = dataclasses.field(default_factory=list)
    scope_is_root_or_home: bool = False
    trust: str = "unknown"  # official | community | unpinned-unknown | local | unknown
    secrets: list[SecretFinding] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PermissionRule:
    app_id: str
    app_name: str
    config_path: str
    rule: str
    kind: str = "unknown"  # allow | deny
    broad: bool = False


@dataclasses.dataclass
class ActivityEvent:
    timestamp: Optional[dt.datetime]
    app: str
    server: Optional[str]
    tool: Optional[str]
    action_type: str  # read | write | exec | network | other
    target: Optional[str]
    args_summary: Optional[str]
    result_status: Optional[str] = None
    sensitive_flags: list[str] = dataclasses.field(default_factory=list)
    session_id: Optional[str] = None


@dataclasses.dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    explanation: str
    fix: str
    subject: str  # human label of what triggered it, e.g. server/app name
    detail: Optional[str] = None


@dataclasses.dataclass
class AppInventory:
    app_id: str
    app_name: str
    found: bool
    config_paths: list[str] = dataclasses.field(default_factory=list)
    servers: list[McpServer] = dataclasses.field(default_factory=list)
    permissions: list[PermissionRule] = dataclasses.field(default_factory=list)
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
    activity: list[ActivityEvent] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    exposure_level: str = "low"

    @property
    def all_servers(self) -> list[McpServer]:
        servers = []
        for app in self.apps:
            servers.extend(app.servers)
        return servers

    @property
    def duration_seconds(self) -> float:
        if not self.finished_at:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()
