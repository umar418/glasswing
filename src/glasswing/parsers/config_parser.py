"""Reads AI-app config files (per registry/apps.yaml) into AppInventory objects.

Fail soft, always: a missing, unreadable, oversized, malformed or outright
hostile file produces a "couldn't read X" note and the scan carries on.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from glasswing.analysis.models import AppInventory, McpServer, PermissionRule, SettingFlag
from glasswing.discovery.paths import current_os, expand_path
from glasswing.parsers import secrets as sec

try:
    import tomllib  # Python >= 3.11
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

MAX_CONFIG_BYTES = 5 * 1024 * 1024
MAX_SERVERS_PER_FILE = 2000


class ConfigError(Exception):
    pass


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code-style JSON),
    leaving string contents untouched."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and text[i + 1:i + 2] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and text[i + 1:i + 2] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # drop the trailing comma
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


def load_config_file(path: Path, fmt: str) -> tuple[Any, bytes]:
    try:
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigError(f"file is too large to be a config ({size // 1024 // 1024} MB); skipped")
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"could not be opened ({exc.__class__.__name__})") from exc
    try:
        text = _decode(data)
    except UnicodeError as exc:
        raise ConfigError("is not a text file") from exc
    if not text.strip():
        return {}, data
    try:
        if fmt == "json":
            try:
                return json.loads(text), data
            except json.JSONDecodeError:
                return json.loads(strip_jsonc(text)), data
        if fmt == "yaml":
            return yaml.safe_load(text), data
        if fmt == "toml":
            return tomllib.loads(text), data
    except RecursionError as exc:
        raise ConfigError("is nested too deeply to read") from exc
    except Exception as exc:
        raise ConfigError(f"is not valid {fmt.upper()}") from exc
    raise ConfigError(f"unsupported format {fmt}")


# ---------------------------------------------------------------- servers


def _s(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _str_list(value: Any, notes: list[str], what: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        notes.append(f"{what} is a single string, not a list")
        return [value]
    if not isinstance(value, list):
        notes.append(f"{what} has an unexpected type and was ignored")
        return []
    out = []
    for item in value:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            out.append(str(item))
        else:
            notes.append(f"{what} contains a non-text item that was ignored")
    return out


def _str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def build_server(name: str, raw: dict, app: dict, config_path: str) -> McpServer:
    notes: list[str] = []
    if isinstance(raw.get("transport"), dict):  # Continue's legacy config.json nests the definition
        raw = {**raw, **raw["transport"]}
    command = raw.get("command")
    args = _str_list(raw.get("args"), notes, "'args'")
    if isinstance(command, list):
        parts = _str_list(command, notes, "'command'")
        command, args = (parts[0] if parts else None), parts[1:] + args
    command = _s(command)
    url = _s(raw.get("url")) or _s(raw.get("serverUrl")) or _s(raw.get("httpUrl"))
    declared = _s(raw.get("type")) or (_s(raw.get("transport")) if not isinstance(raw.get("transport"), dict) else None)
    if url:
        transport = "sse" if (declared or "").lower() == "sse" else "http"
    else:
        transport = "stdio"
    headers = {**_str_dict(raw.get("headers")), **_str_dict(raw.get("http_headers"))}
    return McpServer(
        name=name, app_id=app["id"], app_name=app["name"], config_path=config_path,
        command=command, args=args, url=url, transport=transport,
        env=_str_dict(raw.get("env")), headers=headers,
        auto_trusted=raw.get("trust") is True, parse_notes=notes,
    )


def _resolve_key(data: Any, dotted: str) -> list[Any]:
    """Follow a dotted path; '*' fans out over every key at that level."""
    current = [data]
    for part in dotted.split("."):
        nxt = []
        for node in current:
            if not isinstance(node, dict):
                continue
            if part == "*":
                nxt.extend(node.values())
            elif part in node:
                nxt.append(node[part])
        current = nxt
    return current


def extract_servers(data: Any, mcp_key: str, app: dict, config_path: str) -> list[McpServer]:
    servers: list[McpServer] = []
    for block in _resolve_key(data, mcp_key):
        if isinstance(block, dict):
            items = [(str(k), v) for k, v in block.items()]
        elif isinstance(block, list):
            items = [(str(v.get("name") or f"server-{i + 1}"), v) for i, v in enumerate(block) if isinstance(v, dict)]
        else:
            continue
        for name, raw in items[:MAX_SERVERS_PER_FILE]:
            if isinstance(raw, dict):
                servers.append(build_server(name, raw, app, config_path))
    return servers


def scan_server_secrets(server: McpServer) -> None:
    src = server.config_path
    where = f"server '{sec.redact_text(server.name)}'"
    found = []
    for k, v in server.env.items():
        found.extend(sec.scan_named_value(k, v, src, f"{where}, env {k}"))
    for k, v in server.headers.items():
        hits = [h for h in sec.scan_named_value(k, v, src, f"{where}, header {k}") if h.confidence != "possible"]
        if not hits and k.lower() in ("cookie", "x-api-key", "x-auth") and not sec.is_placeholder(v):
            hits = [sec._finding("named-credential", f"Value of '{k}'", v, src, f"{where}, header {k}", "named-field")]
        found.extend(hits)
    found.extend(sec.scan_args(server.args, src, f"{where}, command arguments"))
    if server.url:
        found.extend(sec.scan_url(server.url, src, f"{where}, address"))
    server.secrets = sec.dedupe(found)


# ---------------------------------------------------------------- settings


def _claude_code_settings(data: dict, app: dict, path: str, user_level: bool, inv: AppInventory) -> None:
    perms = data.get("permissions")
    if isinstance(perms, dict):
        for kind in ("allow", "ask", "deny"):
            rules = perms.get(kind)
            if isinstance(rules, list):
                for rule in rules:
                    if isinstance(rule, str):
                        inv.permissions.append(PermissionRule(app["id"], app["name"], path, rule, kind, user_level))
        # Per Claude Code docs, project-level files cannot set bypassPermissions; only report where it takes effect.
        if perms.get("defaultMode") == "bypassPermissions" and user_level and perms.get("disableBypassPermissionsMode") != "disable":
            inv.flags.append(SettingFlag("PERMISSION-PROMPTS-BYPASSED", path, 'permissions.defaultMode = "bypassPermissions"'))
        dirs = perms.get("additionalDirectories")
        if isinstance(dirs, list):
            from glasswing.discovery.paths import classify_scope
            for d in dirs:
                if isinstance(d, str) and classify_scope(d) in ("disk", "all-users", "home"):
                    inv.flags.append(SettingFlag("PERMISSIONS-BROAD-DIRECTORIES", path, f"additionalDirectories includes {d}"))
    if data.get("enableAllProjectMcpServers") is True:
        inv.flags.append(SettingFlag("MCP-PROJECT-SERVERS-AUTO-APPROVED", path, "enableAllProjectMcpServers = true"))
    env = data.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            if isinstance(v, str):
                hits = sec.scan_named_value(str(k), v, path, f"settings env {k}")
                inv.secrets.extend(h for h in hits if h.confidence != "possible")


def _codex_settings(data: dict, path: str, inv: AppInventory) -> None:
    if data.get("sandbox_mode") == "danger-full-access":
        if data.get("approval_policy") == "never":
            inv.flags.append(SettingFlag("CODEX-NO-SANDBOX-NO-APPROVAL", path, 'sandbox_mode = "danger-full-access", approval_policy = "never"'))
        else:
            inv.flags.append(SettingFlag("CODEX-SANDBOX-DISABLED", path, 'sandbox_mode = "danger-full-access"'))


# ---------------------------------------------------------------- driver


def parse_app(app: dict, project_dirs: list[Path]) -> AppInventory:
    inv = AppInventory(app_id=app["id"], app_name=app["name"], found=False)
    this_os = current_os()
    loaded: dict[str, tuple[Any, bytes] | None] = {}  # resolved path -> parsed (None = failed)
    seen_work: set[tuple] = set()  # (kind, resolved path): never process one file twice for the same purpose
    seen_content: dict[tuple, str] = {}  # (kind, sha256) -> first path with that content

    for cfg in app.get("configs", []):
        if cfg.get("os", "any") not in ("any", this_os):
            continue
        if cfg.get("project_relative"):
            candidates = [pdir / cfg["path"] for pdir in project_dirs]
        else:
            candidates = [expand_path(cfg["path"])]
        kind = (cfg.get("mcp_key"), cfg.get("settings"))

        for path in candidates:
            try:
                if not path.is_file():
                    continue
                real = str(path.resolve())
            except OSError:
                continue
            if (kind, real) in seen_work:
                continue
            seen_work.add((kind, real))
            shown = str(path)

            if real not in loaded:
                try:
                    loaded[real] = load_config_file(path, cfg["format"])
                except ConfigError as exc:
                    loaded[real] = None
                    inv.errors.append(f"couldn't read {shown}: {exc}")
                if loaded[real] is not None:
                    inv.found = True
                    inv.config_paths.append(shown)
            if loaded[real] is None:
                continue
            data, raw_bytes = loaded[real]

            digest = (kind, hashlib.sha256(raw_bytes).hexdigest())
            if digest in seen_content:  # byte-identical copy (e.g. a git worktree): count it, don't re-report it
                inv.identical_copies.setdefault(seen_content[digest], []).append(shown)
                continue
            seen_content[digest] = shown

            if not isinstance(data, dict):
                if data not in (None, {}, []):
                    inv.errors.append(f"couldn't read {shown}: unexpected structure")
                continue
            try:
                if cfg.get("mcp_key"):
                    for server in extract_servers(data, cfg["mcp_key"], app, shown):
                        scan_server_secrets(server)
                        inv.servers.append(server)
                if cfg.get("settings") == "claude-code":
                    _claude_code_settings(data, app, shown, not cfg.get("project_relative"), inv)
                elif cfg.get("settings") == "codex":
                    _codex_settings(data, shown, inv)
                inv.secrets.extend(sec.scan_whole_file(data, shown))
            except Exception as exc:  # last-resort guard: one odd file must never stop the scan
                inv.errors.append(f"couldn't fully read {shown}: {exc.__class__.__name__}")

    _merge_duplicate_servers(inv)
    server_raw = {s.raw for srv in inv.servers for s in srv.secrets}
    inv.secrets = [s for s in sec.dedupe(inv.secrets) if s.raw not in server_raw]
    return inv


def _merge_duplicate_servers(inv: AppInventory) -> None:
    """The same server defined in several files is one server, listed once."""
    merged: dict[tuple, McpServer] = {}
    for s in inv.servers:
        key = (s.name, s.command, tuple(s.args), s.url, tuple(sorted(s.env.items())), tuple(sorted(s.headers.items())))
        if key in merged:
            merged[key].also_defined_in.append(s.config_path)
        else:
            merged[key] = s
    inv.servers = list(merged.values())
