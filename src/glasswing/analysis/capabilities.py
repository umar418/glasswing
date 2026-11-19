"""Work out what each MCP server is: how it is launched, whether its version
is fixed, what it can reach, and how much of that Glasswing actually knows
versus is guessing. Every guess is labelled as one.
"""
from __future__ import annotations

import os
import re

from glasswing.analysis.models import McpServer
from glasswing.discovery.paths import classify_scope
from glasswing.discovery.registry import load_known
from glasswing.parsers.secrets import url_host

_NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--cache", "--registry", "--prefix", "-w", "--workspace"}
_UVX_VALUE_FLAGS = {"--from", "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url", "--with-editable", "--with-requirements", "-c", "--constraint", "--directory"}
_DOCKER_VALUE_FLAGS = {
    "-v", "--volume", "--mount", "-e", "--env", "--env-file", "--name", "-p", "--publish", "--network", "--net",
    "-w", "--workdir", "-u", "--user", "--entrypoint", "-l", "--label", "--platform", "--add-host", "-h", "--hostname",
    "--memory", "-m", "--cpus", "--pull", "--restart", "--security-opt", "--cap-add", "--cap-drop",
}
_INTERPRETERS = {"node", "nodejs", "python", "python3", "deno", "bun", "ruby", "php", "java", "dotnet", "bash", "sh", "zsh", "pwsh", "powershell", "cmd"}
_SCOPE_RANK = {"disk": 5, "all-users": 4, "home": 3, "credential-folder": 2, "personal-folder": 1}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


def _base(command: str) -> str:
    name = os.path.basename(command.replace("\\", "/")).lower()
    return re.sub(r"\.(exe|cmd|bat|ps1)$", "", name)


def _first_positional(args: list[str], value_flags: set[str]) -> tuple[str | None, int]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            continue
        if a.startswith("-"):
            i += 2 if (a in value_flags and "=" not in a) else 1
            continue
        return a, i
    return None, len(args)


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        name, _, version = spec[1:].partition("@")
        return "@" + name, version or None
    name, _, version = spec.partition("@")
    return name, version or None


def _exact_version(version: str | None) -> bool:
    return bool(version) and bool(re.fullmatch(r"v?\d+\.\d+(\.\d+)?([-+.][0-9A-Za-z.-]+)?", version))


def parse_launcher(command: str, args: list[str]) -> dict:
    """-> {runner, package, pinned, rest (args after the package), mounts}"""
    base = _base(command)
    info = {"runner": "local", "package": None, "pinned": None, "rest": list(args), "mounts": []}

    if base in ("npm", "pnpm", "yarn", "bun") and args and args[0] in ("exec", "dlx", "x"):
        base, args = "npx", args[1:]
    if base == "uv" and args[:2] == ["tool", "run"]:
        base, args = "uvx", args[2:]
    if base == "pipx" and args[:1] == ["run"]:
        base, args = "pipx", args[1:]

    if base in ("npx", "bunx", "pnpx"):
        info["runner"] = "npx"
        for flag in ("-p", "--package"):  # "npx -p pkg cmd": the package is the flag's value
            if flag in args[:-1]:
                spec, idx = args[args.index(flag) + 1], len(args) - 1
                break
        else:
            spec, idx = _first_positional(args, _NPX_VALUE_FLAGS)
        if spec:
            if re.match(r"^(\.{0,2}/|~|[A-Za-z]:[\\/])", spec):
                info.update(runner="local", rest=args[idx + 1:])
            else:
                name, version = _split_npm_spec(spec)
                info.update(package=name, pinned=_exact_version(version), rest=args[idx + 1:])
    elif base in ("uvx", "pipx"):
        info["runner"] = base
        spec, idx = _first_positional(args, _UVX_VALUE_FLAGS)
        if "--from" in args[:-1]:
            spec = args[args.index("--from") + 1]
        if spec:
            if spec.startswith(("git+", "http://", "https://")):
                tail = spec.split("://", 1)[-1]
                info.update(package=spec.split("@")[0], pinned="@" in tail.split("/", 1)[-1])
            elif re.match(r"^(\.{0,2}/|~|[A-Za-z]:[\\/])", spec):
                info.update(runner="local")
            else:
                m = re.match(r"^([A-Za-z0-9_.\[\],-]+?)(?:(==|@)(.+))?$", spec)
                name = re.sub(r"\[.*\]$", "", m.group(1)) if m else spec
                info.update(package=name, pinned=bool(m and m.group(3) and _exact_version(m.group(3))))
            info["rest"] = args[idx + 1:]
    elif base in ("docker", "podman"):
        info["runner"] = "docker"
        if "run" in args:
            rest = args[args.index("run") + 1:]
            mounts, i = [], 0
            while i < len(rest):
                a = rest[i]
                val = None
                if a in ("-v", "--volume", "--mount") and i + 1 < len(rest):
                    val = rest[i + 1]
                elif a.startswith(("--volume=", "--mount=")):
                    val = a.split("=", 1)[1]
                elif a.startswith("-v") and len(a) > 2:
                    val = a[2:]
                if val:
                    if "source=" in val or "src=" in val:
                        m = re.search(r"(?:source|src)=([^,]+)", val)
                        if m and "type=volume" not in val:
                            mounts.append(m.group(1))
                    else:
                        m = re.match(r"^((?:[A-Za-z]:)?[^:]*):", val)
                        if m and re.match(r"^(/|~|\.|\$|%|[A-Za-z]:)", m.group(1)):
                            mounts.append(m.group(1))
                i += 1
            image, idx = _first_positional(rest, _DOCKER_VALUE_FLAGS)
            if image:
                name = image.split("@")[0]
                tag = None
                if ":" in name.rsplit("/", 1)[-1]:
                    name, tag = name.rsplit(":", 1)
                pinned = "@sha256:" in image or (tag is not None and tag != "latest")
                info.update(package=name, pinned=pinned, rest=rest[idx + 1:], mounts=mounts)
    elif base in _INTERPRETERS:
        info["runner"] = "local"
    return info


def _words(*texts: str | None) -> set[str]:
    out: set[str] = set()
    for t in texts:
        if t:
            out.update(w for w in re.split(r"[^a-z0-9]+", t.lower()) if w)
    return out


def _guess_capability(server: McpServer) -> str | None:
    words = _words(server.name, server.package)
    for capability, hints in load_known()["name_hints"].items():
        if words & set(hints):
            return capability
    return None


def _recognised_domain(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in load_known()["domains"])


def analyze_server(server: McpServer) -> McpServer:
    known = load_known()["packages"]
    info = {"runner": None, "package": None, "pinned": None, "rest": [], "mounts": []}
    if server.command:
        info = parse_launcher(server.command, server.args)
    server.runner, server.package, server.pinned = info["runner"], info["package"], info["pinned"]

    # mcp-remote is a local wrapper; the thing actually being talked to is the URL argument.
    if server.package == "mcp-remote":
        target = next((a for a in info["rest"] if re.match(r"^https?://", a, re.I)), None)
        if target:
            server.url, server.via_mcp_remote = target, True

    if server.url:
        host = url_host(server.url) or ""
        server.remote_host = host or None
        if host.lower() in _LOCAL_HOSTS or host.startswith("127."):
            server.trust = "local-service"
        elif host and _recognised_domain(host):
            server.trust = "recognised-service"
        else:
            server.trust = "unrecognised-service"
    elif server.package:
        server.trust = "recognised-package" if server.package in known else "unrecognised-package"
    elif server.command:
        server.trust = "local"

    if server.package in known and known[server.package] != "remote":
        server.capability, server.capability_basis = known[server.package], "recognised package"
    else:
        guess = _guess_capability(server)
        if guess:
            server.capability, server.capability_basis = guess, "guessed from its name"
        elif server.url and server.trust != "local-service":
            server.capability, server.capability_basis = "remote", "online service; Glasswing can't see what it can do"
        elif server.command or server.url:
            server.capability, server.capability_basis = "unknown", "Glasswing can't tell what this server can do"

    if server.capability == "filesystem":
        paths = list(info["mounts"]) if server.runner == "docker" else [a for a in info["rest"] if not a.startswith("-")]
        server.scope_paths = paths
        levels = [lvl for lvl in (classify_scope(p) for p in paths) if lvl]
        if levels:
            server.scope_level = max(levels, key=lambda lvl: _SCOPE_RANK[lvl])
    elif info["mounts"]:  # any container that bind-mounts a broad host folder has that access
        levels = [lvl for lvl in (classify_scope(p) for p in info["mounts"]) if lvl]
        if levels:
            server.scope_paths = list(info["mounts"])
            server.scope_level = max(levels, key=lambda lvl: _SCOPE_RANK[lvl])
    return server
