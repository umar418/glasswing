"""Cross-platform path helpers."""
from __future__ import annotations

import os
import platform
import re
from pathlib import Path

SKIP_DIR_NAMES = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", ".next", ".cache", "Library", "AppData"}
DEFAULT_PROJECT_ROOTS = ["~/code", "~/projects", "~/dev", "~/src", "~/Documents", "~/Desktop"]
DEFAULT_PROJECT_SCAN_DEPTH = 3
MAX_PROJECT_DIRS = 20_000

_CREDENTIAL_DIRS = {".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", "keychains"}
_PERSONAL_DIRS = {"documents", "desktop", "downloads", "library", "onedrive", "dropbox", "icloud drive", "google drive", "pictures"}


def current_os() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def home_dir() -> Path:
    return Path(os.path.expanduser("~"))


def expand_path(raw: str) -> Path:
    value = raw
    home = home_dir()
    if "%APPDATA%" in value:
        value = value.replace("%APPDATA%", os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
    if "%LOCALAPPDATA%" in value:
        value = value.replace("%LOCALAPPDATA%", os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
    return Path(os.path.expanduser(value))


def iter_project_roots(extra_roots: list[str] | None = None) -> list[Path]:
    roots = []
    for raw in DEFAULT_PROJECT_ROOTS + (extra_roots or []):
        p = expand_path(raw)
        if p.is_dir():
            roots.append(p)
    return roots


def find_project_dirs(roots: list[Path], max_depth: int = DEFAULT_PROJECT_SCAN_DEPTH) -> list[Path]:
    """Depth- and count-limited walk. Never follows symlinks, so loops cannot trap it."""
    found: list[Path] = []
    queue: list[tuple[Path, int]] = [(r, 0) for r in roots]
    while queue and len(found) < MAX_PROJECT_DIRS:
        current, depth = queue.pop()
        found.append(current)
        if depth >= max_depth:
            continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.name.startswith(".") or entry.name in SKIP_DIR_NAMES:
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            queue.append((Path(entry.path), depth + 1))
                    except OSError:
                        continue
        except OSError:
            continue
    return found


def classify_scope(raw: str) -> str | None:
    """How broad a folder is: 'disk', 'all-users', 'home', 'credential-folder',
    'personal-folder', or None for an ordinary (project-sized) folder."""
    home = str(home_dir()).replace("\\", "/").rstrip("/")
    p = raw.strip().strip("\"'").replace("\\", "/")
    p = re.sub(r"\$\{(?:env:)?HOME\}|\$HOME\b|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%", home, p, flags=re.I)
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    p = re.sub(r"/+", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    low = p.lower()
    if not low:
        return None
    if low == "/" or re.fullmatch(r"[a-z]:/?", low):
        return "disk"
    if low in ("/users", "/home") or re.fullmatch(r"[a-z]:/users", low):
        return "all-users"
    if low == home.lower() or re.fullmatch(r"(?:/users|/home|[a-z]:/users)/[^/]+", low):
        return "home"
    m = re.fullmatch(r"(?:/users|/home|[a-z]:/users)/[^/]+/(.+)", low)
    rel = low[len(home) + 1:] if low.startswith(home.lower() + "/") else (m.group(1) if m else None)
    if rel is None:
        return None
    parts = rel.split("/")
    if any(part in _CREDENTIAL_DIRS for part in parts):
        return "credential-folder"
    if rel in _PERSONAL_DIRS:
        return "personal-folder"
    return None
