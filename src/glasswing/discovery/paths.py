"""Cross-platform path resolution helpers."""
from __future__ import annotations

import os
import platform
from pathlib import Path

SKIP_DIR_NAMES = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".cache",
}

DEFAULT_PROJECT_ROOTS = ["~/code", "~/projects", "~/dev", "~/Documents", "~/Desktop"]
DEFAULT_PROJECT_SCAN_DEPTH = 3


def current_os() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def expand_path(raw: str, base: Path | None = None) -> Path:
    """Expand ~ and %ENV% style placeholders used in the registry files."""
    value = raw
    if "%APPDATA%" in value:
        value = value.replace("%APPDATA%", os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    if "%LOCALAPPDATA%" in value:
        value = value.replace(
            "%LOCALAPPDATA%", os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        )
    path = Path(os.path.expanduser(value))
    if not path.is_absolute() and base is not None:
        path = base / path
    return path


def iter_project_roots(extra_roots: list[str] | None = None) -> list[Path]:
    roots = []
    for raw in DEFAULT_PROJECT_ROOTS + (extra_roots or []):
        p = expand_path(raw)
        if p.is_dir():
            roots.append(p)
    return roots


def find_project_dirs(roots: list[Path], max_depth: int = DEFAULT_PROJECT_SCAN_DEPTH) -> list[Path]:
    """Breadth-limited walk collecting candidate project directories."""
    found: list[Path] = []
    for root in roots:
        _walk(root, max_depth, found)
    return found


def _walk(current: Path, depth_left: int, out: list[Path]) -> None:
    if depth_left < 0:
        return
    out.append(current)
    if depth_left == 0:
        return
    try:
        children = [c for c in current.iterdir() if c.is_dir() and c.name not in SKIP_DIR_NAMES and not c.name.startswith(".")]
    except (PermissionError, OSError):
        return
    for child in children:
        _walk(child, depth_left - 1, out)
