#!/bin/sh
# Installs glasswing. Short and readable on purpose: a security tool
# asking people to pipe a script into a shell should be easy to audit.
# Usage: curl -fsSL https://raw.githubusercontent.com/umar418/glasswing/main/install.sh | sh
set -eu

REPO_URL="https://github.com/umar418/glasswing"

echo "==> Checking for uv..."
if ! command -v uv >/dev/null 2>&1; then
  echo "==> Installing uv (https://docs.astral.sh/uv/)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
else
  echo "==> uv already installed."
fi

echo "==> Running glasswing scan via uvx (nothing is installed permanently)..."
exec uvx --from "git+${REPO_URL}" glasswing scan
