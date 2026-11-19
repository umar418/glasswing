# Installs glasswing. Short and readable on purpose: a security tool
# asking people to pipe a script into a shell should be easy to audit.
# Usage: irm https://raw.githubusercontent.com/umar418/glasswing/main/install.ps1 | iex
$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/umar418/glasswing"

Write-Host "==> Checking for uv..."
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing uv (https://docs.astral.sh/uv/)..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
} else {
    Write-Host "==> uv already installed."
}

Write-Host "==> Running glasswing scan via uvx (nothing is installed permanently)..."
uvx --from "git+$RepoUrl" glasswing scan
