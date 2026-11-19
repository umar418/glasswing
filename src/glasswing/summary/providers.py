"""AI summary provider selection and calls.

Priority: local model (Ollama) first, then a user-provided cloud key, then
no AI at all (the template summary is always available). Every path here
is best-effort and fails soft back to the template summary -- a flaky
network call must never crash a scan.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

OLLAMA_HOST = "http://127.0.0.1:11434"
TIMEOUT = 2.0

PROMPT_INSTRUCTIONS = """You are writing a plain-language security exposure report for a \
non-technical professional (e.g. a lawyer or doctor) about the AI tools on their computer.

You are given ONLY a redacted, structured JSON summary of findings -- no file contents, no \
secrets, no raw arguments. Do not invent anything not present in the JSON.

Write five short markdown sections, in this order:
1. **Overall exposure level** ({exposure_level}) with a two-sentence reason.
2. **What your AI tools can reach right now** -- grouped by app, plain language.
3. **What they actually touched** -- only if activity data is present; otherwise say none was collected this scan.
4. **Top 5 fixes, ranked** -- concrete and specific, from the findings given.
5. **What this scan could not see** -- from the list given.

JSON:
{payload_json}
"""


def detect_ollama_model() -> str | None:
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = data.get("models") or []
        if models:
            return models[0]["name"]
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
    return None


def call_ollama(model: str, payload: dict) -> str | None:
    prompt = PROMPT_INSTRUCTIONS.format(exposure_level=payload["exposure_level"], payload_json=json.dumps(payload, indent=2))
    body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{OLLAMA_HOST}/api/generate", data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("response")
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def call_anthropic(api_key: str, payload: dict) -> str | None:
    prompt = PROMPT_INSTRUCTIONS.format(exposure_level=payload["exposure_level"], payload_json=json.dumps(payload, indent=2))
    body = json.dumps(
        {
            "model": "claude-sonnet-5",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        blocks = data.get("content") or []
        return "".join(b.get("text", "") for b in blocks) or None
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


BYO_ENV_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


def available_byo_provider() -> tuple[str, str] | None:
    for provider, env_var in BYO_ENV_VARS.items():
        key = os.environ.get(env_var)
        if key:
            return provider, key
    return None
