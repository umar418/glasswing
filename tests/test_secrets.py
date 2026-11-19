"""Two promises: a real credential never appears in any output, and things
that are not credentials are not reported as credentials."""
import os

import pytest

from conftest import ANTHROPIC_KEY, OPAQUE_TOKEN, OPENAI_KEY
from glasswing.parsers import secrets as sec

SHORT = "winter2024pw"


def node(**extra):
    return {"command": "node", "args": ["server.js"], **extra}


LEAK_CASES = {
    "env value": lambda h, s: h.cursor({"a": node(env={"API_KEY": s})}),
    "env value with unrelated name": lambda h, s: h.cursor({"a": node(env={"FOO": s})}),
    "header": lambda h, s: h.cursor({"a": {"url": "https://mcp.example.net/x", "headers": {"Authorization": f"Bearer {s}"}}}),
    "x-api-key header": lambda h, s: h.cursor({"a": {"url": "https://mcp.example.net/x", "headers": {"X-API-Key": s}}}),
    "argument": lambda h, s: h.cursor({"a": node(args=["server.js", s])}),
    "--flag=value": lambda h, s: h.cursor({"a": node(args=["server.js", f"--token={s}"])}),
    "--flag value": lambda h, s: h.cursor({"a": node(args=["server.js", "--api-key", s])}),
    "--header argument": lambda h, s: h.cursor({"a": {"command": "npx", "args": ["-y", "mcp-remote", "https://mcp.example.net/x", "--header", f"Authorization: Bearer {s}"]}}),
    "url query": lambda h, s: h.cursor({"a": {"url": f"https://mcp.example.net/sse?api_key={s}&x=1"}}),
    "url password": lambda h, s: h.cursor({"a": {"url": f"https://admin:{s}@mcp.example.net/sse"}}),
    "url path": lambda h, s: h.cursor({"a": {"url": f"https://mcp.example.net/u/{s}/sse"}}),
    "mcp-remote url path": lambda h, s: h.cursor({"a": {"command": "npx", "args": ["-y", "mcp-remote", f"https://mcp.example.net/u/{s}/sse"]}}),
    "server name": lambda h, s: h.cursor({s: node()}),
    "command": lambda h, s: h.cursor({"a": {"command": f"/opt/{s}/run", "args": []}}),
    "permission rule": lambda h, s: h.claude_settings({"permissions": {"allow": [f'Bash(curl -H "x-api-key: {s}" https://api.example.com:*)', "Bash(python3:*)"]}}),
    "settings env": lambda h, s: h.claude_settings({"env": {"ANTHROPIC_API_KEY": s}}),
    "project folder name": lambda h, s: h.write(f"code/{s}/.mcp.json", {"mcpServers": {"a": {"command": "npx", "args": ["-y", "zzz"]}}}),
    "unrelated key elsewhere in file": lambda h, s: h.write(".cursor/mcp.json", {"mcpServers": {}, "notes": {"deep": [f"key is {s} ok"]}}),
    "claude.json project server": lambda h, s: h.write(".claude.json", {"projects": {"/nope": {"mcpServers": {"x": {"type": "http", "url": "https://e.example.net/m", "headers": {"Authorization": f"Bearer {s}"}}}}}}),
    "codex toml": lambda h, s: h.write(".codex/config.toml", f'[mcp_servers.a]\ncommand = "node"\nargs = ["s.js"]\n[mcp_servers.a.env]\nSECRET_TOKEN = "{s}"\n'),
    "continue yaml": lambda h, s: h.write(".continue/config.yaml", f"mcpServers:\n  - name: a\n    command: node\n    args: [s.js]\n    env:\n      API_TOKEN: {s}\n"),
}
# Short low-entropy secrets can only be recognised from their context (a credential-named field or flag).
CONTEXT_ONLY = {"env value with unrelated name", "argument", "server name", "command", "project folder name", "unrelated key elsewhere in file", "url path", "mcp-remote url path"}


@pytest.mark.parametrize("place", sorted(LEAK_CASES))
@pytest.mark.parametrize("secret", [ANTHROPIC_KEY, OPENAI_KEY, OPAQUE_TOKEN, SHORT], ids=["anthropic", "openai", "opaque", "short"])
def test_secret_never_reaches_any_output(home, place, secret):
    if secret == SHORT and place in CONTEXT_ONLY:
        pytest.skip("a short ordinary-looking word with no credential context is indistinguishable from normal text")
    LEAK_CASES[place](home, secret)
    result = home.scan()
    assert secret not in result.everything, f"secret placed in {place} leaked"
    assert secret not in str(result.summary)


def test_ai_payload_contains_no_secret_or_home_path(home):
    from glasswing.summary.redact import build_redacted_payload

    home.cursor({"a": node(env={"API_KEY": ANTHROPIC_KEY}), "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(home.root / "legal" / "smith-v-jones")]}})
    payload = str(build_redacted_payload(home.scan().data))
    assert ANTHROPIC_KEY not in payload
    assert str(home.root) not in payload
    assert "smith-v-jones" not in payload


@pytest.mark.parametrize("place", ["env value", "header", "--flag=value", "settings env", "claude.json project server", "codex toml", "continue yaml"])
def test_plaintext_credential_is_reported(home, place):
    LEAK_CASES[place](home, ANTHROPIC_KEY)
    assert "SECRET-PLAINTEXT-CONFIG" in home.scan().rules


def test_short_password_in_named_field_is_reported(home):
    home.cursor({"a": node(env={"DB_PASSWORD": SHORT})})
    assert "SECRET-PLAINTEXT-CONFIG" in home.scan().rules


@pytest.mark.parametrize("place", ["url query", "url password", "url path", "mcp-remote url path"])
def test_credential_in_url_is_reported(home, place):
    LEAK_CASES[place](home, OPAQUE_TOKEN)
    assert "SECRET-IN-URL" in home.scan().rules


NOT_SECRETS = {
    "env reference ${VAR}": {"API_KEY": "${MY_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_NUMBER_1}"},
    "env reference $VAR": {"API_KEY": "$OPENAI_API_KEY"},
    "windows env reference": {"API_KEY": "%OPENAI_API_KEY%"},
    "vscode input reference": {"API_KEY": "${input:api-key}"},
    "placeholder": {"API_KEY": "your-api-key-here"},
    "angle placeholder": {"API_KEY": "<YOUR_KEY>"},
    "empty": {"API_KEY": ""},
    "xs": {"API_KEY": "xxxxxxxxxxxxxxxx"},
    "token limit": {"MAX_TOKENS": "4096"},
    "token count name": {"TOKEN_LIMIT": "200000"},
    "path to key file": {"PRIVATE_KEY_PATH": "/Users/alice/keys/service.pem"},
    "env var name field": {"API_KEY_ENV_VAR": "OPENAI_API_KEY"},
    "sha256": {"CHECKSUM": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
    "uuid": {"WORKSPACE": "3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a3b"},
    "long path": {"DATA_DIR": "/Users/alice/Library/ApplicationSupport/MyCompany/Server7/build/Release2024/index"},
    "url": {"BASE_URL": "https://api.example.com/v1/projects/2024/reports/quarterly-summary-final"},
    "words": {"MODE": "production-readonly-replica-eu-west-1"},
    "model name": {"MODEL": "claude-sonnet-5-5-20260101-preview-extended"},
}


@pytest.mark.parametrize("label", sorted(NOT_SECRETS))
def test_non_credentials_are_not_reported(home, label):
    home.cursor({"a": node(env=NOT_SECRETS[label])})
    assert not [r for r in home.scan().rules if r.startswith("SECRET")], label


def test_long_paths_and_ids_in_arguments_are_not_reported(home):
    home.cursor({"a": node(args=[
        "/Users/alice/Library/ApplicationSupport/MyCompany/Server7/build/Release2024/index.js",
        "--project", "3f2b8c1e-9d4a-4f6b-8a2e-1c5d7e9f0a3b", "--commit", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
    ])})
    home.write(".cursor/extra.json", {})
    assert not [r for r in home.scan().rules if r.startswith("SECRET")]


def test_ordinary_urls_elsewhere_in_a_file_are_not_reported(home):
    home.write(".claude.json", {"mcpServers": {}, "cache": {"terms_url": "https://www.example.com/legal/consumer-terms-2026/section-a1b2c3d4e5f6g7h8i9j0k1l2"}})
    assert home.scan().data["findings"] == []


def test_uuid_in_remote_url_is_masked_but_not_called_a_credential(home):
    uuid = "7af88ecf-f4c7-4b89-96c9-9a8b550df921"
    home.cursor({"a": {"url": f"https://mcp.example.net/mcp/c/{uuid}"}})
    result = home.scan()
    assert uuid not in result.everything
    assert "SECRET-IN-URL" not in result.rules


def test_words_containing_sk_are_not_api_keys():
    assert sec.find_vendor_secrets("disk-usage-report-for-all-mounted-volumes-2024") == []
    assert sec.find_vendor_secrets("task-runner-configuration-for-production-env") == []
    assert sec.find_vendor_secrets("sk-learn-style-estimator-pipeline-helper") == []


def test_same_secret_in_many_places_is_one_finding(home):
    home.cursor({f"s{i}": node(env={"API_KEY": ANTHROPIC_KEY}) for i in range(3)})
    result = home.scan()
    (found,) = result.findings("SECRET-PLAINTEXT-CONFIG")
    assert found["count"] == 3  # one per server; the same value is not counted again at file level


def test_mask_never_reveals_short_values():
    assert sec.mask_secret("hunter2") == sec.REDACTED
    assert ANTHROPIC_KEY not in sec.mask_secret(ANTHROPIC_KEY)
    assert len(sec.mask_secret(ANTHROPIC_KEY)) < 12


def test_private_key_block_is_masked(home):
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7x9Qm2\nabcDEF123\n-----END RSA PRIVATE KEY-----"
    home.cursor({"a": node(env={"SIGNING": pem})})
    result = home.scan()
    assert "MIIEpAIBAAKCAQEA7x9Qm2" not in result.everything
    assert "SECRET-PLAINTEXT-CONFIG" in result.rules
