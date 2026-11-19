from glasswing.parsers.secrets import mask_secret, redact_url_path_ids, safe_arg, scan_text


def test_mask_secret_never_returns_full_value():
    secret = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
    masked = mask_secret(secret)
    assert secret not in masked
    assert masked.startswith(secret[:3])
    assert masked.endswith(secret[-4:])


def test_scan_text_detects_anthropic_key_and_masks_it():
    secret = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
    findings = scan_text(f'ANTHROPIC_API_KEY={secret}', source_path="test")
    assert findings, "expected at least one match"
    assert any(f.pattern_id == "anthropic-api-key" for f in findings)
    for f in findings:
        assert secret not in f.masked_value


def test_scan_text_ignores_ordinary_text():
    findings = scan_text("hello world, this is just a normal sentence.", source_path="test")
    assert findings == []


def test_safe_arg_masks_secret_looking_argument():
    secret = "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
    result = safe_arg(secret)
    assert secret not in result
    assert result == "<redacted: looks like a secret>"


def test_safe_arg_passes_through_plain_paths():
    assert safe_arg("/Users/alice/projects/app") == "/Users/alice/projects/app"


def test_redact_url_path_ids_masks_uuid_segment():
    url = "https://mcp.example.com/mcp/c/7af88ecf-f4c7-4b89-96c9-9a8b550df921"
    redacted = redact_url_path_ids(url)
    assert "7af88ecf-f4c7-4b89-96c9-9a8b550df921" not in redacted
    assert redacted.startswith("https://mcp.example.com/mcp/c/")


def test_redact_url_path_ids_leaves_non_urls_alone():
    assert redact_url_path_ids("/plain/path") == "/plain/path"
