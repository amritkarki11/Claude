from agent.recon.secret_scanner import redact_preview, scan_files, scan_text, shannon_entropy

AWS = "AKIAIOSFODNN7EXAMPLE"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
BLOB = "q8Zr3KfP0xLm9TvB2nWc7YdH5sJe1GaU4oRi6XbN"


def _only(hits, kind):
    found = [h for h in hits if h["type"] == kind]
    assert len(found) == 1, hits
    return found[0]


def test_aws_key_caught_and_redacted():
    text = f"var a = 1;\nconst cfg = {{ key: '{AWS}' }};\n"
    h = _only(scan_text(text, "app.js"), "aws_access_key")
    assert h["match_preview"] == "AKIA...MPLE"
    assert h["line_number"] == 2 and h["confidence"] == "high" and h["source"] == "app.js"
    assert AWS not in h["context"] and AWS not in h["match_preview"]


def test_jwt_caught_and_redacted():
    h = _only(scan_text(f'token = "{JWT}";'), "jwt")
    assert h["match_preview"] == f"{JWT[:4]}...{JWT[-4:]}"
    assert JWT not in h["context"]


def test_high_entropy_blob_caught_and_redacted():
    h = _only(scan_text(f"x = '{BLOB}'"), "high_entropy_string")
    assert h["match_preview"] == f"{BLOB[:4]}...{BLOB[-4:]}"
    assert BLOB not in h["context"]
    assert shannon_entropy(BLOB) >= 4.2


def test_entropy_threshold_configurable_and_no_false_positive_on_prose():
    assert not [h for h in scan_text(f"x = '{BLOB}'", entropy_threshold=6.0)]
    assert scan_text("function handleUserAuthenticationRequestCallback() {}") == []


def test_matched_secret_not_double_reported_as_entropy():
    hits = scan_text(f"k = '{AWS}'; j = '{JWT}'")
    assert {h["type"] for h in hits} == {"aws_access_key", "jwt"}


def test_dedup_and_generic_assignment():
    text = f"password = 'hunter2hunter2'\npassword = 'hunter2hunter2'\n{AWS}\n{AWS}"
    hits = scan_text(text)
    assert [h["type"] for h in hits].count("generic_secret") == 1
    assert [h["type"] for h in hits].count("aws_access_key") == 1
    assert _only(hits, "generic_secret")["match_preview"] == "hunt...ter2"


def test_other_patterns():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "ip = '10.0.0.5'\n"
        "u = 'https://my-bucket.s3.amazonaws.com/a.png'\n"
        "s = 'xoxb-1234567890-abcdefghij'\n"
        "p = 'password: \"${PASSWORD}\"'\n"  # placeholder: ignored
    )
    kinds = {h["type"] for h in scan_text(text)}
    assert {"private_key", "internal_ip", "s3_bucket_url", "slack_token"} <= kinds
    assert "generic_secret" not in kinds


def test_scan_files_and_short_preview():
    hits = scan_files({"a.js": f"k='{AWS}'", "b.html": "nothing here"})
    assert [h["source"] for h in hits] == ["a.js"]
    assert redact_preview("short") == "*****"


def test_asset_references_not_flagged_as_entropy():
    for ref in (
        "assets/q8Zr3KfP0xLm9TvB2nWc7YdH5sJe1GaU4oRi6XbN",
        "q8Zr3KfP0xLm9TvB2nWc7YdH5sJe1GaU4oRi6XbN.js",
        "q8Zr3KfP0xLm9TvB2nWc7YdH5sJe1GaU4oRi6XbN.woff2",
        "index-q8Zr3KfP0xLm9TvB2nWc7YdH5sJe.js",
    ):
        assert not scan_text(f"load('{ref}')"), ref
    # same token without asset shape is still flagged; pattern secrets unaffected
    assert _only(scan_text(f"x = '{BLOB}'"), "high_entropy_string")
    assert _only(scan_text(f"a='assets/app.js'; k='{AWS}'"), "aws_access_key")
