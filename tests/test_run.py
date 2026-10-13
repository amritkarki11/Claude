"""run.py: building a Session from --cookie/--header/--bearer, the
AUTHENTICATED/UNAUTHENTICATED mode line, and CLI validation."""
import json
import pathlib
import subprocess
import sys

import httpx
import pytest

import run as run_mod
from agent.http import Session

REPO_ROOT = pathlib.Path(__file__).parent.parent


# ---------- build_session ----------

def test_build_session_cookie_header_bearer():
    s = run_mod.build_session("a=1; b=2", ["X-Api-Key: secret", "X-Other:val2"], "tok123")
    assert s.cookies == {"a": "1", "b": "2"}
    assert s.headers == {"X-Api-Key": "secret", "X-Other": "val2"}
    assert s.bearer == "tok123"


def test_build_session_bearer_only():
    s = run_mod.build_session(None, None, "tok")
    assert s.bearer == "tok" and s.cookies == {} and s.headers == {}


def test_build_session_cookie_only_whitespace_tolerant():
    s = run_mod.build_session(" a = 1 ;  b=2 ", None, None)
    assert s.cookies == {"a": "1", "b": "2"}


def test_build_session_bad_cookie_raises():
    with pytest.raises(ValueError):
        run_mod.build_session("not-a-pair", None, None)


def test_build_session_bad_header_raises():
    with pytest.raises(ValueError):
        run_mod.build_session(None, ["NoColonHere"], None)


# ---------- recon() prints an unambiguous auth mode and threads the Session ----------

class _FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _stub_pipeline(monkeypatch, tmp_path, captured: dict):
    async def fake_run_recon(client, seed_url, **kw):
        captured["session"] = kw.get("session")
        return {
            "host": "x", "archive": {},
            "summary": {"pages": 0, "forms": 0, "js_files": 0, "endpoints": 0,
                        "params": 0, "sourcemaps": 0, "sources_exposed": 0, "secrets": 0},
        }

    monkeypatch.setattr("agent.recon.pipeline.run_recon", fake_run_recon)
    monkeypatch.setattr("agent.recon.pipeline.write_report", lambda report, out_dir=None: tmp_path / "r.json")
    monkeypatch.setattr("agent.http.HttpClient", lambda *a, **kw: _FakeClient())


async def test_recon_prints_authenticated_when_session_given(monkeypatch, capsys, tmp_path):
    captured = {}
    _stub_pipeline(monkeypatch, tmp_path, captured)
    session = Session(bearer="tok-secret-value")

    await run_mod.recon("https://host/", session=session)

    out = capsys.readouterr().out
    assert "[recon] mode: AUTHENTICATED" in out
    assert "[recon] mode: UNAUTHENTICATED" not in out
    assert captured["session"] is session
    assert "tok-secret-value" not in out  # mode line names the mode, never the raw credential


async def test_recon_prints_unauthenticated_when_no_session(monkeypatch, capsys, tmp_path):
    captured = {}
    _stub_pipeline(monkeypatch, tmp_path, captured)

    await run_mod.recon("https://host/")

    out = capsys.readouterr().out
    assert "[recon] mode: UNAUTHENTICATED" in out
    assert captured["session"] is None


# ---------- end-to-end: the report never contains the raw credential ----------

async def test_report_never_contains_raw_credential(monkeypatch, capsys, tmp_path):
    secret_report = {
        "host": "x", "archive": {},
        "summary": {"pages": 0, "forms": 0, "js_files": 0, "endpoints": 0,
                    "params": 0, "sourcemaps": 0, "sources_exposed": 0, "secrets": 0},
    }

    async def fake_run_recon(client, seed_url, **kw):
        return secret_report

    monkeypatch.setattr("agent.recon.pipeline.run_recon", fake_run_recon)
    monkeypatch.setattr("agent.recon.pipeline.write_report", lambda report, out_dir=None: tmp_path / "r.json")
    monkeypatch.setattr("agent.http.HttpClient", lambda *a, **kw: _FakeClient())

    await run_mod.recon("https://host/", session=Session(bearer="tok-secret-value"))

    out = capsys.readouterr().out
    assert "tok-secret-value" not in out
    assert "tok-secret-value" not in json.dumps(secret_report)


# ---------- CLI validation ----------

def test_cli_cookie_without_recon_rejected():
    r = subprocess.run(
        [sys.executable, "run.py", "--cookie", "a=1"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 2
    assert "--cookie/--header/--bearer require --recon" in r.stderr


def test_cli_malformed_header_rejected():
    r = subprocess.run(
        [sys.executable, "run.py", "--recon", "https://example.invalid", "--header", "NoColon"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 2
    assert "--header entries must be 'Name: Value'" in r.stderr
    assert "NoColon" not in r.stderr  # the (possibly sensitive) value is never echoed


def test_cli_help_lists_auth_flags():
    r = subprocess.run([sys.executable, "run.py", "--help"], capture_output=True, text=True, cwd=REPO_ROOT)
    assert r.returncode == 0
    assert "--cookie" in r.stdout and "--header" in r.stdout and "--bearer" in r.stdout
