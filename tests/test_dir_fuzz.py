"""dir_fuzz: ffuf JSON parsing, status filtering, rate/thread caps, scope
gate, error results. No real fuzzing."""
import json
import subprocess
from types import SimpleNamespace as NS

import pytest

from agent.recon import dir_fuzz
from agent.scope import ALLOWED, ScopeError

HOST = next(iter(ALLOWED))
TARGET = f"https://{HOST}"

FFUF_JSON = json.dumps({
    "results": [
        {"input": {"FUZZ": "admin"}, "status": 200, "length": 512, "words": 10},
        {"input": {"FUZZ": "backup"}, "status": 403, "length": 128, "words": 4},
        {"input": {"FUZZ": "secret"}, "status": 404, "length": 0, "words": 0},
        {"input": {"FUZZ": "login"}, "status": 302, "length": 0, "words": 0},
    ]
})


def _runner(stdout=FFUF_JSON, stderr="", code=0, calls=None):
    def run(cmd):
        if calls is not None:
            calls.append(cmd)
        return NS(stdout=stdout.encode(), stderr=stderr.encode(), returncode=code)
    return run


# ---------- parsing ----------

def test_parse_ffuf_json():
    assert dir_fuzz.parse_ffuf_json(FFUF_JSON) == [
        {"path": "/admin", "status": 200, "length": 512, "words": 10},
        {"path": "/backup", "status": 403, "length": 128, "words": 4},
        {"path": "/login", "status": 302, "length": 0, "words": 0},
        {"path": "/secret", "status": 404, "length": 0, "words": 0},
    ]


# ---------- status filtering ----------

def test_filter_by_status_default_hides_404():
    parsed = dir_fuzz.parse_ffuf_json(FFUF_JSON)
    found = dir_fuzz.filter_by_status(parsed)
    assert {r["path"] for r in found} == {"/admin", "/backup", "/login"}
    assert all(r["status"] != 404 for r in found)


def test_filter_by_status_custom_list():
    parsed = dir_fuzz.parse_ffuf_json(FFUF_JSON)
    found = dir_fuzz.filter_by_status(parsed, "403,404")
    assert {r["path"] for r in found} == {"/backup", "/secret"}


# ---------- command building ----------

def test_build_command_is_capped_and_safe():
    cmd = dir_fuzz.build_command(TARGET, "/usr/share/wordlists/dirb/common.txt", 40, 10, "200,403")
    assert cmd[:6] == ["wsl", "-d", "kali-linux", "-u", "root", "--"]
    assert cmd[6] == "ffuf"
    ffuf_args = cmd[6:]
    assert ffuf_args[ffuf_args.index("-u") + 1] == f"{TARGET}/FUZZ"
    assert cmd[cmd.index("-w") + 1] == "/usr/share/wordlists/dirb/common.txt"
    assert cmd[cmd.index("-rate") + 1] == "40"
    assert cmd[cmd.index("-t") + 1] == "10"
    assert cmd[cmd.index("-mc") + 1] == "200,403"


async def test_fuzz_uses_default_wordlist_rate_threads_and_codes():
    calls = []
    out = await dir_fuzz.fuzz_directories(TARGET, runner=_runner(calls=calls))
    assert out["ok"]
    cmd = calls[0]
    assert cmd[cmd.index("-w") + 1] == dir_fuzz.DEFAULT_WORDLIST
    assert cmd[cmd.index("-rate") + 1] == str(dir_fuzz.DEFAULT_RATE)
    assert cmd[cmd.index("-t") + 1] == str(dir_fuzz.DEFAULT_THREADS)
    assert cmd[cmd.index("-mc") + 1] == dir_fuzz.DEFAULT_STATUS_CODES
    assert {r["path"] for r in out["paths"]} == {"/admin", "/backup", "/login"}


async def test_fuzz_allows_wordlist_rate_threads_override():
    calls = []
    out = await dir_fuzz.fuzz_directories(
        TARGET, wordlist="/tmp/custom.txt", rate=5, threads=3, runner=_runner(calls=calls)
    )
    assert out["wordlist"] == "/tmp/custom.txt" and out["rate"] == 5 and out["threads"] == 3
    cmd = calls[0]
    assert cmd[cmd.index("-w") + 1] == "/tmp/custom.txt"
    assert cmd[cmd.index("-rate") + 1] == "5"
    assert cmd[cmd.index("-t") + 1] == "3"


# ---------- rate/thread caps: rejected, not silently clamped ----------

@pytest.mark.parametrize("rate", [0, -1, 201, "40", True])
async def test_rate_above_cap_rejected(rate):
    calls = []
    with pytest.raises(ValueError):
        await dir_fuzz.fuzz_directories(TARGET, rate=rate, runner=_runner(calls=calls))
    assert calls == []


@pytest.mark.parametrize("threads", [0, -1, 41, "10", True])
async def test_threads_above_cap_rejected(threads):
    calls = []
    with pytest.raises(ValueError):
        await dir_fuzz.fuzz_directories(TARGET, threads=threads, runner=_runner(calls=calls))
    assert calls == []


@pytest.mark.parametrize("codes", ["200;id", "abc", "", "200,"])
async def test_bad_status_codes_rejected(codes):
    with pytest.raises(ValueError):
        await dir_fuzz.fuzz_directories(TARGET, status_codes=codes, runner=_runner())


# ---------- scope gate ----------

async def test_out_of_scope_raises_and_runs_nothing():
    calls = []
    with pytest.raises(ScopeError):
        await dir_fuzz.fuzz_directories("https://evil.example.org", runner=_runner(calls=calls))
    assert calls == []


# ---------- environment failures come back as results, not exceptions ----------

async def test_error_results_not_exceptions():
    def no_wsl(cmd):
        raise FileNotFoundError()

    r = await dir_fuzz.fuzz_directories(TARGET, runner=no_wsl)
    assert not r["ok"] and r["error"] == "WSL not available" and r["hint"]

    r = await dir_fuzz.fuzz_directories(
        TARGET, runner=_runner("", "bash: line 1: ffuf: command not found", 127)
    )
    assert not r["ok"] and r["error"] == "ffuf not found in WSL"

    def slow(cmd):
        raise subprocess.TimeoutExpired(cmd, 1)

    r = await dir_fuzz.fuzz_directories(TARGET, runner=slow)
    assert not r["ok"] and "timed out" in r["error"]

    r = await dir_fuzz.fuzz_directories(TARGET, runner=_runner('{"results": [bad json}', "", 0))
    assert not r["ok"] and "could not parse" in r["error"]
