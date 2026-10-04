"""Scope guard: config base allowlist, runtime set_scope()/add_to_scope(),
and fail-closed behavior when no scope is set."""
import pytest

import run
from agent import scope
from agent.scope import ScopeError, add_to_scope, check, host_of, set_scope


@pytest.fixture(autouse=True)
def restore_scope():
    saved = set(scope.ALLOWED)
    yield
    scope.ALLOWED.clear()
    scope.ALLOWED.update(saved)


def test_config_hosts_are_allowed_by_default():
    for h in scope._CONFIG_ALLOWED:
        assert check(f"https://{h}/x") == f"https://{h}/x"


def test_out_of_scope_host_refused():
    with pytest.raises(ScopeError):
        check("https://evil.example.org/")


def test_set_scope_runtime_hosts_allowed_and_keeps_config():
    set_scope(["Runtime.Example.com", "other.example.com"])
    assert check("https://runtime.example.com/a")
    assert check("http://other.example.com:8080/")
    for h in scope._CONFIG_ALLOWED:
        assert check(f"https://{h}/")
    with pytest.raises(ScopeError):
        check("https://notlisted.example.com/")


def test_set_scope_replaces_previous_runtime_hosts():
    set_scope(["a.example.com"])
    set_scope(["b.example.com"])
    assert check("https://b.example.com/")
    with pytest.raises(ScopeError):
        check("https://a.example.com/")


def test_add_to_scope_and_host_of_target_url():
    add_to_scope(host_of("https://Target.Example.com:8443/path?q=1"))
    assert check("https://target.example.com/other")


def test_allowed_is_mutated_in_place():
    ref = scope.ALLOWED
    set_scope(["x.example.com"])
    add_to_scope("y.example.com")
    assert scope.ALLOWED is ref


def test_empty_allowlist_fails_closed():
    scope.ALLOWED.clear()
    with pytest.raises(ScopeError, match="no allowlist"):
        check("https://anything.example.com/")


def test_confirm_scope_refuses_when_empty(capsys):
    scope.ALLOWED.clear()
    with pytest.raises(SystemExit) as e:
        run.confirm_scope()
    assert e.value.code == 1


def test_confirm_scope_requires_yes(monkeypatch):
    set_scope(["a.example.com"])
    monkeypatch.setattr("builtins.input", lambda _: "no")
    with pytest.raises(SystemExit):
        run.confirm_scope()
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    run.confirm_scope()  # returns normally
