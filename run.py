"""Entrypoint. First run: `python run.py --check` to verify the three brains.

Scope is resolved from config.yaml by default. --scope/--target can extend
it for a single run, but nothing runs until the resolved scope is printed
and the user explicitly types 'yes' to confirm. Fail closed: if no scope is
set at all, this refuses to run rather than scanning everything.
"""
import argparse
import sys

from agent.router import ask
from agent.scope import ALLOWED, add_to_scope, host_of, set_scope


def check():
    print(f"[scope] allowlist: {sorted(ALLOWED)}")
    for job, label in [("triage", "LOCAL  (ollama)"),
                       ("hypothesis", "FAST   (groq)"),
                       ("exploit_chain", "FRONTIER (claude)")]:
        try:
            out = ask(job, "Reply with exactly: OK")
            print(f"[ok] {label:16} -> {out.strip()[:40]}")
        except Exception as e:
            print(f"[--] {label:16} -> {type(e).__name__}: {e}")


def confirm_scope() -> None:
    """Print the resolved scope and require the user to type 'yes' before
    any scanning proceeds. Fail closed: an empty allowlist refuses outright,
    without even prompting.
    """
    if not ALLOWED:
        print("[scope] no allowed hosts configured (config.yaml has none, and no --scope/--target given).")
        print("[scope] refusing to run — set scope.allowed_hosts in config.yaml or pass --scope/--target.")
        sys.exit(1)

    print("[scope] resolved allowlist for this run:")
    for h in sorted(ALLOWED):
        print(f"  - {h}")

    answer = input("Type 'yes' to confirm you are authorized to target these hosts: ").strip().lower()
    if answer != "yes":
        print("[scope] not confirmed — refusing to run.")
        sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify model providers")
    ap.add_argument("--scope", help="comma-separated allowed hosts for this run, e.g. host1,host2")
    ap.add_argument("--target", help="target URL; its host is auto-added to scope")
    a = ap.parse_args()

    if a.scope:
        set_scope(h.strip() for h in a.scope.split(",") if h.strip())

    if a.target:
        target_host = host_of(a.target)
        if not target_host:
            print(f"[scope] could not parse a host from --target {a.target!r}")
            sys.exit(1)
        add_to_scope(target_host)

    if a.check:
        check()
    else:
        # Pre-scan gate. Refuses if no scope came from config or flags.
        confirm_scope()
