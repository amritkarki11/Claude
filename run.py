"""Entrypoint. First run: `python run.py --check` to verify the three brains."""
import argparse
from agent.router import ask
from agent.scope import ALLOWED


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


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify model providers")
    a = ap.parse_args()
    check() if a.check else ap.print_help()
