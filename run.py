"""Entrypoint. First run: `python run.py --check` to verify the three brains.

Scope is resolved from config.yaml by default. --scope/--target can extend
it for a single run, but nothing runs until the resolved scope is printed
and the user explicitly types 'yes' to confirm. Fail closed: if no scope is
set at all, this refuses to run rather than scanning everything.
"""
import argparse
import asyncio
import sys

from agent.router import ask
from agent.scope import ALLOWED, add_to_scope, host_of, set_scope


def read_scope_file(path: str) -> list[str]:
    """Approved hosts, one per line. Blank lines and #comments are skipped;
    URLs are reduced to their host."""
    hosts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line and (h := host_of(line)):
                hosts.append(h)
    return hosts


def parse_selection(answer: str, count: int) -> list[int] | None:
    """Parse 'all', or numbers/ranges like '1,3,5-7' (1-based) into 0-based
    indexes. Returns None on invalid input."""
    answer = answer.strip().lower()
    if answer == "all":
        return list(range(count))
    picked: set[int] = set()
    try:
        for part in answer.split(","):
            part = part.strip()
            if not part:
                continue
            lo, _, hi = part.partition("-")
            lo_i, hi_i = int(lo), int(hi or lo)
            if lo_i < 1 or hi_i > count or lo_i > hi_i:
                return None
            picked.update(range(lo_i - 1, hi_i))
    except ValueError:
        return None
    return sorted(picked)


def format_source_statuses(statuses) -> str:
    """One line per --domain run reporting what every OSINT source did.
    Always printed — a source that failed is named, never swallowed into
    a quiet zero."""
    parts = [
        f"{s.name}: {s.count} found" if s.ok else f"{s.name}: unavailable ({s.error})"
        for s in statuses
    ]
    return "[subdomains] sources — " + ", ".join(parts)


def pick_subdomains(found: list[dict], domain: str | None = None, include_all: bool = False, ask=input) -> list[str]:
    """Print every discovered subdomain and return the hosts the user selects.
    Nothing is selected unless the user says so (or include_all is set).

    A subdomain that fails DNS resolution is NEVER dropped from this list —
    only its `resolves` status changes. It's shown as unresolved and stays
    selectable; whether to include it is the user's call, not this
    function's. The apex domain itself is always offered as a candidate too
    — even if every OSINT source failed or returned nothing — so --domain
    never silently falls back to leaving scope empty (or to config.yaml's
    allowlist)."""
    by_host = {r["subdomain"]: r for r in found}
    if domain:
        apex = domain.lower().strip(".")
        by_host.setdefault(apex, {"subdomain": apex, "resolves": True, "ips": [], "errors": []})
    hosts = sorted(by_host)
    if not hosts:
        print("[subdomains] no subdomains discovered.")
        return []
    resolving = sum(1 for h in hosts if by_host[h].get("resolves"))
    unresolved = len(hosts) - resolving
    print(f"[subdomains] {len(hosts)} discovered ({resolving} resolving, {unresolved} unresolved):")
    for i, h in enumerate(hosts, 1):
        r = by_host[h]
        detail = ", ".join(r["ips"]) if r.get("resolves") else "unresolved"
        print(f"  {i:3}. {h}  {detail}")
    if include_all:
        return hosts
    while True:
        answer = ask("Select hosts to include (e.g. 1,3,5-7), 'all', or blank for none: ")
        if not answer.strip():
            return []
        idx = parse_selection(answer, len(hosts))
        if idx is not None:
            return [hosts[i] for i in idx]
        print("[subdomains] invalid selection, try again.")


def resolve_scope_mode(a, enumerate_fn=None, ask=input) -> None:
    """Apply --target/--domain/--scope-list to the run allowlist."""
    if a.target:
        host = host_of(a.target)
        if not host:
            print(f"[scope] could not parse a host from target {a.target!r}")
            sys.exit(1)
        add_to_scope(host)
    elif a.scope_list:
        for h in read_scope_file(a.scope_list):
            add_to_scope(h)
    elif a.domain:
        if enumerate_fn is None:
            from agent.recon.subdomains import enumerate_subdomains as enumerate_fn
        found, statuses = asyncio.run(enumerate_fn(a.domain))
        print(format_source_statuses(statuses))
        for h in pick_subdomains(found, domain=a.domain, include_all=a.include_subdomains, ask=ask):
            add_to_scope(h)


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


async def recon(
    seed_url: str,
    portscan: dict | None = None,
    include_dns: bool = False,
    include_archive: bool = False,
) -> None:
    from agent.http import HttpClient
    from agent.recon.pipeline import format_summary, run_recon, write_report

    async with HttpClient() as client:
        report = await run_recon(
            client, seed_url, include_dns=include_dns, portscan=portscan, include_archive=include_archive
        )
    print(format_summary(report, write_report(report)))


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
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--target", help="single target URL; its host is added to scope")
    mode.add_argument("--domain", help="enumerate subdomains of DOMAIN, then choose which to scope")
    mode.add_argument("--scope-list", help="file of approved hosts, one per line")
    ap.add_argument("--include-subdomains", action="store_true",
                    help="with --domain: include all discovered subdomains without prompting")
    ap.add_argument("--recon", metavar="SEED_URL", help="crawl + JS endpoints + source maps; seed host is auto-added to scope")
    ap.add_argument("--portscan", action="store_true", help="with --recon: nmap -sV scan via Kali WSL (opt-in)")
    ap.add_argument("--ports", help="with --portscan: port spec, e.g. 80,443,8080 or 1-1000 (default: nmap top-1000)")
    ap.add_argument("--timing", type=int, default=3, help="with --portscan: nmap timing 0-3 (default 3; higher is rejected)")
    ap.add_argument("--dns", action="store_true", help="with --recon: DNS records, SPF/DMARC, CNAME chain, wildcard check (opt-in)")
    ap.add_argument("--archive", action="store_true",
                    help="with --recon: pull historical URLs from Wayback Machine + URLScan.io, "
                         "feed new in-scope JS through the same extraction pipeline (opt-in)")
    a = ap.parse_args()

    if (a.ports is not None or a.timing != 3) and not a.portscan:
        ap.error("--ports/--timing require --portscan")
    if a.portscan:
        from agent.recon.port_scan import validate_ports, validate_timing
        if not a.recon:
            ap.error("--portscan requires --recon")
        try:
            validate_timing(a.timing)
            validate_ports(a.ports)
        except ValueError as e:
            ap.error(str(e))

    if a.dns and not a.recon:
        ap.error("--dns requires --recon")
    if a.archive and not a.recon:
        ap.error("--archive requires --recon")

    if a.scope:
        set_scope(h.strip() for h in a.scope.split(",") if h.strip())

    if a.include_subdomains and not a.domain:
        ap.error("--include-subdomains requires --domain")

    resolve_scope_mode(a)
    if a.recon:
        seed_host = host_of(a.recon)
        if not seed_host:
            print(f"[scope] could not parse a host from {a.recon!r}")
            sys.exit(1)
        add_to_scope(seed_host)

    if a.check:
        check()
    else:
        # Pre-scan gate. Refuses if no scope came from config or flags.
        confirm_scope()
        if a.recon:
            asyncio.run(recon(
                a.recon,
                {"ports": a.ports, "timing": a.timing} if a.portscan else None,
                include_dns=a.dns,
                include_archive=a.archive,
            ))
