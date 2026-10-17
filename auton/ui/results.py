"""Rich-formatted results display for AUTON scan output.

Theme: red, white, grey, green only.
"""
from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel


def print_recon_summary(report: dict, report_path: str, console: Console) -> None:
    """Print the RECON COMPLETE summary box."""
    s = report.get("summary", {})

    console.print()
    console.print("[bold green]  RECON COMPLETE[/bold green]")

    tbl = Table(
        show_header=False,
        border_style="grey50",
        show_lines=False,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("Key", style="bold red", min_width=18)
    tbl.add_column("Value", style="white")

    tbl.add_row("Target:", report.get("host", ""))
    tbl.add_row("Endpoints:", str(s.get("endpoints", 0)))
    tbl.add_row("Forms found:", str(s.get("forms", 0)))
    tbl.add_row("Pages crawled:", str(s.get("pages", 0)))
    tbl.add_row("JS analyzed:", str(s.get("js_files", 0)))
    tbl.add_row("Secrets:", str(s.get("secrets", 0)))
    tbl.add_row("Source maps:", str(s.get("sourcemaps", 0)))
    tbl.add_row("Report:", str(report_path))

    console.print(tbl)
    console.print()


def print_endpoint_classification(scan_targets: list[dict], console: Console) -> None:
    """Print the endpoint classification table."""
    if not scan_targets:
        return

    console.print("[bold red]  ENDPOINT CLASSIFICATION[/bold red]")

    tbl = Table(
        border_style="grey50",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    tbl.add_column("URL", style="white", min_width=40)
    tbl.add_column("Method", style="green", min_width=8)
    tbl.add_column("Params", style="red", min_width=6)

    for st in scan_targets[:20]:
        tbl.add_row(
            st["url"],
            st["method"],
            str(len(st["params"])),
        )

    console.print(tbl)

    total_params = sum(len(t["params"]) for t in scan_targets)
    console.print(
        f"  [grey70]Total endpoints: {len(scan_targets)}  |  "
        f"Total params: {total_params}[/grey70]"
    )
    console.print()


def print_finding(finding_num: int, candidate, console: Console) -> None:
    """Print a single finding card."""
    conf = candidate.confidence.upper()
    if conf == "HIGH":
        conf_style = "bold red"
    elif conf == "MEDIUM":
        conf_style = "bold white"
    else:
        conf_style = "grey70"

    scanner_name = candidate.scanner.replace("Scanner", "")

    # Finding header
    header = Text()
    header.append(f"[FINDING #{finding_num:04d}] ", style="bold white")
    header.append("CONFIRMED ", style="bold green")
    header.append(conf, style=conf_style)
    console.print(Panel(header, border_style="red", expand=False))

    # Details table
    tbl = Table(
        show_header=False,
        border_style="grey50",
        show_lines=False,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("Key", style="bold red", min_width=14)
    tbl.add_column("Value", style="white")

    tbl.add_row("Type:", scanner_name)
    tbl.add_row("Endpoint:", candidate.endpoint)
    tbl.add_row("Method:", candidate.method)

    evidence = candidate.evidence or {}
    if evidence.get("parameter"):
        tbl.add_row("Parameter:", evidence["parameter"])
    if evidence.get("payload"):
        tbl.add_row("Payload:", str(evidence["payload"]))
    if evidence.get("detail"):
        tbl.add_row("Detail:", str(evidence["detail"]))

    console.print(tbl)

    # Reproduce command
    req = candidate.request_data or {}
    if req:
        curl = _build_curl(candidate.endpoint, candidate.method, req)
        if curl:
            console.print()
            console.print("  [bold red]REPRODUCE[/bold red]")
            console.print(f"  [green]{curl}[/green]")

    # Request/Response
    if req.get("headers") or req.get("body"):
        console.print()
        console.print("  [bold grey70]REQUEST[/bold grey70]")
        if req.get("body"):
            console.print(f"  [white]{req['body'][:200]}[/white]")

    resp = candidate.response_data or {}
    if resp.get("status_code") or resp.get("body"):
        console.print()
        console.print("  [bold grey70]RESPONSE[/bold grey70]")
        if resp.get("status_code"):
            console.print(f"  [white]HTTP {resp['status_code']}[/white]")
        if resp.get("body"):
            body_preview = str(resp["body"])[:200]
            console.print(f"  [white]{body_preview}[/white]")

    console.print()


def print_scan_summary(all_candidates: list, console: Console) -> None:
    """Print the final scan results summary."""
    if not all_candidates:
        console.print(
            "[grey70]No candidate findings from scanners.[/grey70]\n"
        )
        return

    console.print("[bold green]  SCAN RESULTS[/bold green]")

    by_type: dict[str, list] = {}
    for c in all_candidates:
        name = c.scanner.replace("Scanner", "")
        by_type.setdefault(name, []).append(c)

    tbl = Table(
        border_style="grey50",
        header_style="bold white",
        show_lines=True,
        expand=False,
    )
    tbl.add_column("Scanner", style="green", min_width=20)
    tbl.add_column("Findings", style="white", min_width=10)
    tbl.add_column("High", style="red", min_width=6)
    tbl.add_column("Medium", style="white", min_width=8)
    tbl.add_column("Low", style="grey70", min_width=6)

    for name, candidates in sorted(by_type.items()):
        high = sum(1 for c in candidates if c.confidence == "high")
        med = sum(1 for c in candidates if c.confidence == "medium")
        low = sum(1 for c in candidates if c.confidence == "low")
        tbl.add_row(name, str(len(candidates)), str(high), str(med), str(low))

    console.print(tbl)
    console.print(
        f"\n  [bold green]{len(all_candidates)} candidate findings "
        f"(unverified) — run verifiers next.[/bold green]\n"
    )


def _build_curl(url: str, method: str, req: dict) -> str:
    """Build a curl reproduce command from request data."""
    parts = ["curl", "-k"]

    if method != "GET":
        parts.extend(["-X", method])

    headers = req.get("headers", {})
    for k, v in headers.items():
        parts.extend(["-H", f"'{k}: {v}'"])

    body = req.get("body")
    if body:
        parts.extend(["-d", f"'{body}'"])

    cookies = req.get("cookies", {})
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.extend(["-b", f"'{cookie_str}'"])

    parts.append(f"'{url}'")
    return " ".join(parts)
