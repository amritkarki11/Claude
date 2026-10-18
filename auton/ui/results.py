"""Rich-formatted results display for AUTON scan output.

Theme: red, white, grey, green only.
"""
from __future__ import annotations

from urllib.parse import urlencode

from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax


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

    # Show crawl errors if pages = 0
    crawl_errors = report.get("crawl_errors", [])
    if s.get("pages", 0) == 0 and crawl_errors:
        tbl.add_row("Blocked:", crawl_errors[0] if crawl_errors else "unknown")

    console.print(tbl)

    # Technology fingerprint (Wappalyzer + custom rules)
    fp = report.get("fingerprint", {})
    techs_by_cat = fp.get("technologies_by_category", {})
    technologies = fp.get("technologies", {})
    signals = fp.get("signals", [])
    waf = fp.get("waf", [])
    sec_headers = fp.get("security_headers", [])

    if technologies or signals or waf:
        console.print()
        console.print("[bold red]  TECHNOLOGY FINGERPRINT[/bold red]")

        if technologies:
            fp_tbl = Table(
                border_style="grey50",
                header_style="bold white",
                show_lines=True,
                expand=False,
            )
            fp_tbl.add_column("Category", style="bold red", min_width=22)
            fp_tbl.add_column("Technology", style="green", min_width=30)

            for cat in sorted(techs_by_cat):
                fp_tbl.add_row(cat, ", ".join(sorted(techs_by_cat[cat])))

            console.print(fp_tbl)

        # Additional signals from custom rules not in Wappalyzer
        wap_names = {t.lower().replace(" ", "-") for t in technologies}
        extra_signals = [s for s in signals if s not in wap_names]

        info_tbl = Table(
            show_header=False,
            border_style="grey50",
            show_lines=False,
            expand=False,
            padding=(0, 2),
        )
        info_tbl.add_column("Key", style="bold red", min_width=18)
        info_tbl.add_column("Value", style="white")

        if extra_signals:
            info_tbl.add_row("Extra Signals:", ", ".join(extra_signals))
        if waf:
            info_tbl.add_row("WAF:", ", ".join(waf))
        if sec_headers:
            info_tbl.add_row("Security Hdrs:", ", ".join(sec_headers))
        missing_sec = []
        for h in ["csp", "hsts", "x-frame-options", "x-content-type-options"]:
            if h not in sec_headers:
                missing_sec.append(h)
        if missing_sec:
            info_tbl.add_row("Missing Hdrs:", ", ".join(missing_sec))

        if extra_signals or waf or sec_headers or missing_sec:
            console.print(info_tbl)

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
    """Print a single finding card with full request/response and curl."""
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
    if evidence.get("technique"):
        tbl.add_row("Technique:", evidence["technique"])

    console.print(tbl)

    # Reproduce command — build full curl from request_data
    req = candidate.request_data or {}
    curl = _build_curl(candidate.endpoint, candidate.method, req)
    if curl:
        console.print()
        console.print("  [bold red]REPRODUCE[/bold red]")
        console.print(Syntax(curl, "bash", theme="monokai", line_numbers=False, word_wrap=True))

    # Full HTTP request
    full_req = req.get("full_request", "")
    if full_req:
        console.print()
        console.print(
            _truncated_panel(full_req, title="REQUEST", lexer="http")
        )
    elif req.get("headers") or req.get("body"):
        console.print()
        console.print("  [bold grey70]REQUEST[/bold grey70]")
        _print_request_fallback(req, console)

    # Full HTTP response
    resp = candidate.response_data or {}
    full_resp = resp.get("full_response", "")
    if full_resp:
        console.print()
        console.print(
            _truncated_panel(full_resp, title="RESPONSE", lexer="http")
        )
    elif resp.get("status_code") or resp.get("status") or resp.get("body") or resp.get("body_snippet"):
        console.print()
        console.print("  [bold grey70]RESPONSE[/bold grey70]")
        _print_response_fallback(resp, console)

    console.print()


_TRUNCATE_LINES = 12


def _truncated_panel(text: str, *, title: str, lexer: str) -> Panel:
    """Wrap text in a bordered Panel, truncating to _TRUNCATE_LINES."""
    lines = text.splitlines()
    total = len(lines)
    if total > _TRUNCATE_LINES:
        visible = "\n".join(lines[:_TRUNCATE_LINES])
        remaining = total - _TRUNCATE_LINES
        footer = f"\n[dim italic]… {remaining} more lines — see full report[/dim italic]"
        content = Syntax(visible, lexer, theme="monokai", line_numbers=False, word_wrap=True)
        group = Text.from_markup(footer)
        body = Group(content, group)
    else:
        body = Syntax(text, lexer, theme="monokai", line_numbers=False, word_wrap=True)

    return Panel(
        body,
        title=f"[bold grey70]{title}[/bold grey70]",
        border_style="grey50",
        padding=(0, 1),
    )


def _print_request_fallback(req: dict, console: Console) -> None:
    """Print request data from dict fields when full_request is absent."""
    if req.get("headers"):
        for k, v in req["headers"].items():
            console.print(f"  [white]{k}: {v}[/white]")
    if req.get("body"):
        console.print(f"  [white]{str(req['body'])[:500]}[/white]")


def _print_response_fallback(resp: dict, console: Console) -> None:
    """Print response data from dict fields when full_response is absent."""
    status = resp.get("status_code") or resp.get("status")
    if status:
        console.print(f"  [white]HTTP {status}[/white]")
    if resp.get("body"):
        console.print(f"  [white]{str(resp['body'])[:500]}[/white]")
    if resp.get("body_snippet"):
        console.print(f"  [white]{str(resp['body_snippet'])[:500]}[/white]")


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
    """Build a complete curl reproduce command from request data.

    Uses scanner request_data fields: param, payload, id_location,
    sibling_fields, headers, body, cookies, form_data.
    """
    parts = ["curl", "-k", "-v"]

    if method != "GET":
        parts.extend(["-X", method])

    # Headers from request_data
    headers = req.get("headers", {})
    for k, v in headers.items():
        parts.extend(["-H", f"'{k}: {v}'"])

    # Build the payload body/query from scanner-specific fields
    param = req.get("param") or req.get("parameter") or req.get("id_param", "")
    payload = req.get("payload") or req.get("payload_true") or req.get("id_value", "")
    id_location = req.get("id_location", "query")
    siblings = req.get("sibling_fields") or req.get("siblings") or {}

    # form_data from CSRF scanner
    form_data = req.get("form_data")

    if form_data:
        # CSRF-style: we have the full form_data dict
        if "Content-Type" not in {k.lower(): k for k in headers}:
            parts.extend(["-H", "'Content-Type: application/x-www-form-urlencoded'"])
        body_str = urlencode(form_data)
        parts.extend(["-d", f"'{body_str}'"])
    elif param and payload:
        # Scanner gave us param + payload + siblings
        form_fields = dict(siblings)
        form_fields[param] = payload

        if id_location == "body" or method == "POST":
            if "Content-Type" not in {h for h in headers}:
                parts.extend(["-H", "'Content-Type: application/x-www-form-urlencoded'"])
            body_str = urlencode(form_fields)
            parts.extend(["-d", f"'{body_str}'"])
        else:
            qs = urlencode(form_fields)
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{qs}"
    elif req.get("body"):
        # Raw body string
        body = str(req["body"])
        parts.extend(["-d", f"'{body}'"])

    # Cookies
    cookies = req.get("cookies", {})
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.extend(["-b", f"'{cookie_str}'"])

    parts.append(f"'{url}'")
    return " ".join(parts)
