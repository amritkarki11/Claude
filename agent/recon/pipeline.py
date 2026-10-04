"""Recon pipeline: crawl -> JS endpoint extraction -> source-map detection.

Chains the existing recon modules and writes one combined JSON report.
Every request goes through the scope-gated HttpClient; JS files outside
scope are skipped (recorded under `skipped_js`), never fetched.
"""
from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone

import httpx

from ..http import HttpClient, Session
from ..scope import ScopeError, host_of, in_scope
from .crawler import crawl
from .js_extractor import extract_endpoints
from .secret_scanner import scan_files
from .sourcemap_detector import detect_sourcemaps

DEFAULT_OUT_DIR = pathlib.Path("outputs")


async def run_recon(
    client: HttpClient,
    seed_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 100,
    session: Session | None = None,
) -> dict:
    """Run the full recon chain and return the combined report dict."""
    bodies: dict[str, str] = {}  # url -> already-fetched HTML/JS, reused by the secret scan
    crawled = await crawl(
        client, seed_url, max_depth=max_depth, max_pages=max_pages, session=session, bodies=bodies
    )

    js_urls = [u for u in crawled["script_urls"] if in_scope(u)]
    skipped_js = [u for u in crawled["script_urls"] if not in_scope(u)]

    endpoints: list[dict] = []
    for js in js_urls:
        try:
            resp = await client.get(js, session=session)
            resp.raise_for_status()
        except (ScopeError, httpx.HTTPError):
            skipped_js.append(js)
            continue
        bodies[js] = resp.text
        endpoints.extend({**e, "source": js} for e in extract_endpoints(resp.text))

    sourcemaps = await detect_sourcemaps(client, seed_url, js_urls, session=session)

    secrets = scan_files(bodies)  # final step: offline scan of every fetched body

    return {
        "seed": seed_url,
        "host": host_of(seed_url),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages_crawled": crawled["pages_crawled"],
        "forms": crawled["forms"],
        "js_urls": js_urls,
        "skipped_js": skipped_js,
        "endpoints": endpoints,
        "sourcemaps": sourcemaps,
        "secrets": secrets,
        "summary": {
            "secrets": len(secrets),
            "pages": len(crawled["pages_crawled"]),
            "forms": len(crawled["forms"]),
            "js_files": len(js_urls),
            "endpoints": len(endpoints),
            "params": sum(len(e["params"]) for e in endpoints),
            "sourcemaps": len(sourcemaps),
            "sources_exposed": sum(m["source_count"] for m in sourcemaps),
        },
    }


def write_report(report: dict, out_dir: pathlib.Path | str = DEFAULT_OUT_DIR) -> pathlib.Path:
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = report["host"].replace(":", "_") or "unknown"
    path = out / f"recon_{host}_{stamp}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def format_summary(report: dict, path: pathlib.Path) -> str:
    s = report["summary"]
    return (
        f"[recon] {report['host']}: {s['pages']} pages, {s['forms']} forms, "
        f"{s['js_files']} JS files, {s['endpoints']} endpoints ({s['params']} params), "
        f"{s['sourcemaps']} exposed source maps ({s['sources_exposed']} sources), "
        f"{s['secrets']} potential secrets\n"
        f"[recon] report: {path}"
    )
