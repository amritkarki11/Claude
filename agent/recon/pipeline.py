"""Recon pipeline: crawl -> JS endpoint extraction -> source-map detection.

Chains the existing recon modules and writes one combined JSON report.
Every request goes through the scope-gated HttpClient; JS files outside
scope are skipped (recorded under `skipped_js`), never fetched.
"""
from __future__ import annotations

import json
import pathlib
import re
from datetime import datetime, timezone

import httpx
from urllib.parse import urldefrag, urljoin, urlsplit

from ..http import HttpClient, Session
from ..scope import ScopeError, host_of, in_scope
from .crawler import crawl
from .dns_recon import dns_records
from .js_extractor import extract_endpoints
from .secret_scanner import scan_files
from .sourcemap_detector import detect_sourcemaps

DEFAULT_OUT_DIR = pathlib.Path("outputs")
DEFAULT_MAX_JS_FILES = 50

# Quoted JS path strings: dynamic import("./x.js"), Vite __vite__mapDeps entries, "assets/x-HASH.js".
_CHUNK_REF = re.compile(
    r"""["'`]((?:\./|\.\./|/)?(?:[\w.\-]+/)*[\w.\-]+\.m?js)(?:\?[^"'`\s]*)?["'`]"""
)


def extract_chunk_refs(js_text: str, js_url: str) -> list[str]:
    """Absolute URLs of JS chunks referenced from `js_text`, resolved against `js_url`.

    Only strings that look like chunk references are taken: `assets/...js`, relative
    `./x.js` / `../x.js`, or bare names inside `import(...)` / `__vite__mapDeps`.
    """
    cands: list[str] = []
    for m in re.finditer(r"""\bimport\(\s*["'`]([^"'`]+?\.m?js)["'`]\s*\)""", js_text):
        cands.append(m.group(1))
    for m in re.finditer(r"__vite__mapDeps|\bm\.f=", js_text):
        # mapDeps array literal: [...] of quoted paths near the marker
        seg = js_text[m.start(): m.start() + 20000]
        arr = re.search(r"\[((?:\s*[\"'][^\"']+[\"']\s*,?)+)\]", seg)
        if arr:
            cands += re.findall(r"""["']([^"']+?\.m?js)["']""", arr.group(1))
    for m in _CHUNK_REF.finditer(js_text):
        ref = m.group(1)
        if ref.startswith((".", "/")) or "assets/" in ref:
            cands.append(ref)
    out: list[str] = []
    for c in cands:
        url = urldefrag(urljoin(js_url, c))[0]
        if url not in out:
            out.append(url)
    return out


async def run_recon(
    client: HttpClient,
    seed_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 100,
    max_js_files: int = DEFAULT_MAX_JS_FILES,
    session: Session | None = None,
    include_dns: bool = False,
    dns_resolver=None,
) -> dict:
    """Run the full recon chain and return the combined report dict."""
    bodies: dict[str, str] = {}  # url -> already-fetched HTML/JS, reused by the secret scan
    crawled = await crawl(
        client, seed_url, max_depth=max_depth, max_pages=max_pages, session=session, bodies=bodies
    )

    js_urls = [u for u in crawled["script_urls"] if in_scope(u)]
    skipped_js = [u for u in crawled["script_urls"] if not in_scope(u)]

    endpoints: list[dict] = []
    queue = list(js_urls)
    seen = set(queue)  # every JS URL ever queued -> each chunk is fetched once
    js_urls = []       # JS files actually fetched, in scope
    while queue and len(js_urls) < max_js_files:
        js = queue.pop(0)
        try:
            resp = await client.get(js, session=session)
            resp.raise_for_status()
        except (ScopeError, httpx.HTTPError):
            skipped_js.append(js)
            continue
        js_urls.append(js)
        bodies[js] = resp.text
        endpoints.extend({**e, "source": js} for e in extract_endpoints(resp.text))
        for ref in extract_chunk_refs(resp.text, js):
            if ref in seen:
                continue
            seen.add(ref)
            if urlsplit(ref).netloc == urlsplit(js).netloc and in_scope(ref):  # same-origin + scope
                queue.append(ref)
            else:
                skipped_js.append(ref)
    skipped_js.extend(u for u in queue if u not in skipped_js)  # left over once the cap was hit

    sourcemaps = await detect_sourcemaps(client, seed_url, js_urls, session=session)

    secrets = scan_files(bodies)  # final step: offline scan of every fetched body

    dns = {}
    if include_dns and in_scope(seed_url):
        dns[host_of(seed_url)] = await dns_records(host_of(seed_url), dns_resolver)

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
        "dns": dns,
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
