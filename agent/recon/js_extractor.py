"""Extract API endpoints and parameter names from JavaScript source.

Pure-regex, no JS parsing: finds fetch/axios/$.ajax/XHR calls, route
definitions (express-style and `{path: "..."}` objects) and generic
URL-like string literals. Fetching a script by URL goes through
agent.http.HttpClient, so it is scope-gated like everything else.

Output: list of {"path": str, "method": str | None, "params": [str, ...]}.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from ..http import HttpClient, Session

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_M = "|".join(_METHODS)

# A string literal: '...' "..." or `...` (no escaped-quote handling; good enough for recon)
_STR = r"""(?:'([^'\n]*)'|"([^"\n]*)"|`([^`\n]*)`)"""

_RE_AXIOS_VERB = re.compile(
    rf"""\b(?:axios|http|api|client|request|\$http|\$)\s*\.\s*({_M})\s*\(\s*{_STR}""", re.I
)
_RE_ROUTE_VERB = re.compile(
    rf"""\b(?:app|router|route|server|r)\s*\.\s*({_M})\s*\(\s*{_STR}""", re.I
)
_RE_XHR_OPEN = re.compile(rf"""\.open\s*\(\s*['"]({_M})['"]\s*,\s*{_STR}""", re.I)
_RE_FETCH = re.compile(rf"""\bfetch\s*\(\s*{_STR}""")
_RE_CALL_OBJ = re.compile(r"""\b(?:axios|\$\.ajax|\$http|request)\s*\(\s*\{""")
_RE_URL_KEY = re.compile(rf"""\b(?:url|path|endpoint|uri)\s*:\s*{_STR}""")
_RE_METHOD_KEY = re.compile(r"""\b(?:method|type)\s*:\s*['"]([A-Za-z]+)['"]""")
_RE_GENERIC = re.compile(
    r"""['"`]((?:https?:)?//[^\s'"`<>]+|/[A-Za-z0-9_\-.~%:@${}\[\]/?&=+]*[A-Za-z][A-Za-z0-9_\-.~%:@${}\[\]/?&=+]*)['"`]"""
)

_STATIC_EXT = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|mp[34]|webm|webp|pdf|html?|txt)$",
    re.I,
)
_TPL = re.compile(r"\$\{[^}]*\}")
_BODY_KEYS = re.compile(r"""(?<![\w$.])['"]?([A-Za-z_][\w-]*)['"]?\s*:""")


def _first(groups: tuple[str | None, ...]) -> str | None:
    return next((g for g in groups if g is not None), None)


def _balanced(src: str, open_idx: int) -> str:
    """Return the {...} / (...) block starting at open_idx (bounded, tolerant of EOF)."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    depth, limit = 0, min(len(src), open_idx + 2000)
    for i in range(open_idx, limit):
        c = src[i]
        if c in pairs:
            depth += 1
        elif c in pairs.values():
            depth -= 1
            if depth == 0:
                return src[open_idx : i + 1]
    return src[open_idx:limit]


def _normalize(raw: str) -> tuple[str, list[str]] | None:
    """Split a URL-ish literal into (path, params); None if it isn't an endpoint."""
    raw = raw.strip()
    if not raw or any(c.isspace() for c in raw):
        return None
    params: list[str] = []
    if raw.startswith(("http://", "https://", "//")):
        p = urlparse(raw if not raw.startswith("//") else "https:" + raw)
        path, query = p.path or "/", p.query
    else:
        path, _, query = raw.partition("?")
        path = path.split("#", 1)[0]
    # Template placeholders `${id}` become {id}; the name is also a path param.
    for m in _TPL.finditer(path):
        name = re.sub(r"[^\w]", "", m.group(0)[2:-1].split(".")[-1]) or "param"
        params.append(name)
    path = _TPL.sub(lambda m: "{" + (re.sub(r"[^\w]", "", m.group(0)[2:-1].split(".")[-1]) or "param") + "}", path)
    if not path.startswith("/") or path == "/" or _STATIC_EXT.search(path):
        return None
    if "//" in path.lstrip("/") and not path.startswith("/{"):
        path = re.sub(r"/{2,}", "/", path)
    for k, _ in parse_qsl(_TPL.sub("x", query), keep_blank_values=True):
        params.append(k)
    return path, params


def _body_params(block: str) -> list[str]:
    # Keys of the object literal(s) in a request's data/body/params argument.
    keys: list[str] = []
    for m in re.finditer(r"""\b(?:data|body|params|json)\s*:\s*(?:JSON\.stringify\s*\(\s*)?\{""", block):
        keys += _BODY_KEYS.findall(_balanced(block, m.end() - 1)[1:-1])
    return keys


class _Collector:
    def __init__(self) -> None:
        # (method, path) -> params (dict used as an ordered set)
        self._eps: dict[tuple[str | None, str], dict[str, None]] = {}

    def add(self, raw: str | None, method: str | None = None, params: list[str] | None = None) -> None:
        if raw is None:
            return
        norm = _normalize(raw)
        if norm is None:
            return
        path, qparams = norm
        method = method.upper() if method else None
        found = dict.fromkeys(qparams + (params or []))
        if method is None:
            # A method-less hit is folded into any method-bearing one for the same path.
            known = [k for k in self._eps if k[1] == path and k[0]]
            if known:
                for k in known:
                    self._eps[k].update(found)
                return
        else:
            # Upgrade an earlier method-less record for this path.
            found = {**self._eps.pop((None, path), {}), **found}
        self._eps.setdefault((method, path), {}).update(found)

    def result(self) -> list[dict]:
        return sorted(
            ({"path": p, "method": m, "params": sorted(ps)} for (m, p), ps in self._eps.items()),
            key=lambda e: (e["path"], e["method"] or ""),
        )


def extract_endpoints(js: str) -> list[dict]:
    """Extract normalized endpoints from JS source text."""
    col = _Collector()

    for m in _RE_AXIOS_VERB.finditer(js):
        tail = _balanced(js, js.find("(", m.start())) if "(" in js[m.start():m.end()] else ""
        col.add(_first(m.groups()[1:]), m.group(1), _body_params(tail) + _simple_second_arg(tail))
    for m in _RE_ROUTE_VERB.finditer(js):
        col.add(_first(m.groups()[1:]), m.group(1))
    for m in _RE_XHR_OPEN.finditer(js):
        col.add(_first(m.groups()[1:]), m.group(1))
    for m in _RE_FETCH.finditer(js):
        tail = _balanced(js, js.find("(", m.start()))
        mm = _RE_METHOD_KEY.search(tail)
        body = re.search(r"""\bbody\s*:\s*JSON\.stringify\s*\(\s*\{""", tail)
        params = _BODY_KEYS.findall(_balanced(tail, body.end() - 1)[1:-1]) if body else []
        col.add(_first(m.groups()), mm.group(1) if mm else "GET", params)
    for m in _RE_CALL_OBJ.finditer(js):
        block = _balanced(js, m.end() - 1)
        u = _RE_URL_KEY.search(block)
        mm = _RE_METHOD_KEY.search(block)
        if u:
            col.add(_first(u.groups()), mm.group(1) if mm else None, _body_params(block))
    for m in _RE_URL_KEY.finditer(js):
        col.add(_first(m.groups()))
    for m in _RE_GENERIC.finditer(js):
        col.add(m.group(1))
    return col.result()


def _simple_second_arg(call: str) -> list[str]:
    # axios.post(url, {a: 1, b: 2}) -> a, b
    m = re.search(r"""^\(\s*{s}\s*,\s*\{{""".format(s=_STR), call)
    return _BODY_KEYS.findall(_balanced(call, m.end() - 1)[1:-1]) if m else []


async def extract_from_url(
    client: HttpClient, url: str, *, session: Session | None = None
) -> list[dict]:
    """Fetch a JS file through the scope-gated client (raises ScopeError if
    the host is out of scope) and extract its endpoints."""
    resp = await client.get(url, session=session)
    resp.raise_for_status()
    return extract_endpoints(resp.text)
