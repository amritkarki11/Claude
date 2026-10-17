"""Tests for the HTML Crawler (Phase 2.1).

Covers:
  - Link extraction from <a href> tags
  - Form discovery with fields, methods, actions
  - Data attribute URL extraction
  - Meta redirect following
  - Noise filtering (static assets, non-http schemes)
  - URL normalization and deduplication
  - Scope enforcement
  - Same-origin restriction
  - Depth limiting
  - Max pages limiting
  - Title extraction
  - End-to-end crawl with mock HTTP
  - CrawlResult aggregation methods
"""
from __future__ import annotations

import pytest
import httpx

from agent.recon.crawler import (
    Crawler,
    CrawledPage,
    CrawlResult,
    DiscoveredForm,
    FormField,
)
from agent.http import HttpClient, Session
from agent.scope import add_to_scope, ALLOWED


# ── Helpers ────────────────────────────────────────────────────


def _crawler(**kw) -> Crawler:
    """Create a Crawler without HTTP client for parse-only tests."""
    return Crawler(
        client=None,  # type: ignore
        base_url=kw.pop("base_url", "https://example.com"),
        **kw,
    )


def _parse(html: str, page_url: str = "https://example.com/page") -> CrawledPage:
    """Shortcut: parse HTML into CrawledPage."""
    c = _crawler()
    return c.parse_page(html, page_url)


# ── Link extraction tests ─────────────────────────────────────


class TestLinkExtraction:
    def test_basic_links(self):
        html = '''
        <a href="/dashboard">Dashboard</a>
        <a href="/settings/profile">Profile</a>
        <a href="https://example.com/about">About</a>
        '''
        page = _parse(html)
        assert "https://example.com/dashboard" in page.links
        assert "https://example.com/settings/profile" in page.links
        assert "https://example.com/about" in page.links

    def test_relative_links_resolved(self):
        html = '<a href="subpage">Sub</a>'
        page = _parse(html, "https://example.com/app/")
        assert "https://example.com/app/subpage" in page.links

    def test_fragment_stripped(self):
        html = '<a href="/page#section">Link</a>'
        page = _parse(html)
        links = page.links
        assert any("/page" in l and "#" not in l for l in links)

    def test_duplicate_links_deduped(self):
        html = '''
        <a href="/users">Users</a>
        <a href="/users">Users Again</a>
        <a href="/users">Users Third</a>
        '''
        page = _parse(html)
        user_links = [l for l in page.links if "/users" in l]
        assert len(user_links) == 1

    def test_javascript_href_skipped(self):
        html = '<a href="javascript:void(0)">Click</a>'
        page = _parse(html)
        assert len(page.links) == 0

    def test_mailto_skipped(self):
        html = '<a href="mailto:test@example.com">Email</a>'
        page = _parse(html)
        assert len(page.links) == 0

    def test_tel_skipped(self):
        html = '<a href="tel:+1234567890">Call</a>'
        page = _parse(html)
        assert len(page.links) == 0


# ── Form extraction tests ─────────────────────────────────────


class TestFormExtraction:
    def test_basic_form(self):
        html = '''
        <form action="/api/login" method="POST">
            <input name="username" type="text">
            <input name="password" type="password">
            <input type="submit" name="submit" value="Login">
        </form>
        '''
        page = _parse(html)
        assert len(page.forms) == 1
        form = page.forms[0]
        assert form.action == "https://example.com/api/login"
        assert form.method == "POST"
        assert "username" in form.param_names
        assert "password" in form.param_names
        # Submit button should be filtered out
        assert "submit" not in form.param_names

    def test_form_default_get(self):
        html = '''
        <form action="/search">
            <input name="q" type="text">
        </form>
        '''
        page = _parse(html)
        assert page.forms[0].method == "GET"

    def test_form_no_action_uses_page_url(self):
        html = '''
        <form method="POST">
            <input name="data" type="text">
        </form>
        '''
        page = _parse(html, "https://example.com/current")
        assert page.forms[0].action == "https://example.com/current"

    def test_textarea_and_select(self):
        html = '''
        <form action="/feedback" method="POST">
            <textarea name="message"></textarea>
            <select name="category">
                <option value="bug">Bug</option>
            </select>
            <input name="email" type="email">
        </form>
        '''
        page = _parse(html)
        form = page.forms[0]
        assert "message" in form.param_names
        assert "category" in form.param_names
        assert "email" in form.param_names

    def test_form_field_types(self):
        html = '''
        <form action="/register" method="POST">
            <input name="name" type="text">
            <input name="email" type="email" required>
            <input name="age" type="number">
            <input name="hidden_field" type="hidden">
        </form>
        '''
        page = _parse(html)
        form = page.forms[0]
        fields_by_name = {f.name: f for f in form.fields}
        assert fields_by_name["email"].input_type == "email"
        assert fields_by_name["email"].required is True
        assert fields_by_name["age"].input_type == "number"
        assert "hidden_field" in fields_by_name  # hidden fields are kept

    def test_multiple_forms(self):
        html = '''
        <form action="/search" method="GET">
            <input name="q" type="text">
        </form>
        <form action="/login" method="POST">
            <input name="user" type="text">
            <input name="pass" type="password">
        </form>
        '''
        page = _parse(html)
        assert len(page.forms) == 2


# ── Data attribute tests ──────────────────────────────────────


class TestDataAttributes:
    def test_data_url(self):
        html = '<div data-url="/api/users/list"></div>'
        page = _parse(html)
        assert any("/api/users/list" in u for u in page.data_urls)

    def test_data_api(self):
        html = '<div data-api="/api/config"></div>'
        page = _parse(html)
        assert any("/api/config" in u for u in page.data_urls)

    def test_data_endpoint(self):
        html = '<button data-endpoint="/api/delete/item">Delete</button>'
        page = _parse(html)
        assert any("/api/delete/item" in u for u in page.data_urls)

    def test_data_action(self):
        html = '<div data-action="/api/submit"></div>'
        page = _parse(html)
        assert any("/api/submit" in u for u in page.data_urls)


# ── Meta redirect tests ───────────────────────────────────────


class TestMetaRedirect:
    def test_meta_redirect_found(self):
        html = '<meta http-equiv="refresh" content="0;url=/new-page">'
        page = _parse(html)
        assert any("/new-page" in l for l in page.links)

    def test_meta_redirect_absolute(self):
        html = '<meta http-equiv="refresh" content="5;url=https://example.com/redirected">'
        page = _parse(html)
        assert "https://example.com/redirected" in page.links


# ── Noise filtering tests ─────────────────────────────────────


class TestNoiseFiltering:
    def test_static_assets_skipped(self):
        html = '''
        <a href="/images/logo.png">Logo</a>
        <a href="/style.css">CSS</a>
        <a href="/app.js">JS</a>
        <a href="/font.woff2">Font</a>
        <a href="/report.pdf">PDF</a>
        '''
        page = _parse(html)
        assert len(page.links) == 0

    def test_non_asset_links_kept(self):
        html = '''
        <a href="/dashboard">Dashboard</a>
        <a href="/api/users">Users</a>
        '''
        page = _parse(html)
        assert len(page.links) == 2


# ── URL normalization tests ────────────────────────────────────


class TestUrlNormalization:
    def test_canonical_lowercase_host(self):
        c = _crawler()
        assert "example.com" in c._canonical("https://EXAMPLE.COM/path")

    def test_canonical_strips_fragment(self):
        c = _crawler()
        canonical = c._canonical("https://example.com/page#section")
        assert "#" not in canonical

    def test_canonical_strips_trailing_slash(self):
        c = _crawler()
        c1 = c._canonical("https://example.com/page/")
        c2 = c._canonical("https://example.com/page")
        assert c1 == c2

    def test_canonical_sorts_params(self):
        c = _crawler()
        c1 = c._canonical("https://example.com/s?b=2&a=1")
        c2 = c._canonical("https://example.com/s?a=1&b=2")
        assert c1 == c2

    def test_root_slash_kept(self):
        c = _crawler()
        canonical = c._canonical("https://example.com/")
        assert canonical.endswith("/")


# ── Title extraction ───────────────────────────────────────────


class TestTitleExtraction:
    def test_basic_title(self):
        page = _parse("<html><head><title>My App</title></head></html>")
        assert page.title == "My App"

    def test_no_title(self):
        page = _parse("<html><head></head></html>")
        assert page.title == ""


# ── Scope and origin tests ────────────────────────────────────


class TestScopeAndOrigin:
    def test_in_scope_url_allowed(self):
        add_to_scope("example.com")
        c = _crawler(base_url="https://example.com")
        assert c._should_visit("https://example.com/page") is True

    def test_out_of_scope_url_blocked(self):
        c = _crawler(base_url="https://example.com")
        assert c._should_visit("https://evil.com/page") is False

    def test_same_origin_blocks_different_host(self):
        add_to_scope("other.com")
        c = _crawler(base_url="https://example.com", same_origin_only=True)
        assert c._should_visit("https://other.com/page") is False

    def test_same_origin_off_allows_different_host(self):
        add_to_scope("other.com")
        c = _crawler(base_url="https://example.com", same_origin_only=False)
        assert c._should_visit("https://other.com/page") is True

    def test_static_assets_not_visited(self):
        add_to_scope("example.com")
        c = _crawler(base_url="https://example.com")
        assert c._should_visit("https://example.com/logo.png") is False
        assert c._should_visit("https://example.com/style.css") is False


# ── CrawlResult aggregation ───────────────────────────────────


class TestCrawlResult:
    def test_all_links_deduped(self):
        result = CrawlResult(
            base_url="https://example.com",
            pages=[
                CrawledPage(url="/a", links=["https://example.com/x", "https://example.com/y"]),
                CrawledPage(url="/b", links=["https://example.com/y", "https://example.com/z"]),
            ],
        )
        assert result.all_links == [
            "https://example.com/x",
            "https://example.com/y",
            "https://example.com/z",
        ]

    def test_all_forms(self):
        result = CrawlResult(
            base_url="https://example.com",
            pages=[
                CrawledPage(url="/a", forms=[
                    DiscoveredForm(action="/login", method="POST"),
                ]),
                CrawledPage(url="/b", forms=[
                    DiscoveredForm(action="/search", method="GET"),
                    DiscoveredForm(action="/signup", method="POST"),
                ]),
            ],
        )
        assert len(result.all_forms) == 3

    def test_summary(self):
        result = CrawlResult(
            base_url="https://example.com",
            urls_visited=5,
            urls_skipped=2,
            forms_found=3,
        )
        s = result.summary()
        assert s["pages_visited"] == 5
        assert s["forms_found"] == 3


# ── End-to-end with mock HTTP ─────────────────────────────────


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_basic_crawl(self):
        """BFS crawl: index → /about and /users → /users/1."""
        pages = {
            "https://example.com/": '''
                <html><head><title>Home</title></head>
                <body>
                    <a href="/about">About</a>
                    <a href="/users">Users</a>
                </body></html>
            ''',
            "https://example.com/about": '''
                <html><head><title>About</title></head>
                <body><p>About page</p></body></html>
            ''',
            "https://example.com/users": '''
                <html><head><title>Users</title></head>
                <body>
                    <a href="/users/1">User 1</a>
                    <form action="/users/search" method="GET">
                        <input name="q" type="text">
                        <input name="role" type="text">
                    </form>
                </body></html>
            ''',
            "https://example.com/users/1": '''
                <html><head><title>User Detail</title></head>
                <body><p>User 1 profile</p></body></html>
            ''',
        }

        async def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url).rstrip("/")
            if not url.endswith("/") and url + "/" not in pages:
                pass
            html = pages.get(str(request.url), pages.get(str(request.url).rstrip("/"), ""))
            if html:
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return httpx.Response(404, text="Not found", headers={"content-type": "text/html"})

        transport = httpx.MockTransport(handler)
        client = HttpClient(transport=transport)
        add_to_scope("example.com")

        try:
            crawler = Crawler(client, base_url="https://example.com/", max_depth=3)
            result = await crawler.crawl()

            assert result.urls_visited >= 3  # at least index, about, users
            assert result.forms_found >= 1

            # Check forms
            forms = result.all_forms
            search_forms = [f for f in forms if "/search" in f.action]
            assert search_forms
            assert "q" in search_forms[0].param_names

        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_depth_limit(self):
        """Crawler respects max_depth."""
        pages = {
            "https://example.com/": '<a href="/level1">L1</a>',
            "https://example.com/level1": '<a href="/level2">L2</a>',
            "https://example.com/level2": '<a href="/level3">L3</a>',
            "https://example.com/level3": '<p>Deep</p>',
        }

        async def handler(request: httpx.Request) -> httpx.Response:
            html = pages.get(str(request.url), "")
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})

        transport = httpx.MockTransport(handler)
        client = HttpClient(transport=transport)
        add_to_scope("example.com")

        try:
            crawler = Crawler(client, base_url="https://example.com/", max_depth=1)
            result = await crawler.crawl()

            visited_urls = [p.url for p in result.pages]
            # depth=0 is index, depth=1 is level1, level2 should NOT be visited
            assert any("level1" in u for u in visited_urls)
            assert not any("level3" in u for u in visited_urls)

        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_max_pages_limit(self):
        """Crawler stops after max_pages."""
        html = "".join(f'<a href="/page{i}">P{i}</a>' for i in range(50))

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})

        transport = httpx.MockTransport(handler)
        client = HttpClient(transport=transport)
        add_to_scope("example.com")

        try:
            crawler = Crawler(client, base_url="https://example.com/", max_pages=5)
            result = await crawler.crawl()
            assert result.urls_visited <= 5

        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_non_html_not_parsed(self):
        """Non-HTML responses should not be parsed for links."""

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text='{"url": "/api/data"}',
                headers={"content-type": "application/json"},
            )

        transport = httpx.MockTransport(handler)
        client = HttpClient(transport=transport)
        add_to_scope("example.com")

        try:
            crawler = Crawler(client, base_url="https://example.com/api")
            result = await crawler.crawl()
            assert result.urls_visited == 1
            assert len(result.pages[0].links) == 0
            assert len(result.pages[0].forms) == 0

        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Network errors are recorded, not raised."""

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(handler)
        client = HttpClient(transport=transport)
        add_to_scope("example.com")

        try:
            crawler = Crawler(client, base_url="https://example.com/")
            result = await crawler.crawl()
            assert result.urls_visited == 1
            assert len(result.errors) == 1
            assert "Connection refused" in result.errors[0]

        finally:
            await client.aclose()
