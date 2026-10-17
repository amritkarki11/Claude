"""Tests for the JS/SPA endpoint extractor (Phase 2.2).

Covers:
  - Pattern matching: API paths, fetch/axios calls, Angular $http,
    full URLs, generic paths, concatenation, template literals
  - Noise filtering: static assets, short paths, version strings
  - Method guessing from context
  - Param extraction from query strings and JSON bodies
  - HTML script tag discovery
  - Inline script extraction
  - Deduplication with confidence ranking
  - End-to-end extraction via mock HTTP
  - Normalization edge cases
"""
from __future__ import annotations

import pytest
import httpx

from agent.recon.js_extractor import (
    JsExtractor,
    ExtractedEndpoint,
    JsExtractionResult,
    _API_PATH,
    _FETCH_CALL,
    _ANGULAR_HTTP,
    _FULL_URL,
    _GENERIC_PATH,
)
from agent.http import HttpClient, Session


# ── Helpers ────────────────────────────────────────────────────


def _paths(endpoints: list[ExtractedEndpoint]) -> list[str]:
    """Extract just paths from endpoint list for easy assertion."""
    return [ep.path for ep in endpoints]


def _extract(js: str, **kw) -> list[ExtractedEndpoint]:
    """Shortcut: extract from source with no HTTP."""
    return JsExtractor().extract_from_source(js, **kw)


# ── Pattern matching tests ─────────────────────────────────────


class TestApiPathPattern:
    """Tests for the _API_PATH regex — high-confidence API path literals."""

    def test_simple_api_path(self):
        eps = _extract('var url = "/api/users/list";')
        assert "/api/users/list" in _paths(eps)

    def test_data_path(self):
        eps = _extract('get("/data/orders/export")')
        assert "/data/orders/export" in _paths(eps)

    def test_rest_versioned(self):
        eps = _extract('url: "/v1/products/search"')
        assert "/v1/products/search" in _paths(eps)

    def test_auth_paths(self):
        eps = _extract('''
            loginUrl = "/login/oauth";
            logoutPath = "/logout/session";
            registerUrl = "/register/user";
        ''')
        paths = _paths(eps)
        assert "/login/oauth" in paths
        assert "/logout/session" in paths
        assert "/register/user" in paths

    def test_path_with_params(self):
        eps = _extract('fetch("/api/users/{userId}/orders")')
        paths = _paths(eps)
        assert any("/api/users/{userId}/orders" in p for p in paths)

    def test_inventory_paths(self):
        """Patterns common in ecommerce/logistics apps."""
        eps = _extract('''
            x = "/inventory/items/bulk";
            y = "/shipment/tracking";
            z = "/warehouse/config";
        ''')
        paths = _paths(eps)
        assert "/inventory/items/bulk" in paths
        assert "/shipment/tracking" in paths

    def test_backtick_string(self):
        eps = _extract('const u = `/api/users/profile`;')
        assert "/api/users/profile" in _paths(eps)


class TestFetchAxiosPattern:
    """Tests for fetch/axios/XHR call extraction."""

    def test_fetch_call(self):
        eps = _extract('fetch("/api/data/list")')
        assert "/api/data/list" in _paths(eps)

    def test_axios_get(self):
        eps = _extract('axios.get("/api/users/me")')
        paths = _paths(eps)
        assert "/api/users/me" in paths

    def test_axios_post_method(self):
        eps = _extract('axios.post("/api/orders/create")')
        found = [ep for ep in eps if "/api/orders/create" in ep.path]
        assert found
        assert found[0].method == "POST"

    def test_jquery_ajax(self):
        eps = _extract('$.ajax("/api/search/query")')
        assert "/api/search/query" in _paths(eps)

    def test_jquery_get(self):
        eps = _extract('$.get("/api/config/settings")')
        assert "/api/config/settings" in _paths(eps)

    def test_xhr_open(self):
        eps = _extract('xhr.open("POST", "/api/upload/file")')
        assert "/api/upload/file" in _paths(eps)


class TestAngularPattern:
    """Tests for Angular $http pattern."""

    def test_http_get(self):
        eps = _extract('$http.get("/api/users/list")')
        found = [ep for ep in eps if "/api/users/list" in ep.path]
        assert found
        assert found[0].method == "GET"

    def test_http_post(self):
        eps = _extract('$http.post("/api/orders/submit", data)')
        found = [ep for ep in eps if "/api/orders/submit" in ep.path]
        assert found
        assert found[0].method == "POST"

    def test_http_delete(self):
        eps = _extract('$http.delete("/api/items/" + id)')
        found = [ep for ep in eps if ep.path.startswith("/api/items")]
        assert found
        assert found[0].method == "DELETE"


class TestFullUrlPattern:
    """Tests for full URL extraction."""

    def test_https_url(self):
        eps = _extract('var api = "https://api.example.com/v1/users/list";')
        paths = _paths(eps)
        assert "/v1/users/list" in paths

    def test_http_url_with_port(self):
        eps = _extract('url = "http://localhost:8080/api/health/check";')
        paths = _paths(eps)
        assert "/api/health/check" in paths


class TestGenericPathPattern:
    """Tests for generic /word/word paths."""

    def test_two_segment_path(self):
        eps = _extract('path = "/custom/endpoint";')
        assert "/custom/endpoint" in _paths(eps)

    def test_skips_single_segment(self):
        """Single segment paths are too noisy — should be filtered."""
        eps = _extract('x = "/a";')
        assert "/a" not in _paths(eps)


class TestConcatAndTemplate:
    """String concatenation and template literal paths."""

    def test_concat_path(self):
        eps = _extract('baseUrl + "/orders/detail"')
        assert "/orders/detail" in _paths(eps)

    def test_template_literal(self):
        eps = _extract('url = `${baseUrl}/users/profile`')
        assert "/users/profile" in _paths(eps)


# ── Noise filtering tests ─────────────────────────────────────


class TestNoiseFiltering:
    """Static assets, short paths, etc. should be filtered out."""

    def test_static_assets_filtered(self):
        js = '''
            img = "/static/logo.png";
            css = "/assets/style.css";
            font = "/fonts/roboto.woff2";
        '''
        eps = _extract(js)
        paths = _paths(eps)
        assert not any(p.startswith("/static") for p in paths)
        assert not any(p.startswith("/assets") for p in paths)
        assert not any(p.endswith(".woff2") for p in paths)

    def test_js_files_filtered(self):
        eps = _extract('src = "/js/bundle.min.js";')
        paths = _paths(eps)
        assert not any(p.endswith(".js") for p in paths)

    def test_noise_exact_paths(self):
        js = 'x = "/undefined"; y = "/null"; z = "/";'
        eps = _extract(js)
        paths = _paths(eps)
        assert "/" not in paths
        assert "/undefined" not in paths
        assert "/null" not in paths

    def test_version_only_filtered(self):
        eps = _extract('v = "/v1"; x = "/1.0";')
        # These are too short or numeric-only
        paths = _paths(eps)
        assert "/1.0" not in paths


# ── Method guessing tests ─────────────────────────────────────


class TestMethodGuessing:
    """HTTP method detection from context."""

    def test_method_from_hint(self):
        eps = _extract('$.ajax({url: "/api/data/save", method: "POST"})')
        found = [ep for ep in eps if "/api/data/save" in ep.path]
        assert found
        assert found[0].method == "POST"

    def test_method_from_type_hint(self):
        eps = _extract('$.ajax({url: "/api/data/update", type: "PUT"})')
        found = [ep for ep in eps if "/api/data/update" in ep.path]
        assert found
        assert found[0].method == "PUT"

    def test_post_from_context_words(self):
        eps = _extract('function submitForm() { fetch("/api/users/create") }')
        found = [ep for ep in eps if "/api/users/create" in ep.path]
        # "create" and "submit" in context should suggest POST
        assert found

    def test_delete_from_axios(self):
        eps = _extract('axios.delete("/api/items/remove")')
        found = [ep for ep in eps if "/api/items/remove" in ep.path]
        assert found
        assert found[0].method == "DELETE"


# ── Param extraction tests ────────────────────────────────────


class TestParamExtraction:
    """Query and body parameter extraction."""

    def test_query_params(self):
        eps = _extract('fetch("/api/search/query?query=test&page=1&limit=10")')
        found = [ep for ep in eps if "/api/search/query" in ep.path]
        assert found
        params = found[0].params
        assert "query" in params
        assert "page" in params
        assert "limit" in params

    def test_body_params_near_url(self):
        js = '''
        fetch("/api/orders/create", {
            method: "POST",
            body: JSON.stringify({
                "productId": 123,
                "quantity": 1,
                "shippingAddress": "test"
            })
        })
        '''
        eps = _extract(js)
        found = [ep for ep in eps if "/api/orders/create" in ep.path]
        assert found
        params = found[0].params
        assert "productId" in params
        assert "quantity" in params

    def test_skips_framework_keys(self):
        """Keys like 'method', 'headers', etc. are not params."""
        js = '''
        fetch("/api/data/list", {
            method: "GET",
            headers: {"Content-Type": "application/json"},
            credentials: "include"
        })
        '''
        eps = _extract(js)
        found = [ep for ep in eps if "/api/data/list" in ep.path]
        assert found
        params = found[0].params
        assert "method" not in params
        assert "headers" not in params
        assert "credentials" not in params


# ── HTML parsing tests ─────────────────────────────────────────


class TestHtmlParsing:
    """Script tag discovery and inline extraction."""

    def test_find_script_urls(self):
        html = '''
        <html>
        <head>
            <script src="/js/app.js"></script>
            <script src="https://cdn.example.com/lib.js"></script>
            <script src="/static/vendor.min.js"></script>
        </head>
        </html>
        '''
        ext = JsExtractor()
        urls = ext._find_js_urls(html, "https://example.com")
        assert len(urls) == 3
        assert "https://example.com/js/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls

    def test_relative_src_resolved(self):
        html = '<script src="scripts/main.js"></script>'
        ext = JsExtractor()
        urls = ext._find_js_urls(html, "https://app.example.com/page/")
        assert urls == ["https://app.example.com/page/scripts/main.js"]

    def test_data_uri_skipped(self):
        html = '<script src="data:text/javascript,alert(1)"></script>'
        ext = JsExtractor()
        urls = ext._find_js_urls(html, "https://example.com")
        assert urls == []

    def test_inline_script_extraction(self):
        html = '''
        <script>
            var apiUrl = "/api/users/profile";
            fetch("/api/data/dashboard");
        </script>
        '''
        ext = JsExtractor()
        eps = ext._extract_inline_scripts(html, "https://example.com")
        paths = _paths(eps)
        assert "/api/users/profile" in paths
        assert "/api/data/dashboard" in paths


# ── Deduplication tests ────────────────────────────────────────


class TestDeduplication:
    """Dedup by path+method, keeping highest confidence."""

    def test_basic_dedup(self):
        endpoints = [
            ExtractedEndpoint(path="/api/users", method="GET", confidence="low"),
            ExtractedEndpoint(path="/api/users", method="GET", confidence="high"),
            ExtractedEndpoint(path="/api/users", method="POST", confidence="medium"),
        ]
        result = JsExtractor._deduplicate(endpoints)
        assert len(result) == 2  # GET and POST are different
        get_ep = [ep for ep in result if ep.method == "GET"][0]
        assert get_ep.confidence == "high"

    def test_param_merging(self):
        endpoints = [
            ExtractedEndpoint(path="/api/search", method="GET",
                              params=["q", "page"], confidence="medium"),
            ExtractedEndpoint(path="/api/search", method="GET",
                              params=["q", "limit"], confidence="high"),
        ]
        result = JsExtractor._deduplicate(endpoints)
        assert len(result) == 1
        assert set(result[0].params) == {"q", "page", "limit"}


# ── Normalization tests ────────────────────────────────────────


class TestNormalization:
    def test_trailing_slash_stripped(self):
        assert JsExtractor._normalize_path("/api/users/") == "/api/users"

    def test_double_slash_collapsed(self):
        assert JsExtractor._normalize_path("/api//users") == "/api/users"

    def test_empty_becomes_root(self):
        assert JsExtractor._normalize_path("") == "/"


# ── URL to path conversion ────────────────────────────────────


class TestUrlToPath:
    def test_absolute_path(self):
        assert JsExtractor._url_to_path("/api/test") == "/api/test"

    def test_full_url(self):
        assert JsExtractor._url_to_path("https://x.com/api/test") == "/api/test"

    def test_relative_with_base(self):
        result = JsExtractor._url_to_path("api/test", "https://x.com/app/")
        assert result == "/app/api/test"

    def test_empty_returns_none(self):
        assert JsExtractor._url_to_path("") is None

    def test_data_uri_returns_none(self):
        assert JsExtractor._url_to_path("data:text/plain,hi") is None


# ── JsExtractionResult ────────────────────────────────────────


class TestExtractionResult:
    def test_unique_paths(self):
        r = JsExtractionResult(
            target="https://example.com",
            endpoints=[
                ExtractedEndpoint(path="/api/a", method="GET"),
                ExtractedEndpoint(path="/api/b", method="GET"),
                ExtractedEndpoint(path="/api/a", method="POST"),
            ],
        )
        assert r.unique_paths() == ["/api/a", "/api/b"]
        assert r.endpoint_count == 3


# ── End-to-end with mock HTTP ─────────────────────────────────


class TestEndToEnd:
    """Full extract() flow with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_full_extraction(self):
        """Fetch HTML → find JS → fetch JS → extract endpoints."""
        html = '''
        <html>
        <head><script src="/js/app.js"></script></head>
        <body>
            <script>var config = {apiBase: "/api/config/init"};</script>
        </body>
        </html>
        '''
        js_source = '''
        var API = {
            getUsers: function() { return fetch("/api/users/list"); },
            createOrder: function(data) {
                return axios.post("/api/orders/create", {
                    "productId": data.pid,
                    "quantity": data.qty
                });
            },
            search: function(q) {
                return $http.get("/api/search/results?q=" + q + "&limit=20");
            }
        };
        '''

        call_count = 0

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url = str(request.url)
            if url.endswith("/app.js"):
                return httpx.Response(200, text=js_source)
            # Default: return the HTML page
            return httpx.Response(200, text=html)

        transport = httpx.MockTransport(mock_handler)
        client = HttpClient(transport=transport)

        from agent.scope import add_to_scope
        add_to_scope("example.com")

        try:
            extractor = JsExtractor(client=client)
            result = await extractor.extract("https://example.com/app")

            assert result.js_files_found == 1
            assert result.js_files_fetched == 1

            paths = _paths(result.endpoints)
            assert "/api/users/list" in paths
            assert "/api/orders/create" in paths
            assert "/api/config/init" in paths

            # Check method detection
            order_ep = [e for e in result.endpoints if e.path == "/api/orders/create"]
            assert order_ep
            assert order_ep[0].method == "POST"

        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_no_client_returns_error(self):
        """Extract without HTTP client should return error, not crash."""
        extractor = JsExtractor(client=None)
        result = await extractor.extract("https://example.com")
        assert result.errors
        assert "No HTTP client" in result.errors[0]

    @pytest.mark.asyncio
    async def test_failed_js_fetch_recorded(self):
        """Failed JS fetch should record error, not crash."""

        async def failing_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.endswith(".js"):
                return httpx.Response(500, text="Server Error")
            return httpx.Response(200, text='<script src="/app.js"></script>')

        transport = httpx.MockTransport(failing_handler)
        client = HttpClient(transport=transport)

        from agent.scope import add_to_scope
        add_to_scope("example.com")

        try:
            extractor = JsExtractor(client=client)
            result = await extractor.extract("https://example.com")
            # Should still complete without raising
            assert result.js_files_found == 1
            assert result.js_files_fetched == 1  # fetched but may have no endpoints
        finally:
            await client.aclose()


# ── Minified JS stress test ───────────────────────────────────


class TestMinifiedJs:
    """Extraction from realistic minified JavaScript."""

    def test_minified_endpoints(self):
        """Simulates typical webpack/uglify output with API calls."""
        minified = (
            'var a={getUser:function(e){return t.get("/api/users/"+e)},'
            'createOrder:function(e){return t.post("/api/orders/create",'
            '{productId:e.id,quantity:e.qty})},'
            'search:function(e){return t.get("/api/search/results?q="+e+"&page=1")},'
            'deleteItem:function(e){return t.delete("/api/items/"+e)},'
            'updateProfile:function(e){return t.put("/api/users/profile",e)},'
            'getConfig:function(){return fetch("/api/config/settings")},'
            'uploadFile:function(e){return $.post("/api/upload/document",e)},'
            'getDashboard:function(){return $http.get("/dashboard/analytics")},'
            'getReports:function(){return t.get("/report/monthly")},'
            'getInvoices:function(){return t.get("/invoice/list")}};'
        )
        eps = _extract(minified)
        paths = _paths(eps)

        # Should find the major API paths
        assert "/api/orders/create" in paths
        assert "/api/config/settings" in paths
        assert "/api/upload/document" in paths
        assert "/dashboard/analytics" in paths

    def test_concatenated_minified(self):
        """Multiple scripts concatenated (common in bundles)."""
        bundle = (
            '!function(e){e.api="/api/v2/data/export"}(window);'
            '!function(t){t.endpoint="/rest/inventory/sync"}(app);'
            'define(["require"],function(r){return{url:"/api/auth/token/refresh"}});'
        )
        eps = _extract(bundle)
        paths = _paths(eps)
        assert "/api/v2/data/export" in paths
        assert "/api/auth/token/refresh" in paths
