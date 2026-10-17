"""Tests for agent.recon.param_discovery (Phase 2.3)."""
from __future__ import annotations

import pytest

from agent.recon.param_discovery import (
    ParamDiscoverer,
    ParamInfo,
    ParamInventory,
    EndpointParams,
    infer_param_type,
    _infer_type_from_values,
)
from agent.recon.crawler import CrawlResult, CrawledPage, DiscoveredForm, FormField
from agent.recon.js_extractor import JsExtractionResult, ExtractedEndpoint


# ── Type inference by name ────────────────────────────────────


class TestTypeInferenceByName:
    """Test _NAME_TYPE_RULES matching."""

    def test_id_variants(self):
        assert infer_param_type("id") == "id"
        assert infer_param_type("user_id") == "id"
        assert infer_param_type("userId") == "id"
        assert infer_param_type("order_id") == "id"
        assert infer_param_type("ID") == "id"

    def test_uuid(self):
        assert infer_param_type("uuid") == "uuid"
        assert infer_param_type("guid") == "uuid"

    def test_auth_params(self):
        assert infer_param_type("token") == "token"
        assert infer_param_type("api_key") == "token"
        assert infer_param_type("access_token") == "token"
        assert infer_param_type("password") == "password"
        assert infer_param_type("new_password") == "password"
        assert infer_param_type("username") == "username"
        assert infer_param_type("session_id") == "session"
        assert infer_param_type("csrf_token") == "csrf"
        assert infer_param_type("_token") == "csrf"

    def test_pii_params(self):
        assert infer_param_type("email") == "email"
        assert infer_param_type("email_address") == "email"
        assert infer_param_type("phone") == "phone"
        assert infer_param_type("ssn") == "pii"

    def test_date_params(self):
        assert infer_param_type("date") == "date"
        assert infer_param_type("created_at") == "date"
        assert infer_param_type("timestamp") == "date"

    def test_pagination_params(self):
        assert infer_param_type("page") == "pagination"
        assert infer_param_type("limit") == "pagination"
        assert infer_param_type("offset") == "pagination"
        assert infer_param_type("per_page") == "pagination"

    def test_numeric_params(self):
        assert infer_param_type("amount") == "numeric"
        assert infer_param_type("price") == "numeric"
        assert infer_param_type("quantity") == "numeric"

    def test_boolean_params(self):
        assert infer_param_type("is_admin") == "boolean"
        assert infer_param_type("has_permission") == "boolean"
        assert infer_param_type("active") == "boolean"

    def test_file_params(self):
        assert infer_param_type("file") == "file"
        assert infer_param_type("filepath") == "file"
        assert infer_param_type("attachment") == "file"

    def test_url_params(self):
        assert infer_param_type("redirect_url") == "url"
        assert infer_param_type("callback") == "url"
        assert infer_param_type("next") == "url"
        assert infer_param_type("goto") == "url"

    def test_search_params(self):
        assert infer_param_type("q") == "search"
        assert infer_param_type("query") == "search"
        assert infer_param_type("search") == "search"

    def test_sort_params(self):
        assert infer_param_type("sort") == "sort"
        assert infer_param_type("order_by") == "sort"

    def test_enum_params(self):
        assert infer_param_type("type") == "enum"
        assert infer_param_type("status") == "enum"
        assert infer_param_type("role") == "enum"

    def test_code_params(self):
        assert infer_param_type("cmd") == "code"
        assert infer_param_type("command") == "code"
        assert infer_param_type("template") == "code"

    def test_unknown(self):
        assert infer_param_type("xyzzy_foobar") == "unknown"


# ── Type inference from values ────────────────────────────────


class TestTypeInferenceFromValues:
    """Test _infer_type_from_values."""

    def test_uuid_value(self):
        assert _infer_type_from_values(["550e8400-e29b-41d4-a716-446655440000"]) == "uuid"

    def test_integer_value(self):
        assert _infer_type_from_values(["42"]) == "integer"
        assert _infer_type_from_values(["-1"]) == "integer"

    def test_float_value(self):
        assert _infer_type_from_values(["3.14"]) == "numeric"

    def test_email_value(self):
        assert _infer_type_from_values(["user@example.com"]) == "email"

    def test_url_value(self):
        assert _infer_type_from_values(["https://example.com/page"]) == "url"

    def test_boolean_value(self):
        assert _infer_type_from_values(["true"]) == "boolean"
        assert _infer_type_from_values(["1"]) == "integer"  # "1" matches integer first

    def test_date_value(self):
        assert _infer_type_from_values(["2024-01-15"]) == "date"
        assert _infer_type_from_values(["2024-01-15T10:30:00Z"]) == "date"

    def test_string_fallback(self):
        assert _infer_type_from_values(["hello world"]) == "string"

    def test_empty_values(self):
        assert _infer_type_from_values([]) == "string"
        assert _infer_type_from_values([""]) == "string"


# ── Security scoring ─────────────────────────────────────────


class TestSecurityScoring:
    """Test _compute_score logic."""

    def test_id_param_high_score(self):
        d = ParamDiscoverer()
        d.add_params("/api/users", ["user_id"], method="GET")
        inv = d.build_inventory()
        pi = inv.global_params["user_id"]
        assert pi.security_score >= 9

    def test_password_highest_score(self):
        d = ParamDiscoverer()
        d.add_params("/login", ["password"], method="POST")
        inv = d.build_inventory()
        pi = inv.global_params["password"]
        assert pi.security_score == 10  # base 10, capped

    def test_pagination_low_score(self):
        d = ParamDiscoverer()
        d.add_params("/api/list", ["page", "limit"])
        inv = d.build_inventory()
        assert inv.global_params["page"].security_score <= 4
        assert inv.global_params["limit"].security_score <= 4

    def test_privilege_boost(self):
        """Boolean params with privilege names get boosted."""
        d = ParamDiscoverer()
        d.add_params("/api/users", ["is_admin"], method="PUT")
        inv = d.build_inventory()
        pi = inv.global_params["is_admin"]
        # is_admin: boolean base (5), privilege boost (→8), PUT boost (+1) = 9
        assert pi.security_score >= 9

    def test_multi_source_boost(self):
        """Params seen in multiple sources get +1."""
        d = ParamDiscoverer()
        d.add_params("/api/users", ["email"], source="crawler")
        d.add_params("/api/users", ["email"], source="js_extractor")
        inv = d.build_inventory()
        pi = inv.global_params["email"]
        # email base = 7, multi-source +1 = 8
        assert pi.security_score >= 8

    def test_post_method_boost(self):
        """Params used with POST/PUT/DELETE get +1."""
        d = ParamDiscoverer()
        d.add_params("/api/data", ["name"], method="POST")
        inv = d.build_inventory()
        pi = inv.global_params["name"]
        # string base = 3, POST boost +1 = 4
        assert pi.security_score >= 4


# ── Crawl result ingestion ────────────────────────────────────


class TestCrawlIngestion:
    """Test add_crawl_result."""

    def test_form_params_ingested(self):
        form = DiscoveredForm(
            action="https://example.com/login",
            method="POST",
            fields=[
                FormField(name="username", input_type="text"),
                FormField(name="password", input_type="password", required=True),
            ],
            source_page="https://example.com/",
        )
        page = CrawledPage(
            url="https://example.com/",
            forms=[form],
        )
        result = CrawlResult(base_url="https://example.com/", pages=[page])

        d = ParamDiscoverer()
        d.add_crawl_result(result)
        inv = d.build_inventory()

        assert "username" in inv.global_params
        assert "password" in inv.global_params
        assert inv.global_params["password"].param_type == "password"
        assert inv.global_params["password"].required is True

    def test_html_input_type_mapped(self):
        """HTML input types get mapped to param types."""
        form = DiscoveredForm(
            action="https://example.com/register",
            method="POST",
            fields=[
                FormField(name="user_email", input_type="email"),
                FormField(name="dob", input_type="date"),
                FormField(name="avatar", input_type="file"),
                FormField(name="agree", input_type="checkbox"),
            ],
        )
        page = CrawledPage(url="https://example.com/register", forms=[form])
        result = CrawlResult(base_url="https://example.com/", pages=[page])

        d = ParamDiscoverer()
        d.add_crawl_result(result)
        inv = d.build_inventory()

        assert inv.global_params["user_email"].param_type == "email"
        assert inv.global_params["dob"].param_type == "date"
        assert inv.global_params["avatar"].param_type == "file"
        assert inv.global_params["agree"].param_type == "boolean"

    def test_page_url_query_params(self):
        """Query params from page URLs are extracted."""
        page = CrawledPage(
            url="https://example.com/search?query=test&page=1",
        )
        result = CrawlResult(base_url="https://example.com/", pages=[page])

        d = ParamDiscoverer()
        d.add_crawl_result(result)
        inv = d.build_inventory()

        assert "query" in inv.global_params
        assert "page" in inv.global_params
        assert "test" in inv.global_params["query"].sample_values
        assert "1" in inv.global_params["page"].sample_values


# ── JS result ingestion ───────────────────────────────────────


class TestJsIngestion:
    """Test add_js_result."""

    def test_js_params_ingested(self):
        js_result = JsExtractionResult(
            target="https://example.com",
            endpoints=[
                ExtractedEndpoint(
                    path="/api/users",
                    method="GET",
                    params=["user_id", "role"],
                ),
                ExtractedEndpoint(
                    path="/api/orders",
                    method="POST",
                    params=["amount", "item_id"],
                ),
            ],
        )

        d = ParamDiscoverer()
        d.add_js_result(js_result)
        inv = d.build_inventory()

        assert "user_id" in inv.global_params
        assert "role" in inv.global_params
        assert "amount" in inv.global_params
        assert "item_id" in inv.global_params
        assert inv.global_params["user_id"].param_type == "id"
        assert inv.global_params["amount"].param_type == "numeric"

    def test_js_source_tracked(self):
        js_result = JsExtractionResult(
            target="https://example.com",
            endpoints=[
                ExtractedEndpoint(path="/api/data", params=["filter"]),
            ],
        )

        d = ParamDiscoverer()
        d.add_js_result(js_result)
        inv = d.build_inventory()

        assert "js_extractor" in inv.global_params["filter"].sources


# ── URL ingestion ─────────────────────────────────────────────


class TestUrlIngestion:
    """Test add_url."""

    def test_query_params_extracted(self):
        d = ParamDiscoverer()
        d.add_url("https://example.com/api/search?q=hello&limit=10&offset=0")
        inv = d.build_inventory()

        assert "q" in inv.global_params
        assert "limit" in inv.global_params
        assert "offset" in inv.global_params
        assert inv.global_params["q"].param_type == "search"
        assert inv.global_params["limit"].param_type == "pagination"

    def test_sample_values_captured(self):
        d = ParamDiscoverer()
        d.add_url("https://example.com/api/users?id=123&status=active")
        inv = d.build_inventory()

        assert "123" in inv.global_params["id"].sample_values
        assert "active" in inv.global_params["status"].sample_values

    def test_no_query_string_no_params(self):
        d = ParamDiscoverer()
        d.add_url("https://example.com/api/users")
        inv = d.build_inventory()

        assert len(inv.global_params) == 0

    def test_endpoint_stripped_of_query(self):
        """Endpoint URL should not include query string."""
        d = ParamDiscoverer()
        d.add_url("https://example.com/api/data?key=val")
        inv = d.build_inventory()

        assert inv.endpoints[0].url == "https://example.com/api/data"

    def test_multiple_values_same_param(self):
        """Multiple URLs with same param collect sample values."""
        d = ParamDiscoverer()
        d.add_url("https://example.com/items?category=electronics")
        d.add_url("https://example.com/items?category=books")
        inv = d.build_inventory()

        pi = inv.global_params["category"]
        assert "electronics" in pi.sample_values
        assert "books" in pi.sample_values


# ── Manual param addition ─────────────────────────────────────


class TestManualParams:
    """Test add_params."""

    def test_basic_add(self):
        d = ParamDiscoverer()
        d.add_params("/api/users", ["user_id", "name"], method="GET", source="wordlist")
        inv = d.build_inventory()

        assert "user_id" in inv.global_params
        assert "name" in inv.global_params
        assert "wordlist" in inv.global_params["user_id"].sources

    def test_merge_across_sources(self):
        """Same param from different sources merges correctly."""
        d = ParamDiscoverer()
        d.add_params("/api/users", ["email"], method="GET", source="crawler")
        d.add_params("/api/profile", ["email"], method="POST", source="js_extractor")
        inv = d.build_inventory()

        pi = inv.global_params["email"]
        assert "crawler" in pi.sources
        assert "js_extractor" in pi.sources
        assert "/api/users" in pi.endpoints
        assert "/api/profile" in pi.endpoints
        assert "GET" in pi.methods
        assert "POST" in pi.methods


# ── Inventory output ──────────────────────────────────────────


class TestInventoryOutput:
    """Test ParamInventory properties and summary."""

    def test_high_value_params(self):
        d = ParamDiscoverer()
        d.add_params("/login", ["password", "username", "page"])
        inv = d.build_inventory()

        hv = inv.high_value_params
        hv_names = [p.name for p in hv]
        assert "password" in hv_names
        assert "username" in hv_names
        assert "page" not in hv_names  # pagination = low score

    def test_by_type_grouping(self):
        d = ParamDiscoverer()
        d.add_params("/api", ["user_id", "order_id", "email", "page"])
        inv = d.build_inventory()

        by_type = inv.by_type
        id_names = [p.name for p in by_type.get("id", [])]
        assert "user_id" in id_names
        assert "order_id" in id_names

    def test_summary_structure(self):
        d = ParamDiscoverer()
        d.add_params("/api/users", ["user_id", "email", "password"], method="POST")
        inv = d.build_inventory()

        s = inv.summary()
        assert s["endpoints_with_params"] == 1
        assert s["total_params"] == 3
        assert s["unique_params"] == 3
        assert s["high_value_count"] >= 2  # email + password at least
        assert "types" in s
        assert "top_params" in s

    def test_endpoint_params_properties(self):
        d = ParamDiscoverer()
        d.add_params("/api/users", ["user_id", "name", "page"], method="GET")
        inv = d.build_inventory()

        ep = inv.endpoints[0]
        assert ep.param_names == ["user_id", "name", "page"]
        hv = ep.high_value_params
        hv_names = [p.name for p in hv]
        assert "user_id" in hv_names


# ── Combined sources ──────────────────────────────────────────


class TestCombinedSources:
    """Test merging data from crawler + JS + URLs together."""

    def test_full_pipeline(self):
        """Simulate a real recon pipeline feeding param discovery."""
        # Crawler found a login form
        form = DiscoveredForm(
            action="https://example.com/auth/login",
            method="POST",
            fields=[
                FormField(name="username", input_type="text"),
                FormField(name="password", input_type="password", required=True),
                FormField(name="remember", input_type="checkbox"),
            ],
        )
        page = CrawledPage(
            url="https://example.com/?ref=google",
            forms=[form],
        )
        crawl = CrawlResult(base_url="https://example.com/", pages=[page])

        # JS extractor found API endpoints
        js = JsExtractionResult(
            target="https://example.com",
            endpoints=[
                ExtractedEndpoint(path="/api/users", method="GET", params=["user_id", "role"]),
                ExtractedEndpoint(path="/api/orders", method="POST", params=["amount", "user_id"]),
            ],
        )

        # Also found some URLs with params
        d = ParamDiscoverer()
        d.add_crawl_result(crawl)
        d.add_js_result(js)
        d.add_url("https://example.com/api/search?q=test&page=1&sort=date")

        inv = d.build_inventory()

        # Check merged params
        assert inv.unique_params >= 9  # username, password, remember, ref, user_id, role, amount, q, page, sort
        assert "user_id" in inv.global_params

        # user_id seen in JS extractor for two endpoints
        pi = inv.global_params["user_id"]
        assert pi.param_type == "id"
        assert "/api/users" in pi.endpoints
        assert "/api/orders" in pi.endpoints

        # password from form should be typed correctly
        assert inv.global_params["password"].param_type == "password"
        assert inv.global_params["password"].required is True

        # High value count should include auth params
        assert inv.high_value_count >= 3  # password, user_id, username at minimum

        # Summary should be well-formed
        s = inv.summary()
        assert s["unique_params"] == inv.unique_params
        assert len(s["top_params"]) > 0

    def test_empty_inventory(self):
        """Empty discoverer produces empty inventory."""
        d = ParamDiscoverer()
        inv = d.build_inventory()

        assert inv.total_params == 0
        assert inv.unique_params == 0
        assert inv.high_value_count == 0
        assert inv.endpoints == []
        assert inv.global_params == {}
        assert inv.high_value_params == []
        assert inv.summary()["total_params"] == 0
