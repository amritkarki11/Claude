"""Tests for active parameter discovery (mining + fuzzing)."""
from __future__ import annotations

import pytest
from agent.recon.param_discovery import (
    mine_params_from_html,
    mine_params_from_js,
    _REFLECT_CANARY,
)


class TestMineParamsFromHtml:
    def test_hidden_inputs(self):
        html = '''
        <form action="/submit">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="hidden" name="user_id" value="42">
            <input type="text" name="username">
        </form>
        '''
        params = mine_params_from_html(html)
        assert "csrf_token" in params
        assert "user_id" in params
        assert "username" in params

    def test_select_and_textarea(self):
        html = '''
        <select name="country"><option>US</option></select>
        <textarea name="bio"></textarea>
        '''
        params = mine_params_from_html(html)
        assert "country" in params
        assert "bio" in params

    def test_html_comments(self):
        html = '''
        <!-- param=debug -->
        <!-- field: admin_mode -->
        <input type="text" name="q">
        '''
        params = mine_params_from_html(html)
        assert "debug" in params
        assert "admin_mode" in params
        assert "q" in params

    def test_data_attributes(self):
        html = '<div data-user-id="123" data-action-type="edit"></div>'
        params = mine_params_from_html(html)
        assert "user_id" in params
        assert "action_type" in params

    def test_ignores_framework_data_attrs(self):
        html = '<div data-v_app="true" data-bs_toggle="modal" data-toggle="dropdown"></div>'
        params = mine_params_from_html(html)
        assert "v_app" not in params
        assert "bs_toggle" not in params
        assert "toggle" not in params

    def test_empty_html(self):
        assert mine_params_from_html("") == set()
        assert mine_params_from_html("no html here") == set()


class TestMineParamsFromJs:
    def test_searchparams_get(self):
        js = '''
        const id = url.searchParams.get("user_id");
        params.set("page", "1");
        query.append("filter", value);
        '''
        params = mine_params_from_js(js)
        assert "user_id" in params
        assert "page" in params
        assert "filter" in params

    def test_query_string_building(self):
        js = '''
        const url = "/api/search?q=" + term + "&limit=10&offset=" + page;
        '''
        params = mine_params_from_js(js)
        assert "q" in params
        assert "limit" in params
        assert "offset" in params

    def test_fetch_body_params(self):
        js = '''
        fetch("/api/login", {
            method: "POST",
            body: JSON.stringify({"username": user, "password": pass})
        });
        '''
        params = mine_params_from_js(js)
        assert "username" in params
        assert "password" in params

    def test_ignores_fetch_options(self):
        js = '''
        fetch("/api", {
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "credentials": "include"
        });
        '''
        params = mine_params_from_js(js)
        assert "method" not in params
        assert "headers" not in params
        assert "credentials" not in params

    def test_empty_js(self):
        assert mine_params_from_js("") == set()


class TestReflectCanary:
    def test_canary_is_unique(self):
        assert len(_REFLECT_CANARY) > 5
        assert _REFLECT_CANARY.isalnum()
