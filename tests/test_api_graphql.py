"""Tests for API schema and GraphQL discovery modules."""
import pytest

from agent.recon.api_schema import (
    ApiSchemaDiscovery, ApiEndpoint, ApiSchemaResult, _SPEC_PATHS,
)
from agent.recon.graphql_introspect import (
    GraphQLIntrospection, GraphQLResult, GraphQLType, GraphQLField,
    _resolve_type, _GRAPHQL_PATHS,
)


# ── API Schema parsing ──────────────────────────────────────

def test_spec_paths_not_empty():
    assert len(_SPEC_PATHS) >= 5


def test_parse_openapi3():
    disc = ApiSchemaDiscovery.__new__(ApiSchemaDiscovery)
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test", "version": "1.0"},
        "servers": [{"url": "/api/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "tags": ["users"],
                    "parameters": [
                        {"name": "page", "in": "query", "type": "integer"},
                    ],
                },
                "post": {
                    "summary": "Create user",
                    "security": [],  # overrides global
                },
            },
            "/users/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "type": "string"},
                ],
                "get": {
                    "summary": "Get user",
                },
            },
        },
    }
    result = disc._parse_openapi3(spec, "http://test.com")
    assert result.spec_type == "openapi3"
    assert result.base_path == "/api/v1"
    assert len(result.endpoints) == 3

    get_users = next(e for e in result.endpoints if e.path == "/users" and e.method == "GET")
    assert get_users.auth_required is True
    assert len(get_users.parameters) >= 1

    post_users = next(e for e in result.endpoints if e.path == "/users" and e.method == "POST")
    assert post_users.auth_required is False  # security: [] overrides global


def test_parse_swagger2():
    disc = ApiSchemaDiscovery.__new__(ApiSchemaDiscovery)
    spec = {
        "swagger": "2.0",
        "basePath": "/api",
        "paths": {
            "/items": {
                "get": {"summary": "List items"},
            },
        },
    }
    result = disc._parse_swagger2(spec, "http://test.com")
    assert result.spec_type == "openapi2"
    assert result.base_path == "/api"
    assert len(result.endpoints) == 1


def test_parse_unknown_spec():
    disc = ApiSchemaDiscovery.__new__(ApiSchemaDiscovery)
    result = disc._parse_spec({"foo": "bar"}, "http://test.com")
    assert result.endpoints == []


# ── GraphQL introspection parsing ───────────────────────────

def test_graphql_paths_not_empty():
    assert len(_GRAPHQL_PATHS) >= 3


def test_resolve_type_simple():
    assert _resolve_type({"name": "String"}) == "String"


def test_resolve_type_nested():
    assert _resolve_type({"kind": "NON_NULL", "ofType": {"name": "ID"}}) == "ID"


def test_resolve_type_none():
    assert _resolve_type(None) == ""
    assert _resolve_type({}) == ""


def test_graphql_result_defaults():
    r = GraphQLResult()
    assert r.endpoint == ""
    assert r.introspection_open is False
    assert r.types == []


def test_graphql_type_dataclass():
    t = GraphQLType(name="User", kind="OBJECT", fields=[
        GraphQLField(name="id", type_name="ID"),
        GraphQLField(name="name", type_name="String"),
    ])
    assert t.name == "User"
    assert len(t.fields) == 2
    assert t.fields[0].name == "id"


def test_api_endpoint_defaults():
    ep = ApiEndpoint(path="/test", method="GET")
    assert ep.auth_required is False
    assert ep.parameters == []
