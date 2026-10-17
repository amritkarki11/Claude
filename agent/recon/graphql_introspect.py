"""GraphQL introspection — detects open introspection and extracts schema info.

Checks:
  1. Is introspection enabled? (security finding on its own)
  2. Extracts types, queries, mutations for further scanning
  3. Detects common GraphQL endpoints
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)

_GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql",
    "/v1/graphql", "/v2/graphql",
    "/query", "/gql",
]

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""


@dataclass
class GraphQLField:
    """A field on a GraphQL type."""
    name: str
    type_name: str = ""
    args: list[dict] = field(default_factory=list)


@dataclass
class GraphQLType:
    """A GraphQL type from introspection."""
    name: str
    kind: str  # OBJECT, INPUT_OBJECT, ENUM, etc.
    fields: list[GraphQLField] = field(default_factory=list)


@dataclass
class GraphQLResult:
    """Result of GraphQL introspection discovery."""
    endpoint: str = ""
    introspection_open: bool = False
    query_type: str = ""
    mutation_type: str = ""
    types: list[GraphQLType] = field(default_factory=list)
    queries: list[GraphQLField] = field(default_factory=list)
    mutations: list[GraphQLField] = field(default_factory=list)


class GraphQLIntrospection:
    """Discovers GraphQL endpoints and runs introspection."""

    def __init__(self, client: HttpClient, session: Session | None = None):
        self.client = client
        self.session = session or Session()

    async def discover(self, target_url: str) -> GraphQLResult:
        """Try to find a GraphQL endpoint and introspect it."""
        for path in _GRAPHQL_PATHS:
            url = urljoin(target_url, path)
            result = await self._try_introspect(url)
            if result.introspection_open:
                return result

        return GraphQLResult()

    async def _try_introspect(self, url: str) -> GraphQLResult:
        """Attempt introspection at a specific URL."""
        result = GraphQLResult(endpoint=url)

        try:
            resp = await self.client.request(
                "POST", url, session=self.session,
                json={"query": _INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )

            if resp.status_code != 200:
                return result

            try:
                data = resp.json()
            except Exception:
                return result

            if not isinstance(data, dict):
                return result

            schema = data.get("data", {}).get("__schema")
            if not schema:
                errors = data.get("errors", [])
                if errors:
                    for err in errors:
                        msg = str(err.get("message", "")).lower()
                        if "introspection" in msg and ("disabled" in msg or "not allowed" in msg):
                            logger.info("GraphQL found at %s but introspection disabled", url)
                            result.endpoint = url
                            return result
                return result

            result.introspection_open = True
            logger.info("GraphQL introspection OPEN at %s", url)

            qt = schema.get("queryType", {})
            mt = schema.get("mutationType", {})
            result.query_type = qt.get("name", "") if qt else ""
            result.mutation_type = mt.get("name", "") if mt else ""

            type_map: dict[str, GraphQLType] = {}
            for t in schema.get("types", []):
                if not isinstance(t, dict):
                    continue
                name = t.get("name", "")
                if name.startswith("__"):
                    continue
                gtype = GraphQLType(
                    name=name,
                    kind=t.get("kind", ""),
                    fields=[
                        GraphQLField(
                            name=f.get("name", ""),
                            type_name=_resolve_type(f.get("type", {})),
                            args=[a for a in f.get("args", []) if isinstance(a, dict)],
                        )
                        for f in t.get("fields") or []
                        if isinstance(f, dict)
                    ],
                )
                type_map[name] = gtype
                result.types.append(gtype)

            if result.query_type and result.query_type in type_map:
                result.queries = type_map[result.query_type].fields
            if result.mutation_type and result.mutation_type in type_map:
                result.mutations = type_map[result.mutation_type].fields

        except Exception as e:
            logger.debug("GraphQL introspection failed at %s: %s", url, e)

        return result


def _resolve_type(type_info: dict | None) -> str:
    """Resolve a GraphQL type reference to a readable name."""
    if not type_info or not isinstance(type_info, dict):
        return ""
    name = type_info.get("name")
    if name:
        return name
    of_type = type_info.get("ofType")
    if of_type:
        return _resolve_type(of_type)
    return type_info.get("kind", "")
