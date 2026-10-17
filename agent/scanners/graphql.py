"""GraphQL vulnerability scanner.

Checks for:
  - Introspection enabled (info/low)
  - Query depth abuse (DoS via nested queries)
  - Batch query abuse (multiple operations in one request)
"""
from __future__ import annotations

import logging
from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from ..recon.graphql_introspect import GraphQLResult
from .base import Scanner, Candidate

logger = logging.getLogger(__name__)


class GraphQLScanner(Scanner):
    """Scans GraphQL endpoints for common vulnerabilities."""

    vuln_classes = ["graphql", "graphql-introspection"]

    def __init__(self, client: HttpClient,
                 session: Session | None = None,
                 graphql_result: GraphQLResult | None = None):
        super().__init__(client)
        self.session = session or Session()
        self.gql = graphql_result

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        candidates: list[Candidate] = []
        gql = context.get("graphql_result", self.gql)
        if not gql or not gql.endpoint:
            return candidates

        rid = recipe.id.lower()

        if "introspection" in rid and gql.introspection_open:
            candidates.append(self._make_candidate(
                recipe=recipe,
                endpoint=gql.endpoint,
                method="POST",
                evidence={
                    "introspection_open": True,
                    "types_count": len(gql.types),
                    "queries_count": len(gql.queries),
                    "mutations_count": len(gql.mutations),
                    "technique": "graphql-introspection",
                },
                confidence="high",
                request_data={
                    "query": "{ __schema { types { name } } }",
                    "technique": "graphql-introspection",
                },
                response_data={
                    "types": [t.name for t in gql.types[:20]],
                },
            ))

        if "depth" in rid and gql.introspection_open:
            depth_result = await self._test_depth(gql.endpoint)
            if depth_result:
                candidates.append(self._make_candidate(
                    recipe=recipe,
                    endpoint=gql.endpoint,
                    method="POST",
                    evidence=depth_result,
                    confidence="medium",
                    request_data={
                        "technique": "graphql-depth-abuse",
                        "query": depth_result.get("query", ""),
                    },
                ))

        if "batch" in rid:
            batch_result = await self._test_batch(gql.endpoint)
            if batch_result:
                candidates.append(self._make_candidate(
                    recipe=recipe,
                    endpoint=gql.endpoint,
                    method="POST",
                    evidence=batch_result,
                    confidence="medium",
                    request_data={
                        "technique": "graphql-batch",
                    },
                ))

        return candidates

    async def _test_depth(self, endpoint: str) -> dict | None:
        """Test if deeply nested queries are accepted."""
        # Build a 10-level deep query using __typename
        inner = "__typename"
        for i in range(10):
            inner = f"{{ __typename ... on Query {{ {inner} }} }}"
        query = f"query {{ __schema {inner} }}"

        try:
            resp = await self.client.request(
                "POST", endpoint, session=self.session,
                json={"query": query},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and not data.get("errors"):
                    return {
                        "depth_allowed": True,
                        "test_depth": 10,
                        "query": query[:500],
                        "technique": "graphql-depth-abuse",
                    }
        except Exception as e:
            logger.debug("GraphQL depth test failed: %s", e)
        return None

    async def _test_batch(self, endpoint: str) -> dict | None:
        """Test if batch queries (array of operations) are accepted."""
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        try:
            resp = await self.client.request(
                "POST", endpoint, session=self.session,
                json=batch,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) == 3:
                    return {
                        "batch_allowed": True,
                        "batch_size_tested": 3,
                        "technique": "graphql-batch",
                    }
        except Exception as e:
            logger.debug("GraphQL batch test failed: %s", e)
        return None
