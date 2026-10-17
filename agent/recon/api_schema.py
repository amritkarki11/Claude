"""API schema discovery — parses OpenAPI/Swagger specs to extract endpoints.

Looks for common spec locations, parses the schema, and returns a list of
API endpoints with methods, parameters, and auth requirements.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)

# Common locations for API specs
_SPEC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json",
    "/openapi.json", "/openapi.yaml",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api/swagger.json", "/api/openapi.json",
    "/docs/api.json", "/.well-known/openapi.json",
]


@dataclass
class ApiEndpoint:
    """An API endpoint discovered from a schema."""
    path: str
    method: str
    parameters: list[dict] = field(default_factory=list)
    auth_required: bool = False
    description: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class ApiSchemaResult:
    """Result of API schema discovery."""
    spec_url: str = ""
    spec_type: str = ""  # "openapi2", "openapi3", or ""
    base_path: str = ""
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    raw_spec: dict = field(default_factory=dict)


class ApiSchemaDiscovery:
    """Discovers and parses API specs (OpenAPI/Swagger)."""

    def __init__(self, client: HttpClient, session: Session | None = None):
        self.client = client
        self.session = session or Session()

    async def discover(self, target_url: str) -> ApiSchemaResult:
        """Try to find and parse an API spec at the target."""
        for path in _SPEC_PATHS:
            url = urljoin(target_url, path)
            try:
                resp = await self.client.request("GET", url, session=self.session)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                if "json" not in ct and "yaml" not in ct and "text" not in ct:
                    continue

                try:
                    spec = resp.json()
                except Exception:
                    continue

                if not isinstance(spec, dict):
                    continue

                result = self._parse_spec(spec, target_url)
                if result.endpoints:
                    result.spec_url = url
                    logger.info("Found API spec at %s with %d endpoints",
                                url, len(result.endpoints))
                    return result
            except Exception as e:
                logger.debug("Schema probe failed for %s: %s", url, e)

        return ApiSchemaResult()

    def _parse_spec(self, spec: dict, target_url: str) -> ApiSchemaResult:
        """Parse an OpenAPI/Swagger spec dict."""
        if "openapi" in spec and spec.get("openapi", "").startswith("3"):
            return self._parse_openapi3(spec, target_url)
        elif "swagger" in spec and spec.get("swagger", "").startswith("2"):
            return self._parse_swagger2(spec, target_url)
        return ApiSchemaResult()

    def _parse_openapi3(self, spec: dict, target_url: str) -> ApiSchemaResult:
        """Parse OpenAPI 3.x spec."""
        result = ApiSchemaResult(spec_type="openapi3", raw_spec=spec)

        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            result.base_path = servers[0].get("url", "")

        paths = spec.get("paths", {})
        security_schemes = spec.get("components", {}).get("securitySchemes", {})
        has_global_security = bool(spec.get("security"))

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() in ("parameters", "summary", "description", "servers"):
                    continue
                if not isinstance(operation, dict):
                    continue

                params = self._extract_params(operation, methods)
                auth_required = bool(
                    operation.get("security") or
                    (has_global_security and "security" not in operation)
                )

                result.endpoints.append(ApiEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=params,
                    auth_required=auth_required,
                    description=operation.get("summary", ""),
                    tags=operation.get("tags", []),
                ))

        return result

    def _parse_swagger2(self, spec: dict, target_url: str) -> ApiSchemaResult:
        """Parse Swagger 2.0 spec."""
        result = ApiSchemaResult(spec_type="openapi2", raw_spec=spec)
        result.base_path = spec.get("basePath", "")

        paths = spec.get("paths", {})
        has_global_security = bool(spec.get("security"))

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() in ("parameters",):
                    continue
                if not isinstance(operation, dict):
                    continue

                params = self._extract_params(operation, methods)
                auth_required = bool(
                    operation.get("security") or
                    (has_global_security and "security" not in operation)
                )

                result.endpoints.append(ApiEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=params,
                    auth_required=auth_required,
                    description=operation.get("summary", ""),
                    tags=operation.get("tags", []),
                ))

        return result

    @staticmethod
    def _extract_params(operation: dict, path_item: dict) -> list[dict]:
        """Extract parameters from an operation + path-level params."""
        params = []
        all_params = list(path_item.get("parameters", []))
        all_params.extend(operation.get("parameters", []))
        for p in all_params:
            if not isinstance(p, dict):
                continue
            params.append({
                "name": p.get("name", ""),
                "in": p.get("in", ""),
                "required": p.get("required", False),
                "type": p.get("type", p.get("schema", {}).get("type", "")),
            })
        return params
