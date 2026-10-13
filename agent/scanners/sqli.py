"""SQLi scanner — detects SQL injection via error-based and boolean-based probes.

Strategy:
  1. Error-based: inject known SQL-breaking payloads, look for DB error strings
  2. Boolean-based: send true/false conditions, compare response lengths
  3. Time-based: inject SLEEP/WAITFOR, check response time delta (future)

Handles body, query, and path injection points.
"""
from __future__ import annotations

from typing import Any

from ..http import HttpClient, Session
from ..recipes.schema import Recipe
from .base import Scanner, Candidate

# Payloads that reliably trigger DB errors without causing damage
_ERROR_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "1; SELECT 1--",
]

# DB error signatures (case-insensitive matching)
_DB_ERRORS = [
    "sql syntax", "mysql", "mariadb", "postgresql", "sqlite",
    "ora-", "oracle", "microsoft sql", "mssql", "unclosed quotation",
    "quoted string not properly terminated", "syntax error",
    "unexpected end of sql", "sqlexception", "jdbc", "odbc",
    "you have an error in your sql",
    "warning: mysql", "valid mysql result",
    "pg_query", "pg_exec", "unterminated quoted string",
]

# Boolean payloads: (true_payload, false_payload)
_BOOLEAN_PAIRS = [
    ("' OR '1'='1' --", "' OR '1'='2' --"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("' OR 1=1 #", "' OR 1=2 #"),
]


class SqliScanner(Scanner):
    """Detects SQL injection via error-based and boolean-based probes."""

    vuln_classes = ["sqli", "sql-injection"]

    def __init__(self, client: HttpClient, session: Session):
        super().__init__(client)
        self.session = session

    async def _detect(self, target: str, recipe: Recipe,
                      **context: Any) -> list[Candidate]:
        params = context.get("params", [])
        method = context.get("method", "GET")
        id_location = context.get("id_location", "query")

        if not params:
            return []

        candidates = []

        for param in params:
            # Error-based detection
            error_result = await self._error_probe(
                target, param, method, id_location
            )
            if error_result:
                candidates.append(
                    self._make_candidate(
                        recipe=recipe,
                        endpoint=target,
                        method=method,
                        evidence=error_result,
                        confidence="high" if error_result.get("db_type") else "medium",
                        request_data={
                            "param": param,
                            "payload": error_result["payload"],
                            "id_location": id_location,
                            "technique": "error-based",
                        },
                        response_data={
                            "status": error_result.get("status"),
                            "error_match": error_result.get("error_match"),
                        },
                    )
                )
                continue  # skip boolean if error already confirmed

            # Boolean-based detection
            bool_result = await self._boolean_probe(
                target, param, method, id_location
            )
            if bool_result:
                candidates.append(
                    self._make_candidate(
                        recipe=recipe,
                        endpoint=target,
                        method=method,
                        evidence=bool_result,
                        confidence="medium",
                        request_data={
                            "param": param,
                            "payload_true": bool_result["payload_true"],
                            "payload_false": bool_result["payload_false"],
                            "id_location": id_location,
                            "technique": "boolean-based",
                        },
                        response_data={
                            "status": bool_result.get("status"),
                            "length_diff": bool_result.get("length_diff"),
                        },
                    )
                )

        return candidates

    async def _error_probe(self, target: str, param: str,
                           method: str, id_location: str) -> dict | None:
        for payload in _ERROR_PAYLOADS:
            try:
                resp = await self._send(target, param, payload, method, id_location)
                body = resp.text[:2000].lower()
                for error_sig in _DB_ERRORS:
                    if error_sig in body:
                        return {
                            "status": resp.status_code,
                            "payload": payload,
                            "error_match": error_sig,
                            "db_type": self._identify_db(body),
                            "body_snippet": resp.text[:500],
                        }
            except Exception:
                continue
        return None

    async def _boolean_probe(self, target: str, param: str,
                             method: str, id_location: str) -> dict | None:
        # First get baseline response length
        try:
            baseline = await self._send(target, param, "normalvalue", method, id_location)
            baseline_len = len(baseline.text)
        except Exception:
            return None

        for true_payload, false_payload in _BOOLEAN_PAIRS:
            try:
                true_resp = await self._send(target, param, true_payload, method, id_location)
                false_resp = await self._send(target, param, false_payload, method, id_location)

                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                diff = abs(true_len - false_len)

                # Significant length difference suggests boolean injection
                if diff > 50 and true_resp.status_code == false_resp.status_code:
                    return {
                        "status": true_resp.status_code,
                        "payload_true": true_payload,
                        "payload_false": false_payload,
                        "true_length": true_len,
                        "false_length": false_len,
                        "length_diff": diff,
                        "baseline_length": baseline_len,
                    }
            except Exception:
                continue
        return None

    async def _send(self, target: str, param: str, value: str,
                    method: str, id_location: str):
        if id_location == "query":
            return await self.client.request(
                method, target, session=self.session,
                params={param: value},
            )
        elif id_location == "body":
            return await self.client.post(
                target, session=self.session,
                json={param: value},
                headers={"Content-Type": "application/json"},
            )
        elif id_location == "path":
            url = target.rstrip("/") + f"/{value}"
            return await self.client.request(method, url, session=self.session)
        else:
            raise ValueError(f"Unknown id_location: {id_location}")

    @staticmethod
    def _identify_db(body: str) -> str | None:
        if any(s in body for s in ["mysql", "mariadb"]):
            return "MySQL"
        if any(s in body for s in ["postgresql", "pg_"]):
            return "PostgreSQL"
        if any(s in body for s in ["ora-", "oracle"]):
            return "Oracle"
        if any(s in body for s in ["microsoft sql", "mssql"]):
            return "MSSQL"
        if "sqlite" in body:
            return "SQLite"
        return None
