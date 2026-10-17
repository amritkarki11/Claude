"""Directory bruteforce — discovers hidden endpoints, admin panels, and backup files.

Uses a curated wordlist of common paths. Runs with controlled concurrency
to avoid overwhelming the target. Filters out soft-404 responses.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from ..http import HttpClient, Session

logger = logging.getLogger(__name__)

# ── Wordlist — most impactful paths for web app pentesting ─────

_COMMON_DIRS = [
    # Admin panels
    "admin", "admin/", "administrator", "admin/login", "admin/dashboard",
    "panel", "cpanel", "wp-admin", "manager", "administration",
    "admin.php", "admin.asp", "admin.html", "dashboard",
    # Backup / config files
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "database.sql", ".env", "config.php", "config.yml", "config.json",
    "web.config", "wp-config.php", "wp-config.php.bak",
    "configuration.php", ".htaccess", ".htpasswd",
    "config.php.bak", "config.old", "config.bak",
    # Source / version control
    ".git", ".git/HEAD", ".git/config", ".svn", ".svn/entries",
    ".DS_Store", ".hg", ".bzr",
    # API endpoints
    "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "swagger", "swagger.json", "swagger-ui.html", "swagger/index.html",
    "openapi.json", "api-docs", "graphql", "graphiql",
    # Status / debug
    "status", "health", "healthcheck", "info", "debug", "trace",
    "server-status", "server-info", "phpinfo.php", "phpinfo",
    "test", "test.php", "test.html", "test.asp",
    "elmah.axd", "error_log", "errors", "log", "logs",
    # Common app files
    "robots.txt", "sitemap.xml", "crossdomain.xml", "humans.txt",
    "security.txt", ".well-known/security.txt",
    "favicon.ico", "manifest.json",
    # User-facing
    "login", "signin", "signup", "register", "forgot",
    "reset", "logout", "profile", "account", "settings",
    "user", "users", "member", "members",
    # Common directories
    "upload", "uploads", "files", "images", "img", "media",
    "static", "assets", "css", "js", "scripts",
    "include", "includes", "lib", "vendor", "node_modules",
    "temp", "tmp", "cache", "data", "private", "public",
    # Common file extensions to check
    "index.php", "index.asp", "index.jsp", "index.html",
    "default.asp", "default.aspx", "default.htm",
    "web.xml", "WEB-INF/web.xml", "META-INF/MANIFEST.MF",
    # CMS specific
    "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "wp-json/wp/v2/users", "xmlrpc.php",
    "joomla", "drupal", "magento",
    # Tomcat / Java
    "manager/html", "manager/status", "host-manager",
    "WEB-INF", "META-INF", "console",
    # Common hidden endpoints
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "metrics", "prometheus", "monitoring",
    "cgi-bin", "cgi-bin/test", "cgi-bin/printenv",
    # Sensitive files
    "id_rsa", ".ssh/id_rsa", "id_rsa.pub",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerenv",
]


@dataclass
class DirbruteFind:
    """A discovered path from directory bruteforce."""
    path: str
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_url: str = ""
    category: str = ""  # admin, backup, api, config, etc.


@dataclass
class DirbruteResult:
    """Results from directory bruteforce scan."""
    target: str = ""
    paths_tested: int = 0
    findings: list[DirbruteFind] = field(default_factory=list)
    soft_404_signature: str = ""

    @property
    def found_count(self) -> int:
        return len(self.findings)

    def by_category(self) -> dict[str, list[DirbruteFind]]:
        cats: dict[str, list[DirbruteFind]] = {}
        for f in self.findings:
            cats.setdefault(f.category, []).append(f)
        return cats


class DirBrute:
    """Directory bruteforce scanner with soft-404 detection."""

    def __init__(self, client: HttpClient, session: Session,
                 concurrency: int = 10, extra_paths: list[str] | None = None):
        self.client = client
        self.session = session
        self.concurrency = concurrency
        self.wordlist = list(_COMMON_DIRS)
        if extra_paths:
            self.wordlist.extend(extra_paths)

    async def scan(self, target_url: str) -> DirbruteResult:
        """Run directory bruteforce against target."""
        result = DirbruteResult(target=target_url)

        # Normalize base URL
        if not target_url.endswith("/"):
            target_url += "/"

        # Detect soft-404 pattern
        soft_404_len = await self._detect_soft_404(target_url)
        result.soft_404_signature = f"length≈{soft_404_len}" if soft_404_len else ""

        # Run bruteforce with concurrency control
        sem = asyncio.Semaphore(self.concurrency)
        tasks = []
        for path in self.wordlist:
            url = urljoin(target_url, path)
            tasks.append(self._check_path(sem, url, path, soft_404_len))

        findings = await asyncio.gather(*tasks)
        result.paths_tested = len(tasks)
        result.findings = [f for f in findings if f is not None]

        # Sort by status code, then by category importance
        cat_order = {"config": 0, "backup": 1, "admin": 2, "api": 3,
                     "debug": 4, "vcs": 5, "sensitive": 6, "": 7}
        result.findings.sort(key=lambda f: (cat_order.get(f.category, 99), f.status_code))

        return result

    async def _detect_soft_404(self, base_url: str) -> int | None:
        """Send a request to a random nonexistent path to detect soft-404."""
        try:
            fake_url = urljoin(base_url, "auton_nonexistent_path_7x3k9m2p")
            resp = await self.client.get(fake_url, session=self.session)
            if resp.status_code == 200:
                return len(resp.text)
        except Exception:
            pass
        return None

    async def _check_path(self, sem: asyncio.Semaphore, url: str,
                          path: str, soft_404_len: int | None) -> DirbruteFind | None:
        """Check a single path."""
        async with sem:
            try:
                resp = await self.client.get(url, session=self.session,
                                             follow_redirects=False)
                status = resp.status_code
                body_len = len(resp.text)
                content_type = resp.headers.get("content-type", "")

                # Filter out definite 404s
                if status == 404:
                    return None

                # Filter out soft-404s
                if soft_404_len and status == 200:
                    if abs(body_len - soft_404_len) < 100:
                        return None

                # Filter out empty responses
                if status == 200 and body_len < 10:
                    return None

                # Categorize the finding
                category = self._categorize(path)

                # Get redirect URL if applicable
                redirect_url = ""
                if status in (301, 302, 303, 307, 308):
                    redirect_url = resp.headers.get("location", "")

                # Only report interesting status codes
                if status in (200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500):
                    return DirbruteFind(
                        path=path,
                        url=url,
                        status_code=status,
                        content_length=body_len,
                        content_type=content_type.split(";")[0].strip(),
                        redirect_url=redirect_url,
                        category=category,
                    )

            except Exception:
                pass
            return None

    @staticmethod
    def _categorize(path: str) -> str:
        """Categorize a found path."""
        path_lower = path.lower()

        if any(x in path_lower for x in ("admin", "panel", "cpanel", "dashboard", "manager")):
            return "admin"
        if any(x in path_lower for x in ("backup", ".bak", ".old", ".sql", ".zip", ".tar")):
            return "backup"
        if any(x in path_lower for x in (".git", ".svn", ".hg", ".bzr", ".DS_Store")):
            return "vcs"
        if any(x in path_lower for x in ("api", "swagger", "graphql", "openapi", "rest")):
            return "api"
        if any(x in path_lower for x in (".env", "config", "web.config", "wp-config", ".htaccess", ".htpasswd")):
            return "config"
        if any(x in path_lower for x in ("debug", "trace", "phpinfo", "server-status", "server-info", "elmah", "actuator", "error_log")):
            return "debug"
        if any(x in path_lower for x in ("id_rsa", "composer.json", "package.json", "requirements.txt", "Dockerfile")):
            return "sensitive"
        return ""
