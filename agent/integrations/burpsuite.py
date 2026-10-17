"""BurpSuite integration — launch BurpSuite from WSL, create project files,
and optionally proxy agent traffic through Burp for manual review.

This module handles:
  1. Finding BurpSuite on Windows drives from WSL (e.g. /mnt/f/burpsuite/)
  2. Running loader.jar first, then launching BurpSuite
  3. Creating per-engagement project files (.burp)
  4. Configuring the agent's HTTP client to proxy through Burp (127.0.0.1:8080)

Usage:
    burp = BurpSuiteIntegration()
    await burp.setup(target="demo.testfire.net")
    # Agent traffic now goes through Burp for manual review
"""
from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import re
import subprocess
import time
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Common locations to search for BurpSuite on Windows drives from WSL
_WSL_DRIVE_MOUNTS = ["/mnt/c", "/mnt/d", "/mnt/e", "/mnt/f", "/mnt/g"]

# BurpSuite-related file patterns
_BURP_PATTERNS = ["BurpSuite", "burpsuite", "Burp Suite", "burp_suite", "burp"]
_LOADER_NAMES = ["loader.jar", "BurpLoader.jar", "burploader.jar"]
_BURP_JAR_NAMES = [
    "burpsuite_pro.jar", "BurpSuitePro.jar", "burpsuite_community.jar",
    "burpsuite.jar", "BurpSuite.jar",
]

# Default Burp proxy
BURP_PROXY_HOST = "127.0.0.1"
BURP_PROXY_PORT = 8080


class BurpSuiteIntegration:
    """Manages BurpSuite lifecycle for pentest engagements."""

    def __init__(
        self,
        burp_dir: str | pathlib.Path | None = None,
        proxy_host: str = BURP_PROXY_HOST,
        proxy_port: int = BURP_PROXY_PORT,
        projects_dir: str | pathlib.Path | None = None,
    ):
        self.burp_dir = pathlib.Path(burp_dir) if burp_dir else None
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.projects_dir = pathlib.Path(projects_dir) if projects_dir else None
        self._loader_path: pathlib.Path | None = None
        self._burp_jar_path: pathlib.Path | None = None
        self._burp_process: subprocess.Popen | None = None
        self._project_file: pathlib.Path | None = None

    async def setup(self, target: str, engagement_name: str | None = None) -> dict:
        """Full setup: find Burp → run loader → create project → launch Burp.

        Returns a dict with paths and status.
        """
        result = {
            "burp_dir": None,
            "loader_path": None,
            "burp_jar_path": None,
            "project_file": None,
            "proxy": f"{self.proxy_host}:{self.proxy_port}",
            "launched": False,
            "errors": [],
        }

        # Step 1: Find BurpSuite directory
        if self.burp_dir is None:
            self.burp_dir = self._find_burp_dir()
        if self.burp_dir is None:
            result["errors"].append("Could not find BurpSuite directory on any Windows drive")
            return result
        result["burp_dir"] = str(self.burp_dir)

        # Step 2: Find loader.jar and BurpSuite jar
        self._loader_path = self._find_file(self.burp_dir, _LOADER_NAMES)
        self._burp_jar_path = self._find_file(self.burp_dir, _BURP_JAR_NAMES)
        result["loader_path"] = str(self._loader_path) if self._loader_path else None
        result["burp_jar_path"] = str(self._burp_jar_path) if self._burp_jar_path else None

        if self._loader_path is None and self._burp_jar_path is None:
            result["errors"].append(
                f"No loader.jar or burpsuite.jar found in {self.burp_dir}"
            )
            return result

        # Step 3: Create project file
        if engagement_name is None:
            # Clean target name for filename
            clean_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
            date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            engagement_name = f"{clean_target}_{date_str}"

        if self.projects_dir is None:
            self.projects_dir = self.burp_dir / "projects"
        self.projects_dir.mkdir(parents=True, exist_ok=True)

        self._project_file = self.projects_dir / f"{engagement_name}.burp"
        result["project_file"] = str(self._project_file)

        # Step 4: Run loader first (if exists), then launch Burp
        try:
            await self._launch_burp()
            result["launched"] = True
        except Exception as e:
            result["errors"].append(f"Failed to launch BurpSuite: {e}")

        return result

    def _find_burp_dir(self) -> pathlib.Path | None:
        """Search Windows drives from WSL for BurpSuite directory."""
        for drive in _WSL_DRIVE_MOUNTS:
            drive_path = pathlib.Path(drive)
            if not drive_path.exists():
                continue
            # Search top-level and one level deep
            for pattern in _BURP_PATTERNS:
                # Direct match at drive root
                for candidate in drive_path.glob(f"{pattern}*"):
                    if candidate.is_dir():
                        logger.info("Found BurpSuite at %s", candidate)
                        return candidate
                # One level deep (e.g. /mnt/f/tools/burpsuite)
                for candidate in drive_path.glob(f"*/{pattern}*"):
                    if candidate.is_dir():
                        logger.info("Found BurpSuite at %s", candidate)
                        return candidate
        return None

    def _find_file(self, search_dir: pathlib.Path,
                   names: list[str]) -> pathlib.Path | None:
        """Find a file by name in directory (recursive, max depth 3)."""
        for name in names:
            # Direct
            direct = search_dir / name
            if direct.exists():
                return direct
            # One level deep
            for candidate in search_dir.glob(f"*/{name}"):
                if candidate.is_file():
                    return candidate
            # Two levels deep
            for candidate in search_dir.glob(f"*/*/{name}"):
                if candidate.is_file():
                    return candidate
        return None

    async def _launch_burp(self) -> None:
        """Run loader.jar first (if available), then launch BurpSuite."""
        java_cmd = self._find_java()

        # Step 1: Run loader.jar
        if self._loader_path:
            logger.info("Running BurpSuite loader: %s", self._loader_path)
            loader_proc = await asyncio.create_subprocess_exec(
                java_cmd, "-jar", str(self._loader_path),
                cwd=str(self._loader_path.parent),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Wait for loader to finish (it usually patches/prepares Burp)
            try:
                await asyncio.wait_for(loader_proc.wait(), timeout=60)
            except asyncio.TimeoutError:
                logger.warning("Loader took >60s — it may need interaction")

        # Step 2: Launch BurpSuite with project file
        burp_jar = self._burp_jar_path or self._loader_path
        if burp_jar is None:
            raise RuntimeError("No BurpSuite jar found")

        cmd = [java_cmd, "-jar", str(burp_jar)]

        # Add project file argument
        if self._project_file:
            cmd.extend(["--project-file", str(self._project_file)])

        logger.info("Launching BurpSuite: %s", " ".join(cmd))
        self._burp_process = subprocess.Popen(
            cmd,
            cwd=str(burp_jar.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait a moment for Burp to start
        await asyncio.sleep(3)

        if self._burp_process.poll() is not None:
            raise RuntimeError(
                f"BurpSuite exited immediately with code {self._burp_process.returncode}"
            )
        logger.info("BurpSuite launched (PID %d)", self._burp_process.pid)

    def _find_java(self) -> str:
        """Find java command — prefer JAVA_HOME, then PATH."""
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            java_bin = pathlib.Path(java_home) / "bin" / "java"
            if java_bin.exists():
                return str(java_bin)
        # Try just 'java' on PATH
        return "java"

    def is_running(self) -> bool:
        """Check if Burp is still running."""
        if self._burp_process is None:
            return False
        return self._burp_process.poll() is None

    async def wait_for_proxy(self, timeout: float = 30.0) -> bool:
        """Wait until Burp's proxy port is accepting connections."""
        import socket
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.proxy_host, self.proxy_port))
                sock.close()
                if result == 0:
                    logger.info("Burp proxy is ready at %s:%d",
                                self.proxy_host, self.proxy_port)
                    return True
            except Exception:
                pass
            await asyncio.sleep(1)
        return False

    def get_proxy_url(self) -> str:
        """Return the proxy URL for configuring the HTTP client."""
        return f"http://{self.proxy_host}:{self.proxy_port}"

    @property
    def project_file(self) -> pathlib.Path | None:
        return self._project_file

    def stop(self) -> None:
        """Stop the BurpSuite process."""
        if self._burp_process and self._burp_process.poll() is None:
            self._burp_process.terminate()
            try:
                self._burp_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._burp_process.kill()
            logger.info("BurpSuite stopped")
