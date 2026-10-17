"""Multi-terminal support — spawn and manage additional terminal sessions.

This module allows the pentest agent to open additional terminals for:
  - Monitoring traffic (e.g. tailing proxy logs)
  - Running BurpSuite or other tools in parallel
  - Watching Playwright browser sessions
  - Running auxiliary scripts during engagement

Works on Linux/macOS (tmux, screen, xterm) and WSL (cmd.exe, wt.exe).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TerminalSession:
    """Represents a spawned terminal session."""
    id: str
    name: str
    command: str
    pid: int | None = None
    process: subprocess.Popen | None = field(default=None, repr=False)
    backend: str = ""  # "tmux", "screen", "xterm", "wsl-wt", "wsl-cmd"


class TerminalManager:
    """Manage multiple terminal sessions for the pentest agent."""

    def __init__(self):
        self._sessions: dict[str, TerminalSession] = {}
        self._counter = 0
        self._backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """Detect which terminal multiplexer / spawner is available."""
        # Check if we're in WSL
        is_wsl = os.path.exists("/proc/version")
        if is_wsl:
            try:
                with open("/proc/version") as f:
                    version = f.read().lower()
                if "microsoft" in version or "wsl" in version:
                    # Check for Windows Terminal
                    if shutil.which("wt.exe"):
                        return "wsl-wt"
                    if shutil.which("cmd.exe"):
                        return "wsl-cmd"
            except Exception:
                pass

        # Check for tmux (preferred on Linux/macOS)
        if shutil.which("tmux"):
            return "tmux"

        # Check for screen
        if shutil.which("screen"):
            return "screen"

        # Check for xterm (X11)
        if shutil.which("xterm") and os.environ.get("DISPLAY"):
            return "xterm"

        # Fallback: background process
        return "background"

    async def spawn(self, name: str, command: str,
                    cwd: str | None = None) -> TerminalSession:
        """Spawn a new terminal session running the given command.

        Args:
            name: Human-readable name for the session
            command: Shell command to run in the new terminal
            cwd: Working directory for the command

        Returns:
            TerminalSession with session metadata
        """
        self._counter += 1
        session_id = f"term-{self._counter:03d}"

        session = TerminalSession(
            id=session_id,
            name=name,
            command=command,
            backend=self._backend,
        )

        try:
            if self._backend == "tmux":
                session = await self._spawn_tmux(session, cwd)
            elif self._backend == "screen":
                session = await self._spawn_screen(session, cwd)
            elif self._backend == "wsl-wt":
                session = await self._spawn_wsl_wt(session, cwd)
            elif self._backend == "wsl-cmd":
                session = await self._spawn_wsl_cmd(session, cwd)
            elif self._backend == "xterm":
                session = await self._spawn_xterm(session, cwd)
            else:
                session = await self._spawn_background(session, cwd)

            self._sessions[session_id] = session
            logger.info("Spawned terminal %s (%s): %s", session_id, name,
                        command[:80])

        except Exception as e:
            logger.error("Failed to spawn terminal %s: %s", name, e)
            raise

        return session

    async def _spawn_tmux(self, session: TerminalSession,
                          cwd: str | None) -> TerminalSession:
        """Spawn a new tmux window/pane."""
        tmux_session = "pentest-agent"
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", session.name)

        # Check if our tmux session exists
        check = subprocess.run(
            ["tmux", "has-session", "-t", tmux_session],
            capture_output=True,
        )
        if check.returncode != 0:
            # Create new tmux session (detached)
            subprocess.run(
                ["tmux", "new-session", "-d", "-s", tmux_session,
                 "-n", safe_name],
                check=True,
            )
            # Send command to the initial window (literal mode)
            subprocess.run(
                ["tmux", "send-keys", "-t", f"{tmux_session}:{safe_name}",
                 "-l", session.command],
                check=True,
            )
            subprocess.run(
                ["tmux", "send-keys", "-t", f"{tmux_session}:{safe_name}",
                 "Enter"],
                check=True,
            )
        else:
            # Create new window in existing session
            subprocess.run(
                ["tmux", "new-window", "-t", tmux_session,
                 "-n", safe_name],
                check=True,
            )
            if cwd:
                subprocess.run(
                    ["tmux", "send-keys", "-t",
                     f"{tmux_session}:{safe_name}",
                     "-l", f"cd {shlex.quote(cwd)}"],
                    check=True,
                )
                subprocess.run(
                    ["tmux", "send-keys", "-t",
                     f"{tmux_session}:{safe_name}",
                     "Enter"],
                    check=True,
                )
            subprocess.run(
                ["tmux", "send-keys", "-t",
                 f"{tmux_session}:{safe_name}",
                 "-l", session.command],
                check=True,
            )
            subprocess.run(
                ["tmux", "send-keys", "-t",
                 f"{tmux_session}:{safe_name}",
                 "Enter"],
                check=True,
            )

        return session

    async def _spawn_screen(self, session: TerminalSession,
                            cwd: str | None) -> TerminalSession:
        """Spawn a new screen session."""
        cmd = ["screen", "-dmS", session.id, "bash", "-c", session.command]
        proc = subprocess.Popen(cmd, cwd=cwd)
        session.pid = proc.pid
        session.process = proc
        return session

    async def _spawn_wsl_wt(self, session: TerminalSession,
                            cwd: str | None) -> TerminalSession:
        """Open a new tab in Windows Terminal from WSL."""
        # wt.exe can be called from WSL to open a new tab
        wsl_cmd = session.command
        cmd = ["wt.exe", "new-tab", "--title", session.name,
               "wsl.exe", "-e", "bash", "-c", wsl_cmd]
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        session.pid = proc.pid
        session.process = proc
        return session

    async def _spawn_wsl_cmd(self, session: TerminalSession,
                             cwd: str | None) -> TerminalSession:
        """Open a new cmd.exe window from WSL."""
        wsl_cmd = session.command
        cmd = ["cmd.exe", "/c", "start", "cmd.exe", "/k",
               f"wsl.exe -e bash -c '{wsl_cmd}'"]
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        session.pid = proc.pid
        session.process = proc
        return session

    async def _spawn_xterm(self, session: TerminalSession,
                           cwd: str | None) -> TerminalSession:
        """Spawn a new xterm window."""
        cmd = ["xterm", "-T", session.name, "-e", session.command]
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        session.pid = proc.pid
        session.process = proc
        return session

    async def _spawn_background(self, session: TerminalSession,
                                cwd: str | None) -> TerminalSession:
        """Fallback: run as a background process with log file."""
        log_dir = os.path.join(cwd or os.getcwd(), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"{session.id}.log")

        with open(log_file, "w") as log_f:
            proc = subprocess.Popen(
                ["bash", "-c", session.command],
                cwd=cwd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
            )
        session.pid = proc.pid
        session.process = proc
        logger.info("Background terminal %s logging to %s",
                    session.id, log_file)
        return session

    def list_sessions(self) -> list[TerminalSession]:
        """Return all active sessions."""
        return [s for s in self._sessions.values()
                if s.process is None or s.process.poll() is None]

    def kill_session(self, session_id: str) -> bool:
        """Kill a terminal session by ID."""
        session = self._sessions.get(session_id)
        if session is None:
            return False

        if self._backend == "tmux":
            subprocess.run(
                ["tmux", "kill-window", "-t",
                 f"pentest-agent:{session.name}"],
                capture_output=True,
            )
        elif session.process and session.process.poll() is None:
            session.process.terminate()
            try:
                session.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                session.process.kill()

        del self._sessions[session_id]
        return True

    def kill_all(self) -> int:
        """Kill all terminal sessions. Returns count killed."""
        ids = list(self._sessions.keys())
        count = 0
        for sid in ids:
            if self.kill_session(sid):
                count += 1
        return count

    @property
    def backend_name(self) -> str:
        """Human-readable name of the terminal backend."""
        return {
            "tmux": "tmux (multiplexer)",
            "screen": "GNU Screen",
            "wsl-wt": "Windows Terminal (WSL)",
            "wsl-cmd": "CMD.exe (WSL)",
            "xterm": "XTerm (X11)",
            "background": "Background process",
        }.get(self._backend, self._backend)
