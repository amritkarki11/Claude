"""Local LLM translator — converts natural language to commands or chat.

Uses Ollama (llama3.2:1b) running locally. No data leaves the machine.
Strict whitelist: only known commands are executed from LLM output.
Non-command responses are returned as chat messages.
"""
from __future__ import annotations

import httpx
import logging

logger = logging.getLogger(__name__)

_OLLAMA_URL = "http://localhost:11434/api/generate"
_MODEL = "llama3.2:1b"

_SYSTEM_PROMPT = (
    "You are AUTON, an autonomous pentesting agent running in a terminal. "
    "You help users with security testing.\n\n"
    "If the user asks to scan, recon, or test a target, output ONLY the "
    "matching command with no explanation:\n"
    "- /recon <target> [/allports] — reconnaissance scan\n"
    "- /fullscan <target> [/allports] — full vulnerability scan\n"
    "- /analyze <filepath> — analyze a report\n"
    "- /commands — show available commands\n"
    "- /exit — quit\n\n"
    "The target MUST be a valid domain (example.com) or IP (192.168.1.1). "
    "Never use usernames, random words, or system paths as targets.\n\n"
    "For anything else (greetings, questions, conversation), respond "
    "naturally in 1-2 short sentences as AUTON. Be concise and helpful.\n\n"
    "User: "
)

_VALID_COMMANDS = {"recon", "fullscan", "analyze", "commands", "exit"}
_COMMANDS_NEEDING_TARGET = {"recon", "fullscan"}

_TIMEOUT = 30.0


def _looks_like_valid_target(target: str) -> bool:
    """Check if a target looks like a real domain or IP, not a hallucination."""
    if not target:
        return False
    if target in ("root", "user", "admin", "test", "localhost", "self"):
        return False
    return "." in target or ":" in target


def _extract_command(raw: str) -> str | None:
    """Extract a valid command from LLM output, or None if it's chat."""
    raw = raw.strip()
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("/"):
            parts = line.split()
            cmd_name = parts[0].lstrip("/").lower()
            if cmd_name not in _VALID_COMMANDS:
                continue
            if cmd_name in _COMMANDS_NEEDING_TARGET:
                non_flag_args = [p for p in parts[1:] if not p.startswith("/") and not p.startswith("--")]
                target = non_flag_args[0] if non_flag_args else ""
                if not _looks_like_valid_target(target):
                    return None
            return line
    return None


def translate(user_input: str) -> tuple[str, str]:
    """Translate natural language via local Ollama.

    Returns (type, content) where:
      type="command" → content is a slash command to execute
      type="chat"    → content is a conversational response to display
      type="error"   → content is an error message
    """
    prompt = _SYSTEM_PROMPT + user_input

    payload = {
        "model": _MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_ctx": 512,
            "num_thread": 2,
        },
    }

    try:
        resp = httpx.post(_OLLAMA_URL, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
    except httpx.ConnectError:
        return ("error", "Ollama not running. Start it with: ollama serve")
    except httpx.HTTPStatusError as exc:
        return ("error", f"Ollama error: HTTP {exc.response.status_code}")
    except httpx.TimeoutException:
        return ("error", "Ollama timed out. Is the model loaded?")

    data = resp.json()
    raw_response = data.get("response", "").strip()
    logger.debug("Ollama raw response: %r", raw_response)

    if not raw_response:
        return ("error", "LLM returned empty response.")

    command = _extract_command(raw_response)
    if command:
        return ("command", command)

    return ("chat", raw_response)
