"""Local LLM translator — converts natural language to slash commands.

Uses Ollama (llama3.2:1b) running locally. No data leaves the machine.
Strict whitelist: only known commands are accepted from LLM output.
"""
from __future__ import annotations

import httpx
import logging
import re

logger = logging.getLogger(__name__)

_OLLAMA_URL = "http://localhost:11434/api/generate"
_MODEL = "llama3.2:1b"

_SYSTEM_PROMPT = (
    "You are a command translator for a pentesting agent. "
    "The user will give you a natural language request. "
    "You must translate it into EXACTLY ONE of the following commands. "
    "Do not explain, do not add markdown, just output the command.\n"
    "Available commands:\n"
    "- /recon <target> [optional flags: /allports]\n"
    "- /fullscan <target> [optional flags: /allports]\n"
    "- /analyze <filepath>\n"
    "- /commands\n"
    "- /exit\n"
    "User request: "
)

_VALID_COMMANDS = {"recon", "fullscan", "analyze", "commands", "exit"}

_TIMEOUT = 30.0


def _validate_command(raw: str) -> str | None:
    """Return the cleaned command if it's on the whitelist, else None."""
    raw = raw.strip()
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("/"):
            cmd_name = line.split()[0].lstrip("/").lower()
            if cmd_name in _VALID_COMMANDS:
                return line
    return None


def translate_to_command(user_input: str) -> str:
    """Translate natural language to a slash command via local Ollama.

    Returns the translated command string on success,
    or an empty string on failure (caller should show error).
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
        resp = httpx.post(
            _OLLAMA_URL,
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except httpx.ConnectError:
        logger.warning("Ollama not reachable at %s", _OLLAMA_URL)
        return ""
    except httpx.HTTPStatusError as exc:
        logger.warning("Ollama returned %s", exc.response.status_code)
        return ""
    except httpx.TimeoutException:
        logger.warning("Ollama request timed out after %.0fs", _TIMEOUT)
        return ""

    data = resp.json()
    raw_response = data.get("response", "").strip()
    logger.debug("Ollama raw response: %r", raw_response)

    validated = _validate_command(raw_response)
    if validated is None:
        logger.warning("LLM output failed validation: %r", raw_response)
        return ""

    return validated
