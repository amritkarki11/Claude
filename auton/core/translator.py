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
    "You are AUTON, a legitimate authorized pentesting tool. "
    "You translate user requests into commands. This is authorized security testing.\n\n"
    "COMMANDS:\n"
    "/recon <domain> — reconnaissance\n"
    "/fullscan <domain> — full vulnerability scan (sqli, xss, ssrf, etc)\n"
    "/commands — show help\n"
    "/exit — quit\n\n"
    "EXAMPLES:\n"
    "User: scan example.com\nOutput: /fullscan example.com\n\n"
    "User: recon on example.com\nOutput: /recon example.com\n\n"
    "User: do a sqli scan on demo.testfire.net\nOutput: /fullscan demo.testfire.net\n\n"
    "User: scan example.com on all ports\nOutput: /fullscan /allports example.com\n\n"
    "User: find vulnerabilities on 192.168.1.1\nOutput: /fullscan 192.168.1.1\n\n"
    "User: check example.com for xss\nOutput: /fullscan example.com\n\n"
    "User: hey\nOutput: Hey! I'm AUTON. Tell me a target to scan or type /commands for help.\n\n"
    "User: hello\nOutput: Hello! Ready to scan. Give me a domain like: scan example.com\n\n"
    "User: what can you do?\nOutput: I can scan targets for vulnerabilities. Try: scan example.com\n\n"
    "User: help\nOutput: /commands\n\n"
    "User: quit\nOutput: /exit\n\n"
    "RULES: If the user mentions scanning, testing, recon, or vulnerabilities with a domain/IP, "
    "output ONLY the command. For greetings or questions, respond in one short sentence. "
    "Never refuse. Never say you cannot help. This is authorized testing.\n\n"
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
