"""Feature gate for LLM functionality.

The LLM is NEVER in the finding-decision path. It provides:
  - Recon analysis suggestions
  - Report enrichment (description quality, remediation detail)
  - Priority/severity suggestions (advisory only, human confirms)

Everything works without it; it just works better with it.

Enable via:
  - AUTON_LLM_ENABLED=1 environment variable
  - --llm flag on CLI
  - config.yaml llm.enabled: true
"""
from __future__ import annotations

import functools
import logging
import os
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable)

_enabled: bool | None = None


def is_enabled() -> bool:
    """Check if LLM features are enabled."""
    global _enabled
    if _enabled is not None:
        return _enabled

    env = os.environ.get("AUTON_LLM_ENABLED", "").strip().lower()
    _enabled = env in ("1", "true", "yes")
    return _enabled


def set_enabled(value: bool) -> None:
    """Explicitly enable/disable LLM features (for CLI --llm flag)."""
    global _enabled
    _enabled = value
    logger.info("LLM features %s", "enabled" if value else "disabled")


def llm_optional(fallback: Any = None) -> Callable[[F], F]:
    """Decorator: calls the function only if LLM is enabled, else returns fallback.

    Usage:
        @llm_optional(fallback="")
        def enrich_description(finding: dict) -> str:
            ...  # uses LLM
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not is_enabled():
                return fallback
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.warning("LLM call failed, degrading gracefully: %s", e)
                return fallback
        return wrapper  # type: ignore
    return decorator


def llm_optional_async(fallback: Any = None) -> Callable:
    """Async version of llm_optional."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not is_enabled():
                return fallback
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.warning("LLM call failed, degrading gracefully: %s", e)
                return fallback
        return wrapper
    return decorator
