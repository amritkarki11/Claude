"""Model router — one interface to three brains, routed by job.

Tiers:
  local    — on-box (Ollama). Private, free. Bulk extraction + triage.
  fast     — free cloud (Groq). Hypothesis generation + report drafting.
  frontier — paid cloud (Claude). Deep reasoning. Budget-capped.

Every cloud call passes through:
  1. Regex redaction (fast, deterministic)
  2. Optional local-model redaction check (context-aware)
  3. Budget gate (frontier only)
"""
from __future__ import annotations

import json
import os
import pathlib
from datetime import datetime, timezone

import yaml
from litellm import completion

from .budget import Budget
from .redact import redact

_CFG = yaml.safe_load(
    (pathlib.Path(__file__).parent.parent / "config.yaml").read_text()
)
_MODELS = _CFG["models"]
_ROUTING = _CFG["routing"]
_REDACT = _CFG["privacy"]["redact_before_cloud"]
_BUDGET_CAP = _CFG.get("budget", {}).get("frontier_usd_cap", 100)

# Global budget tracker
budget = Budget(
    cap_usd=_BUDGET_CAP,
    log_path=pathlib.Path(__file__).parent.parent / "outputs" / "budget.jsonl",
)


class BudgetExhausted(RuntimeError):
    """Raised when a frontier call would exceed the budget cap."""


def ask(job: str, prompt: str, system: str = "", **kw) -> str:
    """Route a job to the appropriate model tier.

    Args:
        job: routing key from config.yaml (triage, hypothesis, etc.)
        prompt: the user message content
        system: optional system message
        **kw: passed through to litellm.completion

    Returns:
        Model response text.

    Raises:
        ValueError: unknown job type
        BudgetExhausted: frontier budget exceeded
    """
    if job not in _ROUTING:
        raise ValueError(f"Unknown job {job!r}; add it to routing in config.yaml")

    tier = _ROUTING[job]
    model = _MODELS[tier]
    is_local = tier == "local"

    # Budget gate for frontier calls
    if tier == "frontier" and not budget.allow():
        raise BudgetExhausted(
            f"Frontier budget exhausted (${budget.spent_usd:.2f} / "
            f"${budget.cap_usd:.2f}). Falling back or stopping."
        )

    # Redaction for cloud calls
    text = prompt
    if not is_local and _REDACT:
        text = redact(prompt)
        sys_text = redact(system) if system else system
    else:
        sys_text = system

    # Build messages
    msgs = []
    if sys_text:
        msgs.append({"role": "system", "content": sys_text})
    msgs.append({"role": "user", "content": text})

    # Model-specific config
    extra = {}
    if is_local:
        extra["api_base"] = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")

    resp = completion(model=model, messages=msgs, **extra, **kw)

    # Track frontier spend
    if tier == "frontier":
        usage = resp.get("usage", {})
        budget.record(
            job=job,
            model=model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    return resp["choices"][0]["message"]["content"]


def ask_with_prompt(job: str, prompt_tuple: tuple[str, str], **kw) -> str:
    """Convenience: takes a (system, user) tuple from agent.prompts."""
    system, user = prompt_tuple
    return ask(job, prompt=user, system=system, **kw)


def get_budget_summary() -> dict:
    """Return current budget usage summary."""
    return budget.summary()


def available_tiers() -> dict[str, str]:
    """Return {tier: model} for configured tiers."""
    return dict(_MODELS)
