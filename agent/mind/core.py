"""Mind Core — the integration layer that wires the pentester persona,
persistent memory, and continuous learning into the scanning pipeline.

This is what makes the agent "think" like a pentester:
  - Before scanning: load relevant intel for the target's tech stack
  - During scanning: use persona prompts for LLM-guided decisions
  - After scanning: record what worked for next time
  - Between engagements: learn from new CVEs, exploits, and research

Usage:
    from agent.mind.core import Mind

    mind = Mind()

    # Before a scan — gather intelligence
    await mind.prepare_for_target(tech_stack=["nginx", "react", "postgresql"])

    # During a scan — get pentester reasoning
    prompt = mind.think_about("Found 500 error with SQL syntax on /api/search?q=test")
    decision = ask("triage", prompt)

    # After a scan — record results
    mind.record_finding("sqli", success=True, tech_stack="postgresql")
    mind.record_finding("xss", success=False, tech_stack="react")

    # Daily — update intelligence
    summary = await mind.daily_update()
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from .memory import Memory, MIND_DATA_DIR
from .persona import PentesterPersona, pentester
from .learner import Learner
from .daily_update import DailyUpdate

logger = logging.getLogger(__name__)


class Mind:
    """The agent's mind — persona, memory, and learning combined.

    Instantiate once at startup. Thread-safe for reads; writes are
    append-only to disk.
    """

    def __init__(self, data_dir: Path | str = MIND_DATA_DIR,
                 nvd_api_key: str | None = None,
                 github_token: str | None = None):
        self.memory = Memory(data_dir)
        self.persona = pentester
        self.learner = Learner(self.memory)
        self._updater = DailyUpdate(
            memory=self.memory,
            nvd_api_key=nvd_api_key,
            github_token=github_token,
        )
        self._current_context: str = ""
        self._current_tech_stack: list[str] = []

    # ── Pre-scan intelligence ──────────────────────────────────

    async def prepare_for_target(self, tech_stack: list[str],
                                 target_url: str = "") -> dict:
        """Load intelligence relevant to the target before scanning.

        Searches CVE databases, ExploitDB, and GitHub advisories for
        anything matching the identified tech stack. Returns a summary
        of what was found.
        """
        self._current_tech_stack = tech_stack
        self._current_context = f"Target: {target_url}\nTech stack: {', '.join(tech_stack)}"

        logger.info("Mind: preparing intelligence for tech stack %s", tech_stack)

        # Search all sources
        results = await self._updater.search_for_target(tech_stack)

        # Get relevant existing memories
        relevant_cves = self.memory.get_relevant_cves(tech_stack, limit=20)
        effective_techniques = self.memory.get_effective_techniques()

        results["relevant_cves_in_memory"] = len(relevant_cves)
        results["effective_techniques"] = [
            {"id": t.technique_id, "effectiveness": round(t.effectiveness, 2)}
            for t in effective_techniques[:10]
        ]

        logger.info("Mind: found %d relevant CVEs, %d exploits, %d advisories",
                     len(results.get("cves", [])),
                     len(results.get("exploits", [])),
                     len(results.get("advisories", [])))

        return results

    # ── Pentester reasoning ────────────────────────────────────

    def system_prompt(self) -> str:
        """Get the full system prompt with persona + current context."""
        return self.persona.system_prompt(self._current_context)

    def think_about(self, observation: str) -> str:
        """Generate a triage prompt for an observation during testing.

        Feed this to the LLM via router.ask() to get pentester-quality
        decision making about what to do next.
        """
        # Enrich with relevant memories
        related = self.memory.search(observation, limit=5)
        context_parts = [self.persona.triage_prompt(observation)]

        if related:
            context_parts.append("\n## Relevant Prior Intelligence")
            for entry in related:
                summary = json.dumps(entry.data, default=str)[:200]
                context_parts.append(f"- [{entry.category}] {summary}")

        if self._current_tech_stack:
            context_parts.append(
                f"\n## Known Tech Stack\n{', '.join(self._current_tech_stack)}"
            )

        return "\n".join(context_parts)

    def analyze_chain(self, findings: list[dict]) -> str:
        """Analyze findings for exploit chains.

        Feed this to the LLM to get chain analysis with historical context.
        """
        # Enrich with what's worked before
        prompt = self.persona.chain_analysis_prompt(findings)

        effective = self.memory.get_effective_techniques()
        if effective:
            prompt += "\n\n## Previously Effective Techniques\n"
            for t in effective[:5]:
                prompt += (f"- {t.technique_id}: {t.effectiveness:.0%} success rate "
                           f"on {', '.join(t.tech_stacks[:3])}\n")

        return prompt

    def prioritize_targets(self, endpoints: list[dict],
                           tech_signals: list[str]) -> list[dict]:
        """Reorder endpoints by attack priority based on learned patterns.

        Uses the persona's priority list + historical effectiveness data
        to decide which endpoints to test first.
        """
        scored: list[tuple[float, dict]] = []

        for ep in endpoints:
            score = 0.0
            url = ep.get("url", "").lower()
            method = ep.get("method", "GET")
            params = ep.get("params", [])

            # Persona-based priority: admin, auth, file upload, etc.
            high_value_patterns = [
                ("admin", 3.0), ("auth", 2.5), ("login", 2.5),
                ("upload", 2.0), ("import", 2.0), ("export", 1.8),
                ("api", 1.5), ("user", 1.5), ("account", 1.5),
                ("payment", 2.0), ("checkout", 2.0),
                ("search", 1.3), ("debug", 3.0), ("super", 3.0),
                ("graphql", 2.0), ("ws", 1.5), ("webhook", 1.8),
            ]
            for pattern, weight in high_value_patterns:
                if pattern in url:
                    score += weight
                    break

            # POST/PUT/DELETE endpoints are higher priority than GET
            method_weights = {"POST": 1.5, "PUT": 1.3, "DELETE": 1.2, "PATCH": 1.3, "GET": 1.0}
            score *= method_weights.get(method, 1.0)

            # More parameters = more attack surface
            score += len(params) * 0.3

            # Boost if tech stack has known CVEs
            for signal in tech_signals:
                technique = self.memory.get_technique_score(signal)
                if technique.effectiveness > 0.5:
                    score *= 1.2

            scored.append((score, ep))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [ep for _, ep in scored]

    # ── Post-scan learning ─────────────────────────────────────

    def record_finding(self, scanner_id: str, success: bool,
                       tech_stack: str = "", details: dict | None = None) -> None:
        """Record the result of a scan attempt for future learning."""
        self.memory.record_technique_result(scanner_id, success, tech_stack)

        if success and details:
            self.memory.store_attack_pattern(
                f"{scanner_id}-{int(time.time())}",
                {
                    "scanner": scanner_id,
                    "tech_stack": tech_stack,
                    "endpoint_pattern": details.get("endpoint", ""),
                    "method": details.get("method", ""),
                    "tags": [scanner_id, tech_stack] if tech_stack else [scanner_id],
                    "description": f"Successful {scanner_id} on {tech_stack}",
                }
            )

    def record_engagement_summary(self, target: str, findings_count: int,
                                  tech_stack: list[str],
                                  scanners_used: list[str]) -> None:
        """Record a summary of an engagement (no sensitive data)."""
        from .memory import MemoryEntry
        entry = MemoryEntry(
            id=f"engagement:{int(time.time())}",
            category="engagement",
            timestamp=time.time(),
            data={
                "target_hash": hash(target) % (10 ** 8),  # anonymized
                "findings_count": findings_count,
                "tech_stack": tech_stack,
                "scanners_used": scanners_used,
            },
            tags=tech_stack + scanners_used,
            source="self",
            confidence=1.0,
        )
        self.memory.store(entry)

    # ── Intelligence updates ───────────────────────────────────

    async def daily_update(self) -> dict:
        """Run the full daily intelligence update."""
        summary = await self._updater.run_full()
        return summary.to_dict()

    async def quick_update(self) -> dict:
        """Quick update: CVEs + KEV only."""
        summary = await self._updater.run_quick()
        return summary.to_dict()

    def brief(self) -> str:
        """Get the current intelligence brief."""
        return self._updater.get_brief()

    def status(self) -> dict:
        """Return the mind's current state."""
        mem_summary = self.memory.summary()
        return {
            "memories": mem_summary["total_memories"],
            "by_category": mem_summary["by_category"],
            "techniques_tracked": mem_summary["techniques_tracked"],
            "current_tech_stack": self._current_tech_stack,
            "top_techniques": mem_summary.get("top_techniques", [])[:5],
        }
