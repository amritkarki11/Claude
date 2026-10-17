"""Daily Update — scheduled intelligence gathering pipeline.

Run this daily (or on-demand) to keep the agent's mind current:

    python -m agent.mind.daily_update          # full update
    python -m agent.mind.daily_update --quick   # CVEs + KEV only (faster)
    python -m agent.mind.daily_update --brief   # print today's brief only

The pipeline:
  1. Fetch new CVEs from NVD (last 7 days)
  2. Fetch CISA KEV updates (actively exploited)
  3. Search ExploitDB for new web exploits
  4. Fetch GitHub security advisories
  5. Pull security research RSS feeds
  6. Process everything through the learner
  7. Correlate across sources
  8. Generate recipe suggestions
  9. Write a daily brief to mind_data/daily_briefs/
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .memory import Memory, MIND_DATA_DIR
from .learner import Learner, LearningSummary
from .sources.nvd import NVDFeed
from .sources.cisa_kev import CISAKEVFeed
from .sources.exploitdb import ExploitDBFeed
from .sources.github_advisories import GitHubAdvisoryFeed
from .sources.security_feeds import SecurityFeedAggregator

logger = logging.getLogger(__name__)


class DailyUpdate:
    """Orchestrates the daily intelligence gathering pipeline."""

    def __init__(self, memory: Memory | None = None,
                 nvd_api_key: str | None = None,
                 github_token: str | None = None):
        self.memory = memory or Memory()
        self.learner = Learner(self.memory)

        self.nvd = NVDFeed(api_key=nvd_api_key)
        self.kev = CISAKEVFeed()
        self.exploitdb = ExploitDBFeed()
        self.github = GitHubAdvisoryFeed(token=github_token)
        self.feeds = SecurityFeedAggregator()

    async def run_full(self) -> LearningSummary:
        """Run the complete daily update pipeline."""
        summary = LearningSummary()
        start = time.monotonic()
        logger.info("Starting full daily intelligence update")

        # 1. NVD CVEs
        try:
            cves = await self.nvd.fetch_recent(days=7)
            summary.new_cves = self.learner.process_cves(cves)
            logger.info("NVD: %d new CVEs stored", summary.new_cves)
        except Exception as e:
            logger.error("NVD fetch failed: %s", e)

        # 2. CISA KEV
        try:
            kev_entries = await self.kev.fetch_recent(days=7)
            kev_count = self.learner.process_kev_entries(kev_entries)
            summary.new_cves += kev_count
            logger.info("CISA KEV: %d new actively-exploited entries", kev_count)
        except Exception as e:
            logger.error("CISA KEV fetch failed: %s", e)

        # 3. ExploitDB
        try:
            exploits = await self.exploitdb.search("", exploit_type="webapps", limit=50)
            summary.new_exploits = self.learner.process_exploits(exploits)
            logger.info("ExploitDB: %d new exploits stored", summary.new_exploits)
        except Exception as e:
            logger.error("ExploitDB fetch failed: %s", e)

        # 4. GitHub Advisories
        try:
            advisories = await self.github.fetch_recent(days=7)
            summary.new_advisories = self.learner.process_advisories(advisories)
            logger.info("GitHub: %d new advisories stored", summary.new_advisories)
        except Exception as e:
            logger.error("GitHub advisories fetch failed: %s", e)

        # 5. Security RSS feeds
        try:
            feed_items = await self.feeds.fetch_all(max_per_feed=15)
            summary.new_feed_items = self.learner.process_feed_items(feed_items)
            logger.info("Feeds: %d new items stored", summary.new_feed_items)
        except Exception as e:
            logger.error("Feed aggregation failed: %s", e)

        # 6. Correlate
        summary.correlations_found = self.learner.correlate()

        # 7. Recipe suggestions
        suggestions = self.learner.generate_recipe_suggestions()
        summary.recipe_suggestions = len(suggestions)

        # 8. High priority items
        summary.high_priority_items = self.learner.get_priority_intel(limit=10)

        elapsed = time.monotonic() - start
        logger.info("Daily update complete in %.1fs", elapsed)

        # Write daily brief
        self._write_brief(summary, suggestions, elapsed)

        return summary

    async def run_quick(self) -> LearningSummary:
        """Quick update: CVEs + KEV only (for rate-limited environments)."""
        summary = LearningSummary()
        logger.info("Starting quick intelligence update (CVEs + KEV)")

        try:
            cves = await self.nvd.fetch_recent(days=3, max_results=50)
            summary.new_cves = self.learner.process_cves(cves)
        except Exception as e:
            logger.error("NVD fetch failed: %s", e)

        try:
            kev_entries = await self.kev.fetch_recent(days=7)
            kev_count = self.learner.process_kev_entries(kev_entries)
            summary.new_cves += kev_count
        except Exception as e:
            logger.error("CISA KEV fetch failed: %s", e)

        summary.correlations_found = self.learner.correlate()
        summary.high_priority_items = self.learner.get_priority_intel(limit=5)
        return summary

    async def search_for_target(self, tech_stack: list[str]) -> dict:
        """Search all sources for intel relevant to a specific tech stack.

        Call this before scanning a target to load targeted intelligence.
        """
        results = {
            "cves": [],
            "exploits": [],
            "advisories": [],
            "memory_hits": [],
        }

        for tech in tech_stack:
            # Search NVD
            try:
                cves = await self.nvd.fetch_by_keyword(tech, days=90, max_results=20)
                new = self.learner.process_cves(cves)
                results["cves"].extend([c.to_dict() for c in cves[:5]])
            except Exception as e:
                logger.warning("NVD search for %s failed: %s", tech, e)

            # Search ExploitDB
            try:
                exploits = await self.exploitdb.search_by_product(tech, limit=10)
                self.learner.process_exploits(exploits)
                results["exploits"].extend([e.to_dict() for e in exploits[:5]])
            except Exception as e:
                logger.warning("ExploitDB search for %s failed: %s", tech, e)

            # Search GitHub advisories
            try:
                advisories = await self.github.search(tech, limit=10)
                self.learner.process_advisories(advisories)
                results["advisories"].extend([a.to_dict() for a in advisories[:5]])
            except Exception as e:
                logger.warning("GitHub search for %s failed: %s", tech, e)

        # Search memory for anything already known
        for tech in tech_stack:
            hits = self.memory.search(tech, limit=10)
            results["memory_hits"].extend([
                {"id": h.id, "category": h.category, "tags": h.tags[:5]}
                for h in hits
            ])

        self.learner.correlate()
        return results

    def get_brief(self) -> str:
        """Generate a text brief of what the mind knows right now."""
        summary = self.memory.summary()
        priority = self.learner.get_priority_intel(limit=10)

        lines = [
            "=" * 60,
            "  PENTEST AGENT — INTELLIGENCE BRIEF",
            "=" * 60,
            f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            f"  Total memories:    {summary['total_memories']}",
        ]
        for cat, count in sorted(summary["by_category"].items()):
            lines.append(f"    {cat:20s} {count}")
        lines.append(f"  Techniques tracked: {summary['techniques_tracked']}")
        lines.append("")

        if priority:
            lines.append("  TOP PRIORITY INTELLIGENCE")
            lines.append("  " + "-" * 40)
            for item in priority:
                lines.append(f"  [{item['score']:.2f}] {item['summary']}")
            lines.append("")

        if summary.get("top_techniques"):
            lines.append("  TOP EFFECTIVE TECHNIQUES")
            lines.append("  " + "-" * 40)
            for t in summary["top_techniques"][:5]:
                lines.append(f"  {t['id']:30s} {t['effectiveness']:.0%}")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _write_brief(self, summary: LearningSummary,
                     suggestions: list[dict], elapsed: float) -> None:
        """Write the daily brief to a JSON file."""
        briefs_dir = MIND_DATA_DIR / "daily_briefs"
        briefs_dir.mkdir(parents=True, exist_ok=True)

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        brief_path = briefs_dir / f"{today}.json"

        brief = {
            "date": today,
            "elapsed_seconds": round(elapsed, 1),
            "summary": summary.to_dict(),
            "recipe_suggestions": suggestions[:10],
            "memory_state": self.memory.summary(),
        }

        brief_path.write_text(json.dumps(brief, indent=2), encoding="utf-8")
        logger.info("Daily brief written to %s", brief_path)


async def _main():
    """CLI entry point for daily updates."""
    ap = argparse.ArgumentParser(description="Pentest Agent — Daily Intelligence Update")
    ap.add_argument("--quick", action="store_true", help="Quick update (CVEs + KEV only)")
    ap.add_argument("--brief", action="store_true", help="Print current intelligence brief")
    ap.add_argument("--nvd-key", help="NVD API key for higher rate limits")
    ap.add_argument("--github-token", help="GitHub token for advisory API")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    updater = DailyUpdate(
        nvd_api_key=args.nvd_key,
        github_token=args.github_token,
    )

    if args.brief:
        print(updater.get_brief())
        return

    if args.quick:
        summary = await updater.run_quick()
    else:
        summary = await updater.run_full()

    print(f"\nUpdate complete:")
    print(f"  New CVEs:       {summary.new_cves}")
    print(f"  New exploits:   {summary.new_exploits}")
    print(f"  New advisories: {summary.new_advisories}")
    print(f"  New feed items: {summary.new_feed_items}")
    print(f"  Correlations:   {summary.correlations_found}")
    print(f"  Recipe ideas:   {summary.recipe_suggestions}")

    if summary.high_priority_items:
        print(f"\n  HIGH PRIORITY:")
        for item in summary.high_priority_items[:5]:
            print(f"    [{item['score']:.2f}] {item['summary']}")


if __name__ == "__main__":
    asyncio.run(_main())
