"""Aggregated security RSS/Atom feeds — real-time threat intelligence.

Pulls from multiple security research sources to stay current on:
  - New exploitation techniques and bypasses
  - WAF evasion methods
  - Tool releases and updates
  - Bug bounty writeups and disclosed reports
  - Vendor security bulletins

Each source returns normalized FeedItem objects that the learner
can process into actionable knowledge.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from xml.etree import ElementTree

import httpx

logger = logging.getLogger(__name__)


@dataclass
class FeedItem:
    """One item from a security feed."""
    title: str
    url: str
    published: str
    summary: str
    source: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "url": self.url,
            "published": self.published,
            "summary": self.summary,
            "source": self.source,
            "tags": self.tags,
        }


# Feed sources — each is {name, url, type (rss|atom|json)}
SECURITY_FEEDS = [
    {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "type": "rss",
        "tags": ["web-security", "research", "burp"],
    },
    {
        "name": "PortSwigger Daily Swig",
        "url": "https://portswigger.net/daily-swig/rss",
        "type": "rss",
        "tags": ["web-security", "news"],
    },
    {
        "name": "Project Discovery Blog",
        "url": "https://blog.projectdiscovery.io/rss/",
        "type": "rss",
        "tags": ["tools", "nuclei", "recon"],
    },
    {
        "name": "Assetnote Research",
        "url": "https://blog.assetnote.io/feed.xml",
        "type": "atom",
        "tags": ["web-security", "research", "attack-surface"],
    },
    {
        "name": "NIST NVD Recent",
        "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
        "type": "rss",
        "tags": ["cve", "nvd"],
    },
    {
        "name": "Exploit Database",
        "url": "https://www.exploit-db.com/rss.xml",
        "type": "rss",
        "tags": ["exploits", "poc"],
    },
    {
        "name": "HackerOne Hacktivity",
        "url": "https://hackerone.com/hacktivity.json",
        "type": "json",
        "tags": ["bug-bounty", "disclosed"],
    },
    {
        "name": "Snyk Vulnerability DB",
        "url": "https://security.snyk.io/rss/all",
        "type": "rss",
        "tags": ["dependencies", "supply-chain"],
    },
]


class SecurityFeedAggregator:
    """Fetches and normalizes items from multiple security feeds."""

    def __init__(self, feeds: list[dict] | None = None):
        self.feeds = feeds or SECURITY_FEEDS

    async def fetch_all(self, max_per_feed: int = 20) -> list[FeedItem]:
        """Fetch recent items from all configured feeds."""
        all_items: list[FeedItem] = []

        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            for feed_config in self.feeds:
                try:
                    items = await self._fetch_one(client, feed_config, max_per_feed)
                    all_items.extend(items)
                except Exception as e:
                    logger.warning("Feed %s error: %s", feed_config["name"], e)

        all_items.sort(key=lambda i: i.published, reverse=True)
        logger.info("Security feeds: fetched %d items from %d sources",
                     len(all_items), len(self.feeds))
        return all_items

    async def _fetch_one(self, client: httpx.AsyncClient,
                         config: dict, max_items: int) -> list[FeedItem]:
        """Fetch items from a single feed source."""
        resp = await client.get(config["url"])
        resp.raise_for_status()

        feed_type = config.get("type", "rss")
        source_name = config["name"]
        base_tags = config.get("tags", [])

        if feed_type == "json":
            return self._parse_json_feed(resp.text, source_name, base_tags, max_items)
        elif feed_type == "atom":
            return self._parse_atom(resp.text, source_name, base_tags, max_items)
        else:
            return self._parse_rss(resp.text, source_name, base_tags, max_items)

    def _parse_rss(self, xml_text: str, source: str,
                   base_tags: list[str], max_items: int) -> list[FeedItem]:
        """Parse RSS 2.0 feed."""
        items = []
        try:
            root = ElementTree.fromstring(xml_text)
        except ElementTree.ParseError:
            return items

        for item_el in root.findall(".//item")[:max_items]:
            title = (item_el.findtext("title") or "").strip()
            link = (item_el.findtext("link") or "").strip()
            pub_date = (item_el.findtext("pubDate") or "").strip()
            description = (item_el.findtext("description") or "").strip()

            # Strip HTML from description
            description = re.sub(r"<[^>]+>", "", description)[:500]

            tags = list(base_tags)
            tags.extend(_extract_vuln_tags(title + " " + description))

            items.append(FeedItem(
                title=title, url=link, published=pub_date,
                summary=description, source=source, tags=tags,
            ))
        return items

    def _parse_atom(self, xml_text: str, source: str,
                    base_tags: list[str], max_items: int) -> list[FeedItem]:
        """Parse Atom feed."""
        items = []
        try:
            root = ElementTree.fromstring(xml_text)
        except ElementTree.ParseError:
            return items

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.findall("atom:entry", ns)[:max_items]:
            title = (entry.findtext("atom:title", namespaces=ns) or "").strip()
            link_el = entry.find("atom:link", ns)
            link = link_el.get("href", "") if link_el is not None else ""
            published = (entry.findtext("atom:published", namespaces=ns) or
                         entry.findtext("atom:updated", namespaces=ns) or "").strip()
            summary = (entry.findtext("atom:summary", namespaces=ns) or
                       entry.findtext("atom:content", namespaces=ns) or "").strip()
            summary = re.sub(r"<[^>]+>", "", summary)[:500]

            tags = list(base_tags)
            tags.extend(_extract_vuln_tags(title + " " + summary))

            items.append(FeedItem(
                title=title, url=link, published=published,
                summary=summary, source=source, tags=tags,
            ))
        return items

    def _parse_json_feed(self, json_text: str, source: str,
                         base_tags: list[str], max_items: int) -> list[FeedItem]:
        """Parse JSON-based feed (e.g., HackerOne Hacktivity)."""
        import json
        items = []
        try:
            data = json.loads(json_text)
        except (ValueError, TypeError):
            return items

        # Handle HackerOne's format
        reports = data if isinstance(data, list) else data.get("data", [])
        for report in reports[:max_items]:
            if isinstance(report, dict):
                title = report.get("title", report.get("attributes", {}).get("title", ""))
                url = report.get("url", "")
                published = report.get("disclosed_at", report.get("created_at", ""))
                summary = report.get("vulnerability_information", "")[:500]

                tags = list(base_tags)
                severity = report.get("severity", {})
                if isinstance(severity, dict) and severity.get("rating"):
                    tags.append(f"severity:{severity['rating']}")
                tags.extend(_extract_vuln_tags(title + " " + summary))

                items.append(FeedItem(
                    title=title, url=url, published=published,
                    summary=summary, source=source, tags=tags,
                ))
        return items


def _extract_vuln_tags(text: str) -> list[str]:
    """Extract vulnerability-related tags from text."""
    text_lower = text.lower()
    tags = []
    patterns = {
        "sqli": ["sql injection", "sqli", "blind sql"],
        "xss": ["cross-site scripting", "xss", "reflected xss", "stored xss"],
        "ssrf": ["ssrf", "server-side request"],
        "rce": ["remote code execution", "rce", "command execution"],
        "lfi": ["local file inclusion", "lfi", "path traversal", "directory traversal"],
        "xxe": ["xml external entity", "xxe"],
        "idor": ["idor", "insecure direct object"],
        "csrf": ["csrf", "cross-site request forgery"],
        "auth-bypass": ["authentication bypass", "auth bypass"],
        "deserialization": ["deserialization", "insecure deserialization"],
        "ssti": ["template injection", "ssti", "server-side template"],
        "open-redirect": ["open redirect"],
        "prototype-pollution": ["prototype pollution"],
        "race-condition": ["race condition", "toctou"],
        "jwt": ["jwt", "json web token"],
        "graphql": ["graphql"],
        "websocket": ["websocket"],
    }
    for tag, keywords in patterns.items():
        if any(kw in text_lower for kw in keywords):
            tags.append(tag)
    return tags
