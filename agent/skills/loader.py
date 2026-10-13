"""Skill loader — parses VAPT methodology files into structured data
the agent can query at runtime.

A skill is a directory containing:
  SKILL.md          — main methodology (phases, decision tree)
  references/*.md   — detailed checklists loaded on demand

The loader extracts:
  - phases with numbered steps
  - the decision tree (target type -> phase order)
  - reference file index (name -> path)
  - payload/checklist sections from references
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Phase:
    """One testing phase from the methodology."""
    number: int
    title: str
    raw: str  # full markdown text of this phase
    steps: list[str] = field(default_factory=list)


@dataclass
class ChecklistItem:
    """A single checklist entry from a reference file."""
    category: str  # e.g. "SQL Injection", "SSL Pinning Bypass"
    title: str
    content: str  # raw markdown block


@dataclass
class Skill:
    """Parsed VAPT methodology skill."""
    name: str
    description: str
    phases: list[Phase]
    decision_tree: str
    reference_index: dict[str, Path]  # ref name -> file path
    _refs_cache: dict[str, str] = field(default_factory=dict, repr=False)

    def get_phase(self, number: int) -> Optional[Phase]:
        """Get a phase by number."""
        for p in self.phases:
            if p.number == number:
                return p
        return None

    def phases_for_target(self, target_type: str) -> list[int]:
        """Return phase numbers relevant to a target type based on
        the decision tree."""
        t = target_type.lower()
        if "mobile" in t or "apk" in t or "ipa" in t:
            return [0, 1, 2, 3, 4, 5, 6]
        elif "api" in t:
            return [0, 1, 2, 3, 4, 6]
        else:  # web app (default)
            return [0, 1, 2, 3, 4, 5, 6]

    def load_reference(self, name: str) -> str:
        """Load a reference file by name (e.g. 'web-vapt'). Cached."""
        if name in self._refs_cache:
            return self._refs_cache[name]
        path = self.reference_index.get(name)
        if path is None:
            raise KeyError(f"Unknown reference: {name!r}. Available: {list(self.reference_index)}")
        text = path.read_text(encoding="utf-8")
        self._refs_cache[name] = text
        return text

    def get_checklists(self, ref_name: str) -> list[ChecklistItem]:
        """Parse a reference file into checklist items (one per ## section)."""
        text = self.load_reference(ref_name)
        return _parse_checklists(text)

    def get_payloads(self, ref_name: str, category: str) -> Optional[str]:
        """Get the raw content block for a specific category from a reference."""
        for item in self.get_checklists(ref_name):
            if item.category.lower() == category.lower():
                return item.content
        return None


SKILLS_DIR = Path(__file__).parent


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Extract YAML-ish frontmatter from SKILL.md. Returns (meta, body)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("---", 3)
    if end == -1:
        return {}, text
    fm_block = text[3:end].strip()
    body = text[end + 3:].strip()
    meta = {}
    for line in fm_block.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, body


def _parse_phases(body: str) -> list[Phase]:
    """Extract phases (## Phase N: Title) from the methodology body."""
    phase_pattern = re.compile(
        r"^## Phase (\d+)[:\s—–-]+(.+?)$", re.MULTILINE
    )
    matches = list(phase_pattern.finditer(body))
    phases = []
    for i, m in enumerate(matches):
        number = int(m.group(1))
        title = m.group(2).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        raw = body[start:end].strip()
        steps = []
        for line in raw.splitlines():
            line_s = line.strip()
            if re.match(r"^[-*]\s+\*\*\d+\.\d+", line_s) or re.match(r"^###\s+\d+\.\d+", line_s):
                steps.append(line_s)
            elif line_s.startswith("- ") and not line_s.startswith("- **Done"):
                steps.append(line_s)
        phases.append(Phase(number=number, title=title, raw=raw, steps=steps))
    return phases


def _extract_decision_tree(body: str) -> str:
    """Pull the decision tree block from the methodology."""
    marker = "## Decision Tree"
    idx = body.find(marker)
    if idx == -1:
        return ""
    block = body[idx:]
    code_start = block.find("```")
    if code_start == -1:
        return block.strip()
    code_end = block.find("```", code_start + 3)
    if code_end == -1:
        return block[code_start + 3:].strip()
    return block[code_start + 3:code_end].strip()


def _parse_checklists(text: str) -> list[ChecklistItem]:
    """Split a reference file into checklist items by ## heading."""
    heading_re = re.compile(r"^## (.+)$", re.MULTILINE)
    matches = list(heading_re.finditer(text))
    items = []
    for i, m in enumerate(matches):
        category = m.group(1).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = text[start:end].strip()
        title = category
        items.append(ChecklistItem(category=category, title=title, content=content))
    return items


def load_skill(skill_dir: Path | str = SKILLS_DIR / "vapt") -> Skill:
    """Load a VAPT skill from a directory containing SKILL.md + references/."""
    skill_dir = Path(skill_dir)
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

    text = skill_md.read_text(encoding="utf-8")
    meta, body = _parse_frontmatter(text)

    name = meta.get("name", skill_dir.name)
    description = meta.get("description", "")

    phases = _parse_phases(body)
    decision_tree = _extract_decision_tree(body)

    refs_dir = skill_dir / "references"
    reference_index: dict[str, Path] = {}
    if refs_dir.exists():
        for ref_file in sorted(refs_dir.glob("*.md")):
            ref_name = ref_file.stem  # e.g. "web-vapt"
            reference_index[ref_name] = ref_file

    return Skill(
        name=name,
        description=description,
        phases=phases,
        decision_tree=decision_tree,
        reference_index=reference_index,
    )
