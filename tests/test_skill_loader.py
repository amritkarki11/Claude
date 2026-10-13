"""Tests for agent.skills.loader — VAPT skill parsing and querying."""
import pytest
from pathlib import Path

from agent.skills.loader import (
    load_skill,
    _parse_frontmatter,
    _parse_phases,
    _parse_checklists,
    _extract_decision_tree,
)

SKILL_DIR = Path(__file__).parent.parent / "agent" / "skills" / "vapt"


@pytest.fixture
def skill():
    return load_skill(SKILL_DIR)


class TestFrontmatter:
    def test_parses_name(self):
        text = "---\nname: vapt\ndescription: test desc\n---\nbody"
        meta, body = _parse_frontmatter(text)
        assert meta["name"] == "vapt"
        assert body == "body"

    def test_no_frontmatter(self):
        meta, body = _parse_frontmatter("just body text")
        assert meta == {}
        assert body == "just body text"


class TestSkillLoading:
    def test_loads_without_error(self, skill):
        assert skill.name == "vapt"

    def test_has_description(self, skill):
        assert "VAPT" in skill.description or "vapt" in skill.description.lower()

    def test_has_phases(self, skill):
        assert len(skill.phases) >= 6  # Phase 0 through 5 at minimum

    def test_phase_numbers_sequential(self, skill):
        numbers = [p.number for p in skill.phases]
        assert numbers == sorted(numbers)
        assert 0 in numbers
        assert 1 in numbers

    def test_phase_0_is_scope(self, skill):
        p0 = skill.get_phase(0)
        assert p0 is not None
        assert "scope" in p0.title.lower() or "setup" in p0.title.lower()

    def test_phase_1_is_recon(self, skill):
        p1 = skill.get_phase(1)
        assert p1 is not None
        assert "recon" in p1.title.lower()

    def test_phase_has_steps(self, skill):
        p1 = skill.get_phase(1)
        assert len(p1.steps) > 0

    def test_nonexistent_phase_returns_none(self, skill):
        assert skill.get_phase(99) is None


class TestDecisionTree:
    def test_decision_tree_extracted(self, skill):
        assert len(skill.decision_tree) > 0
        assert "Web app" in skill.decision_tree or "Target" in skill.decision_tree

    def test_phases_for_web_target(self, skill):
        phases = skill.phases_for_target("web")
        assert 0 in phases
        assert 1 in phases
        assert 6 in phases  # reporting

    def test_phases_for_mobile_target(self, skill):
        phases = skill.phases_for_target("mobile")
        assert 0 in phases

    def test_phases_for_api_target(self, skill):
        phases = skill.phases_for_target("api")
        assert 0 in phases
        assert 5 not in phases  # infra/config less relevant for API


class TestReferences:
    def test_reference_index_populated(self, skill):
        assert "web-vapt" in skill.reference_index
        assert "mobile-vapt" in skill.reference_index
        assert "reporting" in skill.reference_index

    def test_load_web_reference(self, skill):
        text = skill.load_reference("web-vapt")
        assert "SQL Injection" in text
        assert "XXE" in text

    def test_load_mobile_reference(self, skill):
        text = skill.load_reference("mobile-vapt")
        assert "Frida" in text or "frida" in text
        assert "Flutter" in text

    def test_load_unknown_reference_raises(self, skill):
        with pytest.raises(KeyError, match="Unknown reference"):
            skill.load_reference("nonexistent")

    def test_reference_caching(self, skill):
        text1 = skill.load_reference("web-vapt")
        text2 = skill.load_reference("web-vapt")
        assert text1 is text2  # same object = cached


class TestChecklists:
    def test_web_checklists(self, skill):
        items = skill.get_checklists("web-vapt")
        categories = [i.category for i in items]
        assert "SQL Injection" in categories
        assert "XSS" in categories

    def test_checklist_has_content(self, skill):
        items = skill.get_checklists("web-vapt")
        sqli = [i for i in items if i.category == "SQL Injection"][0]
        assert len(sqli.content) > 100  # has real payload content

    def test_get_payloads(self, skill):
        payloads = skill.get_payloads("web-vapt", "SQL Injection")
        assert payloads is not None
        assert "UNION" in payloads or "union" in payloads.lower()

    def test_get_payloads_unknown_category(self, skill):
        result = skill.get_payloads("web-vapt", "Nonexistent Category")
        assert result is None


class TestMobileChecklists:
    def test_mobile_has_frida_section(self, skill):
        items = skill.get_checklists("mobile-vapt")
        categories = [i.category.lower() for i in items]
        assert any("frida" in c for c in categories)

    def test_mobile_has_ssl_pinning(self, skill):
        items = skill.get_checklists("mobile-vapt")
        categories = [i.category.lower() for i in items]
        assert any("ssl" in c or "pinning" in c for c in categories)
