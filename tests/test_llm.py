"""Tests for LLM feature gate and augmentation layer."""
import os
import pytest
from unittest.mock import patch, MagicMock

from agent.llm.gate import is_enabled, set_enabled, llm_optional, llm_optional_async, _enabled


# --- gate tests ---

class TestIsEnabled:
    def setup_method(self):
        import agent.llm.gate as g
        g._enabled = None

    def test_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            import agent.llm.gate as g
            g._enabled = None
            assert g.is_enabled() is False

    def test_enabled_via_env_1(self):
        with patch.dict(os.environ, {"AUTON_LLM_ENABLED": "1"}):
            import agent.llm.gate as g
            g._enabled = None
            assert g.is_enabled() is True

    def test_enabled_via_env_true(self):
        with patch.dict(os.environ, {"AUTON_LLM_ENABLED": "true"}):
            import agent.llm.gate as g
            g._enabled = None
            assert g.is_enabled() is True

    def test_enabled_via_env_yes(self):
        with patch.dict(os.environ, {"AUTON_LLM_ENABLED": "YES"}):
            import agent.llm.gate as g
            g._enabled = None
            assert g.is_enabled() is True

    def test_disabled_for_random_string(self):
        with patch.dict(os.environ, {"AUTON_LLM_ENABLED": "maybe"}):
            import agent.llm.gate as g
            g._enabled = None
            assert g.is_enabled() is False

    def test_set_enabled(self):
        import agent.llm.gate as g
        g.set_enabled(True)
        assert g.is_enabled() is True
        g.set_enabled(False)
        assert g.is_enabled() is False

    def test_caches_result(self):
        import agent.llm.gate as g
        g._enabled = None
        with patch.dict(os.environ, {"AUTON_LLM_ENABLED": "1"}):
            assert g.is_enabled() is True
        # Still True because cached
        assert g.is_enabled() is True
        g._enabled = None  # reset


class TestLlmOptionalDecorator:
    def setup_method(self):
        import agent.llm.gate as g
        g._enabled = None

    def test_returns_fallback_when_disabled(self):
        import agent.llm.gate as g
        g.set_enabled(False)

        @llm_optional(fallback="default")
        def my_func():
            return "llm_result"

        assert my_func() == "default"

    def test_calls_func_when_enabled(self):
        import agent.llm.gate as g
        g.set_enabled(True)

        @llm_optional(fallback="default")
        def my_func():
            return "llm_result"

        assert my_func() == "llm_result"

    def test_returns_fallback_on_exception(self):
        import agent.llm.gate as g
        g.set_enabled(True)

        @llm_optional(fallback=[])
        def failing_func():
            raise RuntimeError("LLM crashed")

        assert failing_func() == []

    def test_preserves_function_name(self):
        @llm_optional(fallback=None)
        def my_named_func():
            pass

        assert my_named_func.__name__ == "my_named_func"

    def test_passes_args_through(self):
        import agent.llm.gate as g
        g.set_enabled(True)

        @llm_optional(fallback=None)
        def adder(a, b, extra=0):
            return a + b + extra

        assert adder(1, 2, extra=3) == 6


class TestLlmOptionalAsyncDecorator:
    def setup_method(self):
        import agent.llm.gate as g
        g._enabled = None

    @pytest.mark.asyncio
    async def test_returns_fallback_when_disabled(self):
        import agent.llm.gate as g
        g.set_enabled(False)

        @llm_optional_async(fallback="nope")
        async def my_async():
            return "yes"

        assert await my_async() == "nope"

    @pytest.mark.asyncio
    async def test_calls_func_when_enabled(self):
        import agent.llm.gate as g
        g.set_enabled(True)

        @llm_optional_async(fallback="nope")
        async def my_async():
            return "yes"

        assert await my_async() == "yes"

    @pytest.mark.asyncio
    async def test_returns_fallback_on_exception(self):
        import agent.llm.gate as g
        g.set_enabled(True)

        @llm_optional_async(fallback={})
        async def boom():
            raise ValueError("fail")

        assert await boom() == {}


# --- augment tests ---

class TestAugmentFunctions:
    """Test augment functions return fallbacks when LLM disabled."""

    def setup_method(self):
        import agent.llm.gate as g
        g.set_enabled(False)

    def test_enrich_finding_returns_none_when_disabled(self):
        from agent.llm.augment import enrich_finding_description
        result = enrich_finding_description({"recipe_id": "sqli", "endpoint": "/login"})
        assert result is None

    def test_suggest_attack_surface_returns_empty_when_disabled(self):
        from agent.llm.augment import suggest_attack_surface
        result = suggest_attack_surface(["php", "mysql"], ["http://x.com/api"])
        assert result == []

    def test_generate_executive_summary_returns_empty_when_disabled(self):
        from agent.llm.augment import generate_executive_summary
        result = generate_executive_summary("http://example.com", [{"severity": "high"}], ["nginx"])
        assert result == ""


class TestAugmentWithMockedLLM:
    """Test augment functions call LLM correctly when enabled."""

    def setup_method(self):
        import agent.llm.gate as g
        g.set_enabled(True)

    def _patch_route(self, return_value):
        import sys
        import types
        mock_router = types.ModuleType("agent.router")
        mock_router.route = MagicMock(return_value=return_value)
        return patch.dict(sys.modules, {"agent.router": mock_router})

    def test_enrich_finding_with_llm(self):
        mock_result = {"description": "SQL injection found", "remediation": "Use parameterized queries"}
        with self._patch_route(mock_result):
            from agent.llm.augment import enrich_finding_description
            result = enrich_finding_description({"recipe_id": "sqli", "endpoint": "/login"})
            assert result["description"] == "SQL injection found"
            assert result["remediation"] == "Use parameterized queries"

    def test_suggest_attack_surface_with_llm(self):
        with self._patch_route(["sqli", "xss", "ssrf"]):
            from agent.llm.augment import suggest_attack_surface
            result = suggest_attack_surface(["php"], ["http://x.com/a"])
            assert result == ["sqli", "xss", "ssrf"]

    def test_generate_summary_with_llm(self):
        with self._patch_route("The assessment found critical issues."):
            from agent.llm.augment import generate_executive_summary
            result = generate_executive_summary("http://x.com", [{"severity": "high"}], ["nginx"])
            assert "critical" in result.lower()

    def test_enrich_returns_none_for_bad_response(self):
        with self._patch_route("not a dict"):
            from agent.llm.augment import enrich_finding_description
            result = enrich_finding_description({"recipe_id": "sqli"})
            assert result is None

    def test_suggest_returns_empty_for_bad_response(self):
        with self._patch_route("not a list"):
            from agent.llm.augment import suggest_attack_surface
            result = suggest_attack_surface([], [])
            assert result == []

    def test_suggest_caps_at_five(self):
        with self._patch_route(["a", "b", "c", "d", "e", "f", "g"]):
            from agent.llm.augment import suggest_attack_surface
            result = suggest_attack_surface([], [])
            assert len(result) == 5
