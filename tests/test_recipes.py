"""Recipe engine: schema validation, loading, and tech_signal matching."""
import pytest

from agent.recipes.loader import load_recipes, match_from_recon, match_recipes
from agent.recipes.schema import Recipe, SchemaError, validate_recipe

VALID = {
    "id": "idor-otp-trigger",
    "applies_to": ["api"],
    "tech_signals": ["rest-api", "session-cookie"],
    "preconditions": ["two sessions available"],
    "detect": [{"step": "do the thing"}],
    "signal": "returns success for a foreign id",
    "verify": "replay and confirm",
    "severity": "high",
    "remediation": "check object ownership server-side",
    "source": "CWE-639",
}


def test_validate_recipe_accepts_valid():
    r = validate_recipe(VALID)
    assert isinstance(r, Recipe)
    assert r.id == "idor-otp-trigger"
    assert r.tech_signals == ("rest-api", "session-cookie")
    assert r.severity == "high"


@pytest.mark.parametrize("missing", list(VALID))
def test_validate_recipe_rejects_missing_field(missing):
    bad = {k: v for k, v in VALID.items() if k != missing}
    with pytest.raises(SchemaError):
        validate_recipe(bad)


def test_validate_recipe_rejects_bad_severity():
    with pytest.raises(SchemaError):
        validate_recipe({**VALID, "severity": "catastrophic"})


def test_validate_recipe_rejects_empty_lists_and_non_dict_detect():
    with pytest.raises(SchemaError):
        validate_recipe({**VALID, "tech_signals": []})
    with pytest.raises(SchemaError):
        validate_recipe({**VALID, "detect": ["not a dict"]})


def test_loader_loads_idor_recipe_from_repo():
    result = load_recipes()
    ids = {r.id for r in result.recipes}
    assert "idor-otp-trigger" in ids
    assert result.errors == []


def test_malformed_recipe_rejected(tmp_path):
    (tmp_path / "good.yaml").write_text(
        "id: ok-one\n"
        "applies_to: [api]\n"
        "tech_signals: [rest-api]\n"
        "preconditions: [one]\n"
        "detect:\n  - step: look\n"
        "signal: s\nverify: v\nseverity: low\nremediation: r\nsource: s\n"
    )
    (tmp_path / "bad.yaml").write_text("id: broken\napplies_to: [api]\n")  # missing most fields
    (tmp_path / "not_yaml.yaml").write_text(": : : not valid yaml : : :\n\tbad indent")

    result = load_recipes(tmp_path)
    assert [r.id for r in result.recipes] == ["ok-one"]
    assert len(result.errors) == 2
    paths = {p for p, _ in result.errors}
    assert any("bad.yaml" in p for p in paths)
    assert any("not_yaml.yaml" in p for p in paths)


def test_matching_recon_result_returns_idor_recipe():
    result = load_recipes()
    recon = {"tech_signals": ["rest-api", "session-cookie", "nginx"]}
    matched = match_from_recon(result.recipes, recon)
    assert {r.id for r in matched} == {"idor-otp-trigger"}


def test_non_matching_signal_returns_nothing():
    result = load_recipes()
    recon = {"tech_signals": ["graphql"]}
    assert match_from_recon(result.recipes, recon) == []


def test_partial_signal_overlap_does_not_match():
    recipe = validate_recipe(VALID)
    # has rest-api but not session-cookie -> recipe needs BOTH
    assert match_recipes([recipe], ["rest-api"]) == []
    assert match_recipes([recipe], ["rest-api", "session-cookie"]) == [recipe]


def test_matching_is_case_insensitive():
    recipe = validate_recipe(VALID)
    assert match_recipes([recipe], ["REST-API", "Session-Cookie"]) == [recipe]
