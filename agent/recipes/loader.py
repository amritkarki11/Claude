"""Loads every YAML recipe from agent/recipes/, validates each against the
schema, and matches recipes against a recon result's tech_signals.

A malformed recipe never takes down the whole load: it's collected into
`errors` (LoadResult) so the rest of the recipe set still loads, and a bad
recipe can never silently match anything.
"""
from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

import yaml

from .schema import Recipe, SchemaError, validate_recipe

RECIPES_DIR = pathlib.Path(__file__).parent


@dataclass
class LoadResult:
    recipes: list[Recipe] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (path, message)


def load_recipes(directory: pathlib.Path | str = RECIPES_DIR) -> LoadResult:
    """Load + validate every *.yaml/*.yml file in `directory` (non-recursive)."""
    directory = pathlib.Path(directory)
    result = LoadResult()
    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            result.errors.append((str(path), f"invalid YAML: {e}"))
            continue
        try:
            result.recipes.append(validate_recipe(raw, path=str(path)))
        except SchemaError as e:
            result.errors.append((str(path), str(e)))
    return result


def match_recipes(recipes: list[Recipe], tech_signals) -> list[Recipe]:
    """Recipes whose tech_signals are ALL present among the given signals
    (a recipe is a candidate only once every signal it needs is observed)."""
    have = {s.lower() for s in tech_signals}
    return [r for r in recipes if {s.lower() for s in r.tech_signals} <= have]


def match_from_recon(recipes: list[Recipe], recon_result: dict) -> list[Recipe]:
    """Convenience wrapper: pull tech_signals out of a recon result dict
    (top-level `tech_signals` key, defaulting to empty) and match."""
    return match_recipes(recipes, recon_result.get("tech_signals", []))
