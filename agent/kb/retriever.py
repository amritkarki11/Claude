"""Recipe retriever — the main interface for the agent loop.

Combines two retrieval strategies:
  1. Exact signal matching (from recipes/loader.py) — deterministic
  2. Vector similarity (from kb/store.py) — fuzzy, catches partial matches

The retriever merges results, deduplicates, and returns ranked recipes
ready for the scanner pipeline.
"""
from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Optional

from ..recipes.loader import load_recipes, match_recipes, LoadResult
from ..recipes.schema import Recipe
from .store import VectorStore, SearchResult


@dataclass
class RetrievalResult:
    """Merged retrieval output."""
    recipe_id: str
    recipe: Recipe
    exact_match: bool      # matched via deterministic signal matching
    vector_score: float    # cosine similarity (0 if not in vector results)
    combined_rank: int     # final rank after merging


@dataclass
class Retriever:
    """Two-stage recipe retriever.

    Stage 1 (exact): recipes whose tech_signals are ALL present in the query.
    Stage 2 (fuzzy): vector similarity search for partial/synonym matches.

    Exact matches always rank above fuzzy-only matches.
    """
    store: VectorStore = field(default_factory=VectorStore)
    recipes: list[Recipe] = field(default_factory=list)
    _recipe_map: dict[str, Recipe] = field(default_factory=dict)

    def build(self, recipes_dir: pathlib.Path | str | None = None,
              recipes: list[Recipe] | None = None) -> int:
        """Build the retriever from recipes.

        Args:
            recipes_dir: path to directory containing recipe YAML files
            recipes: or pass Recipe objects directly

        Returns:
            Number of recipes indexed.
        """
        if recipes is not None:
            self.recipes = list(recipes)
        elif recipes_dir is not None:
            result = load_recipes(recipes_dir)
            self.recipes = result.recipes
        else:
            raise ValueError("Provide either recipes_dir or recipes")

        self._recipe_map = {r.id: r for r in self.recipes}
        self.store.build(self.recipes)
        return len(self.recipes)

    def retrieve(self, tech_signals: list[str], top_k: int = 10,
                 min_score: float = 0.05) -> list[RetrievalResult]:
        """Retrieve relevant recipes for a set of tech signals.

        Args:
            tech_signals: observed technology signals from recon
            top_k: max results to return
            min_score: minimum vector similarity to include fuzzy matches

        Returns:
            Ranked list of RetrievalResult, exact matches first.
        """
        # Stage 1: exact signal matching
        exact_matches = match_recipes(self.recipes, tech_signals)
        exact_ids = {r.id for r in exact_matches}

        # Stage 2: vector similarity
        vector_results = self.store.search_by_signals(tech_signals, top_k=top_k * 2)
        vector_map = {r.recipe_id: r.score for r in vector_results}

        # Merge: exact matches first (sorted by vector score desc), then fuzzy
        results = []
        rank = 1

        # Exact matches, ranked by vector score if available
        exact_scored = [
            (r, vector_map.get(r.id, 0.0))
            for r in exact_matches
        ]
        exact_scored.sort(key=lambda x: x[1], reverse=True)
        for recipe, vscore in exact_scored:
            results.append(RetrievalResult(
                recipe_id=recipe.id,
                recipe=recipe,
                exact_match=True,
                vector_score=vscore,
                combined_rank=rank,
            ))
            rank += 1

        # Fuzzy-only matches (not in exact set, above min_score)
        for vr in vector_results:
            if vr.recipe_id not in exact_ids and vr.score >= min_score:
                recipe = self._recipe_map.get(vr.recipe_id)
                if recipe:
                    results.append(RetrievalResult(
                        recipe_id=vr.recipe_id,
                        recipe=recipe,
                        exact_match=False,
                        vector_score=vr.score,
                        combined_rank=rank,
                    ))
                    rank += 1

        return results[:top_k]

    def retrieve_for_endpoint(self, tech_signals: list[str],
                              endpoint: str = "", method: str = "",
                              params: list[str] | None = None,
                              top_k: int = 10) -> list[RetrievalResult]:
        """Retrieve recipes with additional endpoint context for better ranking.

        Builds a richer query that includes endpoint info alongside signals.
        """
        query_parts = list(tech_signals)
        if endpoint:
            query_parts.append(endpoint)
        if method:
            query_parts.append(method)
        if params:
            query_parts.extend(params)

        # Still do exact matching on signals only
        exact_matches = match_recipes(self.recipes, tech_signals)
        exact_ids = {r.id for r in exact_matches}

        # But vector search uses the richer query
        query_text = " ".join(query_parts)
        vector_results = self.store.search(query_text, top_k=top_k * 2)
        vector_map = {r.recipe_id: r.score for r in vector_results}

        results = []
        rank = 1

        exact_scored = [
            (r, vector_map.get(r.id, 0.0))
            for r in exact_matches
        ]
        exact_scored.sort(key=lambda x: x[1], reverse=True)
        for recipe, vscore in exact_scored:
            results.append(RetrievalResult(
                recipe_id=recipe.id,
                recipe=recipe,
                exact_match=True,
                vector_score=vscore,
                combined_rank=rank,
            ))
            rank += 1

        for vr in vector_results:
            if vr.recipe_id not in exact_ids and vr.score >= 0.05:
                recipe = self._recipe_map.get(vr.recipe_id)
                if recipe:
                    results.append(RetrievalResult(
                        recipe_id=vr.recipe_id,
                        recipe=recipe,
                        exact_match=False,
                        vector_score=vr.score,
                        combined_rank=rank,
                    ))
                    rank += 1

        return results[:top_k]

    def save(self, directory: pathlib.Path | str) -> None:
        """Persist the retriever's vector store."""
        self.store.save(directory)

    @classmethod
    def load(cls, directory: pathlib.Path | str,
             recipes_dir: pathlib.Path | str | None = None) -> "Retriever":
        """Load a saved retriever. Recipes are reloaded from YAML."""
        store = VectorStore.load(directory)
        obj = cls(store=store)
        if recipes_dir:
            result = load_recipes(recipes_dir)
            obj.recipes = result.recipes
        obj._recipe_map = {r.id: r for r in obj.recipes}
        return obj
