"""Vector store for recipe embeddings.

Simple numpy-based store with cosine similarity search. Recipes are
indexed by their id, and the store persists to disk as a directory
containing the embedder, vectors, and a recipe id map.

For a future upgrade: swap for FAISS or Chroma by implementing the
same search() interface.
"""
from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from .embedder import Embedder, recipe_to_text


@dataclass
class SearchResult:
    """A single search hit."""
    recipe_id: str
    score: float       # cosine similarity, 0–1
    rank: int          # 1-based


@dataclass
class VectorStore:
    """In-memory vector store backed by numpy arrays.

    Supports:
      - Building from a list of Recipe objects
      - Cosine similarity search
      - Persistence to/from a directory
      - Incremental add (re-fits the embedder)
    """
    embedder: Embedder = field(default_factory=Embedder)
    vectors: Optional[np.ndarray] = None   # shape (n_recipes, n_features)
    recipe_ids: list[str] = field(default_factory=list)
    _texts: list[str] = field(default_factory=list)  # raw texts for re-fitting

    def build(self, recipes: list) -> int:
        """Build the store from a list of Recipe objects.

        Args:
            recipes: list of Recipe objects (from schema.py)

        Returns:
            Number of recipes indexed.
        """
        self._texts = [recipe_to_text(r) for r in recipes]
        self.recipe_ids = [r.id for r in recipes]
        if self._texts:
            self.vectors = self.embedder.fit(self._texts)
        else:
            self.vectors = np.empty((0, 0), dtype=np.float32)
        return len(self.recipe_ids)

    def add(self, recipes: list) -> int:
        """Add recipes to the store. Re-fits the embedder on the full corpus.

        Args:
            recipes: new Recipe objects to add

        Returns:
            Total number of recipes after adding.
        """
        new_texts = [recipe_to_text(r) for r in recipes]
        new_ids = [r.id for r in recipes]
        # Deduplicate by id
        for text, rid in zip(new_texts, new_ids):
            if rid not in self.recipe_ids:
                self._texts.append(text)
                self.recipe_ids.append(rid)
        # Re-fit on full corpus
        if self._texts:
            self.vectors = self.embedder.fit(self._texts)
        return len(self.recipe_ids)

    def search(self, query: str, top_k: int = 5) -> list[SearchResult]:
        """Search for recipes similar to the query text.

        Args:
            query: free-text query (e.g. "rest-api session-cookie idor otp")
            top_k: number of results to return

        Returns:
            List of SearchResult, sorted by descending similarity.
        """
        if self.vectors is None or len(self.recipe_ids) == 0:
            return []

        query_vec = self.embedder.embed(query)
        # Cosine similarity (vectors are already L2-normalized)
        scores = self.vectors @ query_vec
        top_k = min(top_k, len(scores))
        top_indices = np.argsort(scores)[::-1][:top_k]

        results = []
        for rank, idx in enumerate(top_indices, start=1):
            results.append(SearchResult(
                recipe_id=self.recipe_ids[idx],
                score=float(scores[idx]),
                rank=rank,
            ))
        return results

    def search_by_signals(self, tech_signals: list[str], top_k: int = 5) -> list[SearchResult]:
        """Search using tech signals as the query — the primary retrieval path.

        Builds a query string from the signals and runs vector search.
        """
        query = " ".join(tech_signals)
        return self.search(query, top_k=top_k)

    def __len__(self) -> int:
        return len(self.recipe_ids)

    def save(self, directory: Path | str) -> None:
        """Persist the store to a directory."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        self.embedder.save(directory / "embedder.pkl")
        np.save(directory / "vectors.npy", self.vectors)
        with open(directory / "meta.json", "w", encoding="utf-8") as f:
            json.dump({"recipe_ids": self.recipe_ids}, f)
        with open(directory / "texts.pkl", "wb") as f:
            pickle.dump(self._texts, f)

    @classmethod
    def load(cls, directory: Path | str) -> "VectorStore":
        """Load a previously saved store."""
        directory = Path(directory)
        embedder = Embedder.load(directory / "embedder.pkl")
        vectors = np.load(directory / "vectors.npy")
        with open(directory / "meta.json", "r", encoding="utf-8") as f:
            meta = json.load(f)
        with open(directory / "texts.pkl", "rb") as f:
            texts = pickle.load(f)
        store = cls(embedder=embedder, vectors=vectors,
                    recipe_ids=meta["recipe_ids"], _texts=texts)
        return store
