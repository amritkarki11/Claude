"""Text embedder for recipe documents.

Uses TF-IDF (scikit-learn) to convert recipe text into dense-ish vectors.
Lightweight, runs offline, no GPU needed. The vocabulary is domain-specific
(security terms), so TF-IDF works surprisingly well for retrieval.

For a future upgrade path: swap this for a local sentence-transformer
(nomic-embed-text via Ollama) by implementing the same interface.
"""
from __future__ import annotations

import joblib
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize


def recipe_to_text(recipe) -> str:
    """Flatten a Recipe object into a single searchable document.

    Concatenates the structured fields into weighted text — fields that
    matter more for matching (tech_signals, detect steps) get repeated
    so TF-IDF naturally weights them higher.
    """
    parts = [
        f"id: {recipe.id}",
        f"applies_to: {' '.join(recipe.applies_to)}",
        # Tech signals repeated for weight
        f"tech_signals: {' '.join(recipe.tech_signals)}",
        f"signals: {' '.join(recipe.tech_signals)}",
        f"preconditions: {' '.join(recipe.preconditions)}",
        f"severity: {recipe.severity}",
        f"signal: {recipe.signal}",
        f"verify: {recipe.verify}",
        f"remediation: {recipe.remediation}",
        f"source: {recipe.source}",
    ]
    # Detect steps — extract the step descriptions
    for step in recipe.detect:
        if isinstance(step, dict):
            parts.append(step.get("step", ""))
    return "\n".join(parts)


class Embedder:
    """TF-IDF based text embedder for recipe retrieval.

    Fits a vocabulary on the recipe corpus, then can embed new queries
    against that vocabulary. Serializable via pickle for persistence.
    """

    def __init__(self, max_features: int = 2048, ngram_range: tuple = (1, 2)):
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            stop_words="english",
            sublinear_tf=True,  # log-scaled TF for better discrimination
            dtype=np.float32,
        )
        self._fitted = False

    def fit(self, texts: list[str]) -> np.ndarray:
        """Fit the vectorizer on a corpus and return the document vectors.

        Args:
            texts: list of recipe documents (from recipe_to_text)

        Returns:
            L2-normalized document vectors, shape (n_docs, n_features)
        """
        matrix = self.vectorizer.fit_transform(texts)
        self._fitted = True
        return normalize(matrix, norm="l2").toarray()

    def embed(self, text: str) -> np.ndarray:
        """Embed a single query text using the fitted vocabulary.

        Args:
            text: query string (e.g. "rest-api session-cookie otp")

        Returns:
            L2-normalized vector, shape (n_features,)
        """
        if not self._fitted:
            raise RuntimeError("Embedder must be fit() before embed()")
        vec = self.vectorizer.transform([text])
        return normalize(vec, norm="l2").toarray()[0]

    def embed_batch(self, texts: list[str]) -> np.ndarray:
        """Embed multiple texts at once.

        Returns:
            L2-normalized vectors, shape (n_texts, n_features)
        """
        if not self._fitted:
            raise RuntimeError("Embedder must be fit() before embed_batch()")
        matrix = self.vectorizer.transform(texts)
        return normalize(matrix, norm="l2").toarray()

    @property
    def vocab_size(self) -> int:
        if not self._fitted:
            return 0
        return len(self.vectorizer.vocabulary_)

    def save(self, path: Path | str) -> None:
        """Persist the fitted vectorizer to disk."""
        joblib.dump(self.vectorizer, path)

    @classmethod
    def load(cls, path: Path | str) -> "Embedder":
        """Load a previously saved embedder."""
        vectorizer = joblib.load(path)
        obj = cls.__new__(cls)
        obj.vectorizer = vectorizer
        obj._fitted = True
        return obj
