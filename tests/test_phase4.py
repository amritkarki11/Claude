"""Tests for Phase 4 — Knowledge Base (Embedder, Store, Retriever)."""
import pytest
import tempfile
import pathlib

from agent.recipes.schema import Recipe, validate_recipe
from agent.kb.embedder import Embedder, recipe_to_text
from agent.kb.store import VectorStore, SearchResult
from agent.kb.retriever import Retriever, RetrievalResult


# ── Fixtures ──────────────────────────────────────────────────

IDOR_RECIPE_DATA = {
    "id": "idor-otp-trigger",
    "applies_to": ["api", "web"],
    "tech_signals": ["rest-api", "session-cookie"],
    "preconditions": ["two authenticated sessions are available"],
    "detect": [
        {"step": "Identify the OTP-trigger endpoint"},
        {"step": "As session A, call the endpoint for a foreign id", "method": "POST"},
    ],
    "signal": "The endpoint returns success for an id the session does not own",
    "verify": "Replay the request and confirm status indicates OTP was issued",
    "severity": "high",
    "remediation": "Add object-level authorization check",
    "source": "CWE-639",
}

XXE_RECIPE_DATA = {
    "id": "xxe-basic",
    "applies_to": ["api", "web"],
    "tech_signals": ["xml-parser", "rest-api"],
    "preconditions": ["endpoint accepts XML input"],
    "detect": [
        {"step": "Send a crafted XML with an external entity declaration"},
        {"step": "Check if the entity is resolved in the response"},
    ],
    "signal": "External entity content appears in response body",
    "verify": "Re-send the payload and confirm entity resolution is consistent",
    "severity": "critical",
    "remediation": "Disable external entity processing in XML parser",
    "source": "CWE-611",
}

SQLI_RECIPE_DATA = {
    "id": "sqli-error-based",
    "applies_to": ["web"],
    "tech_signals": ["sql-database", "form-input"],
    "preconditions": ["endpoint accepts user input in query parameters"],
    "detect": [
        {"step": "Inject a single quote and observe error message"},
        {"step": "Try UNION SELECT to extract data"},
    ],
    "signal": "SQL error message or UNION data appears in response",
    "verify": "Re-run injection and confirm consistent data extraction",
    "severity": "critical",
    "remediation": "Use parameterized queries",
    "source": "CWE-89",
}


@pytest.fixture
def sample_recipes():
    return [
        validate_recipe(IDOR_RECIPE_DATA),
        validate_recipe(XXE_RECIPE_DATA),
        validate_recipe(SQLI_RECIPE_DATA),
    ]


# ── Embedder tests ────────────────────────────────────────────

class TestRecipeToText:
    def test_contains_id(self, sample_recipes):
        text = recipe_to_text(sample_recipes[0])
        assert "idor-otp-trigger" in text

    def test_contains_signals(self, sample_recipes):
        text = recipe_to_text(sample_recipes[0])
        assert "rest-api" in text
        assert "session-cookie" in text

    def test_contains_detect_steps(self, sample_recipes):
        text = recipe_to_text(sample_recipes[0])
        assert "OTP-trigger endpoint" in text

    def test_contains_severity(self, sample_recipes):
        text = recipe_to_text(sample_recipes[0])
        assert "high" in text


class TestEmbedder:
    def test_fit_returns_vectors(self, sample_recipes):
        texts = [recipe_to_text(r) for r in sample_recipes]
        emb = Embedder()
        vectors = emb.fit(texts)
        assert vectors.shape[0] == 3
        assert vectors.shape[1] > 0

    def test_embed_query(self, sample_recipes):
        texts = [recipe_to_text(r) for r in sample_recipes]
        emb = Embedder()
        emb.fit(texts)
        vec = emb.embed("rest-api session-cookie idor otp")
        assert vec.shape[0] > 0

    def test_embed_before_fit_raises(self):
        emb = Embedder()
        with pytest.raises(RuntimeError):
            emb.embed("test query")

    def test_vocab_size(self, sample_recipes):
        texts = [recipe_to_text(r) for r in sample_recipes]
        emb = Embedder()
        emb.fit(texts)
        assert emb.vocab_size > 0

    def test_save_load(self, sample_recipes, tmp_path):
        texts = [recipe_to_text(r) for r in sample_recipes]
        emb = Embedder()
        emb.fit(texts)
        path = tmp_path / "emb.pkl"
        emb.save(path)
        loaded = Embedder.load(path)
        assert loaded.vocab_size == emb.vocab_size
        vec = loaded.embed("test query")
        assert vec.shape[0] > 0


# ── Store tests ───────────────────────────────────────────────

class TestVectorStore:
    def test_build(self, sample_recipes):
        store = VectorStore()
        count = store.build(sample_recipes)
        assert count == 3
        assert len(store) == 3

    def test_search_returns_results(self, sample_recipes):
        store = VectorStore()
        store.build(sample_recipes)
        results = store.search("rest-api session-cookie idor otp")
        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)

    def test_search_ranks_idor_first(self, sample_recipes):
        store = VectorStore()
        store.build(sample_recipes)
        results = store.search("rest-api session-cookie idor otp")
        assert results[0].recipe_id == "idor-otp-trigger"

    def test_search_by_signals(self, sample_recipes):
        store = VectorStore()
        store.build(sample_recipes)
        results = store.search_by_signals(["rest-api", "session-cookie"])
        assert len(results) > 0

    def test_search_xxe_first_for_xml(self, sample_recipes):
        store = VectorStore()
        store.build(sample_recipes)
        results = store.search("xml-parser external entity xxe")
        assert results[0].recipe_id == "xxe-basic"

    def test_add_deduplicates(self, sample_recipes):
        store = VectorStore()
        store.build(sample_recipes[:2])
        count = store.add(sample_recipes)  # includes duplicates
        assert count == 3  # not 5

    def test_empty_store_search(self):
        store = VectorStore()
        store.build([])
        results = store.search("anything")
        assert results == []

    def test_save_load(self, sample_recipes, tmp_path):
        store = VectorStore()
        store.build(sample_recipes)
        store.save(tmp_path / "kb")
        loaded = VectorStore.load(tmp_path / "kb")
        assert len(loaded) == 3
        results = loaded.search("idor otp")
        assert len(results) > 0

    def test_scores_between_zero_and_one(self, sample_recipes):
        store = VectorStore()
        store.build(sample_recipes)
        results = store.search("rest-api session-cookie")
        for r in results:
            assert 0.0 <= r.score <= 1.0


# ── Retriever tests ───────────────────────────────────────────

class TestRetriever:
    def test_build_from_recipes(self, sample_recipes):
        ret = Retriever()
        count = ret.build(recipes=sample_recipes)
        assert count == 3

    def test_retrieve_exact_match(self, sample_recipes):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        results = ret.retrieve(["rest-api", "session-cookie"])
        # IDOR recipe requires exactly these signals → exact match
        assert any(r.exact_match and r.recipe_id == "idor-otp-trigger" for r in results)

    def test_retrieve_exact_matches_rank_first(self, sample_recipes):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        results = ret.retrieve(["rest-api", "session-cookie"])
        exact = [r for r in results if r.exact_match]
        fuzzy = [r for r in results if not r.exact_match]
        if exact and fuzzy:
            assert max(r.combined_rank for r in exact) < min(r.combined_rank for r in fuzzy)

    def test_retrieve_for_endpoint(self, sample_recipes):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        results = ret.retrieve_for_endpoint(
            tech_signals=["rest-api", "session-cookie"],
            endpoint="/api/v1/sendOTP",
            method="POST",
            params=["mobileNo", "userId"],
        )
        assert len(results) > 0
        assert results[0].recipe_id == "idor-otp-trigger"

    def test_retrieve_xxe_signals(self, sample_recipes):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        results = ret.retrieve(["xml-parser", "rest-api"])
        exact = [r for r in results if r.exact_match]
        assert any(r.recipe_id == "xxe-basic" for r in exact)

    def test_retrieve_no_match(self, sample_recipes):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        results = ret.retrieve(["graphql", "websocket"], min_score=0.5)
        # Should get no exact matches, and fuzzy below threshold
        exact = [r for r in results if r.exact_match]
        assert len(exact) == 0

    def test_save_load(self, sample_recipes, tmp_path):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        ret.save(tmp_path / "kb")
        loaded = Retriever.load(tmp_path / "kb")
        results = loaded.store.search("idor otp")
        assert len(results) > 0

    def test_combined_rank_sequential(self, sample_recipes):
        ret = Retriever()
        ret.build(recipes=sample_recipes)
        results = ret.retrieve(["rest-api", "session-cookie"])
        ranks = [r.combined_rank for r in results]
        assert ranks == sorted(ranks)
        assert ranks[0] == 1
