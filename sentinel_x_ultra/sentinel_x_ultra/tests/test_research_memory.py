"""Tests for the V3 Research Memory Engine."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG_PARENT = Path(__file__).resolve().parents[2]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from sentinel_x_ultra.research_memory import (  # noqa: E402
    FILE_KINDS,
    HashEmbedder,
    MemoryChunk,
    ResearchMemoryEngine,
    kind_for,
)


# ---------------------------------------------------------------------------
# Embedder
# ---------------------------------------------------------------------------


class TestHashEmbedder:
    def test_dimension_matches_constructor(self):
        e = HashEmbedder(dim=64)
        assert e.dim == 64
        v = e.embed("hello world")
        assert len(v) == 64

    def test_vector_is_normalized(self):
        e = HashEmbedder(dim=32)
        v = e.embed("the quick brown fox")
        norm = sum(x * x for x in v) ** 0.5
        assert norm == pytest.approx(1.0, abs=1e-6)

    def test_same_text_produces_same_vector(self):
        e = HashEmbedder()
        assert e.embed("hello") == e.embed("hello")


# ---------------------------------------------------------------------------
# File kind detection
# ---------------------------------------------------------------------------


class TestKindFor:
    def test_source_code_extensions(self):
        for ext in (".py", ".js", ".ts", ".go", ".java", ".rs"):
            assert kind_for(Path(f"foo{ext}")) == "source_code"

    def test_markdown_is_markdown(self):
        assert kind_for(Path("README.md")) == "markdown"

    def test_png_is_screenshot(self):
        assert kind_for(Path("a.png")) == "screenshot"

    def test_json_is_api_spec(self):
        assert kind_for(Path("openapi.json")) == "api_spec"

    def test_log_is_log(self):
        assert kind_for(Path("audit.log")) == "log"

    def test_har_is_har(self):
        assert kind_for(Path("recording.har")) == "har"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class TestResearchMemoryEngine:
    def test_index_and_persist(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        chunks = eng.index_file(
            "p1",
            Path("src/auth/login.py"),
            content="def login(user, pw):\n    return True\n" * 20,
        )
        assert len(chunks) >= 1
        for c in chunks:
            assert c.embedding
            assert c.embedding_model.startswith("hash-")
            assert c.indexed_at

        # Reload from disk in a fresh engine
        eng2 = ResearchMemoryEngine(base_path=tmp_path)
        all_chunks = eng2.all("p1")
        assert len(all_chunks) == len(chunks)

    def test_chunk_metadata_detects_component_refs(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        eng.index_file(
            "p2",
            Path("src/auth/SessionManager.py"),
            content="class SessionManager: def renew(self, token): return token",
        )
        all_chunks = eng.all("p2")
        assert any("SessionManager" in c.component_refs for c in all_chunks)

    def test_chunk_metadata_detects_risk_tags(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        eng.index_file(
            "p3",
            Path("src/api/users.py"),
            content="# SQL Injection vulnerability here\nquery = ' OR 1=1'\n",
        )
        all_chunks = eng.all("p3")
        assert any("sql_injection" in c.risk_tags for c in all_chunks)

    def test_search_finds_relevant_chunk(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        eng.index_file(
            "p4",
            Path("src/auth/login.py"),
            content="def login(user, pw): return check_credentials(user, pw)\n",
        )
        eng.index_file(
            "p4",
            Path("src/api/users.py"),
            content="def list_users(): return db.query('SELECT * FROM users')\n",
        )
        results = eng.search("p4", "login credentials", top_k=5)
        assert results
        # The auth chunk should rank above the api chunk for "login credentials"
        top = results[0]
        assert "login" in top.text.lower() or "credential" in top.text.lower()

    def test_search_filters_by_kind(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        eng.index_file("p5", Path("a.py"), content="hello world python")
        eng.index_file("p5", Path("b.md"), content="hello world markdown")
        results = eng.search("p5", "hello", kind="markdown")
        assert results
        assert all(c.file_kind == "markdown" for c in results)

    def test_search_filters_by_risk(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        eng.index_file("p6", Path("a.py"), content="SQL injection possible here")
        eng.index_file("p6", Path("b.py"), content="Just normal safe code")
        results = eng.search("p6", "anything", risk="sql_injection")
        assert results
        assert all("sql_injection" in c.risk_tags for c in results)

    def test_stats(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        eng.index_file("p7", Path("a.py"), content="x = 1\n" * 10)
        eng.index_file("p7", Path("b.md"), content="# Title\nBody\n")
        stats = eng.stats("p7")
        assert stats.files_indexed == 2
        assert stats.chunks_indexed >= 2
        assert "source_code" in stats.by_kind
        assert "markdown" in stats.by_kind

    def test_index_text_inline(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        chunks = eng.index_text(
            "p8",
            kind="note",
            text="Important security note about authentication.",
            tags=["important"],
        )
        assert len(chunks) >= 1
        assert all(c.file_kind == "note" for c in chunks)
        assert all("important" in c.tags for c in chunks)

    def test_empty_file_yields_no_chunks(self, tmp_path: Path):
        eng = ResearchMemoryEngine(base_path=tmp_path)
        chunks = eng.index_file("p9", Path("empty.py"), content="")
        assert chunks == []
