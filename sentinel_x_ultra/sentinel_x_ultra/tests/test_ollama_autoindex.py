"""Tests for the Ollama embedder (with fallback) and the auto-index hook."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

_PKG_PARENT = Path(__file__).resolve().parents[2]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from sentinel_x_ultra.ollama_embedder import OllamaEmbedder  # noqa: E402
from sentinel_x_ultra.research_memory import HashEmbedder  # noqa: E402


# ---------------------------------------------------------------------------
# Ollama embedder
# ---------------------------------------------------------------------------


class TestOllamaEmbedder:
    def test_falls_back_when_ollama_unreachable(self):
        # Point at a port nothing is listening on so the network call fails.
        e = OllamaEmbedder(base_url="http://127.0.0.1:1", dim=64, timeout_s=0.5)
        v = e.embed("hello world")
        # Should still produce a normalised vector of the right dim
        assert len(v) == 64
        norm = sum(x * x for x in v) ** 0.5
        assert norm == pytest.approx(1.0, abs=1e-6)

    def test_healthcheck_returns_dict(self):
        e = OllamaEmbedder(base_url="http://127.0.0.1:1", dim=32, timeout_s=0.5)
        h = e.healthcheck()
        assert "ok" in h
        assert h["ok"] is False  # nothing listening on :1
        assert h["model"] == "nomic-embed-text"


# ---------------------------------------------------------------------------
# Auto-index on workspace upload
# ---------------------------------------------------------------------------


class TestAutoIndexOnUpload:
    def test_uploaded_file_is_searchable_via_research_memory(self, tmp_path: Path, monkeypatch):
        # Use a clean TestClient with a temp storage dir so the test is hermetic.
        sentinel_root = tmp_path / "sentinel"
        sentinel_root.mkdir()
        monkeypatch.setattr(
            "sentinel_x_ultra.server.settings.storage.base_path", sentinel_root
        )
        from fastapi.testclient import TestClient
        from sentinel_x_ultra.server import app

        with TestClient(app) as client:
            # Create project + workspace
            r = client.post("/api/projects", json={"name": "autoindex-test"})
            assert r.status_code == 200, r.text
            pid = r.json()["project_id"]
            r = client.post(f"/api/projects/{pid}/workspace/init")
            assert r.status_code == 200, r.text

            # Upload a file with "auth" in the basename
            src = tmp_path / "auth_login.py"
            src.write_text("def login(user, pw):\n    return check(user, pw)\n")
            r = client.post(
                f"/api/projects/{pid}/workspace/upload",
                json={"source_path": str(src)},
            )
            assert r.status_code == 200, r.text
            payload = r.json()
            assert "chunks_indexed" in payload
            assert payload["chunks_indexed"] >= 1

            # The Research Memory Engine should now have at least one chunk
            # that we can search for.
            r = client.post(
                f"/api/projects/{pid}/research/search",
                json={"query": "login", "top_k": 5},
            )
            assert r.status_code == 200, r.text
            results = r.json()["results"]
            assert results
            assert any("login" in c["text"].lower() for c in results)
