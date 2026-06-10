"""Ollama embedder — real local embeddings.

Wraps Ollama's ``/api/embeddings`` HTTP endpoint. If Ollama is not
running or the model is not available, falls back to the dependency-free
:class:`HashEmbedder` so the rest of the system keeps working.

The embedder is a drop-in replacement for :class:`HashEmbedder` in
:class:`ResearchMemoryEngine`.
"""

from __future__ import annotations

import math
from typing import Any

import structlog

from .research_memory import HashEmbedder

logger = structlog.get_logger()


class OllamaEmbedder:
    """Real embeddings via Ollama. Falls back to HashEmbedder on failure."""

    def __init__(
        self,
        model: str = "nomic-embed-text",
        base_url: str = "http://localhost:11434",
        dim: int = 768,
        timeout_s: float = 30.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._dim = dim
        self._timeout = timeout_s
        self._fallback = HashEmbedder(dim=dim)

    @property
    def dim(self) -> int:
        return self._dim

    def _normalize(self, v: list[float]) -> list[float]:
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def embed(self, text: str) -> list[float]:
        try:
            import httpx  # local import so the module is optional
            with httpx.Client(timeout=self._timeout) as client:
                r = client.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                )
                if r.status_code == 200:
                    data = r.json()
                    emb = data.get("embedding") or []
                    if emb and len(emb) == self._dim:
                        return self._normalize([float(x) for x in emb])
                    # Dimension mismatch — adapt dim and fall through.
                    if emb:
                        self._dim = len(emb)
                        return self._normalize([float(x) for x in emb])
                logger.warning(
                    "ollama_embed_failed",
                    status=r.status_code,
                    body=r.text[:200],
                )
        except Exception as e:  # pragma: no cover - network path
            logger.warning("ollama_embed_error", error=str(e))
        # Fallback: deterministic local fingerprint.
        return self._fallback.embed(text)

    def healthcheck(self) -> dict[str, Any]:
        """Probe Ollama. Returns ``{"ok": bool, "model": str, "dim": int}``."""
        try:
            import httpx
            with httpx.Client(timeout=2.0) as client:
                r = client.get(f"{self.base_url}/api/tags")
                if r.status_code == 200:
                    tags = r.json().get("models", [])
                    has = any(m.get("name", "").startswith(self.model) for m in tags)
                    return {"ok": has, "model": self.model, "dim": self._dim,
                            "available_models": [m.get("name", "") for m in tags][:10]}
        except Exception as e:  # pragma: no cover
            return {"ok": False, "model": self.model, "dim": self._dim, "error": str(e)}
        return {"ok": False, "model": self.model, "dim": self._dim}
