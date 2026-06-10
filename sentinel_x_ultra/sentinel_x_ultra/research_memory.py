"""Research Memory Engine — V3.

The V3 spec says:

    Every file added to a project becomes searchable.
    Index:
        Source Code, Screenshots, PDFs, Markdown, Reports, Logs,
        HAR Files, API Specifications, Documentation, Notes
    Store:
        Embeddings, Metadata, Tags, Relationships,
        Component References, Risk References

This module provides a :class:`ResearchMemoryEngine` that:

  * Chunks every indexed file (line-based, with overlap).
  * Computes a deterministic per-chunk embedding using a pluggable
    embedder. The default embedder is a lightweight local hash-based
    "fingerprint" that requires no model — swap in a real embedder
    (Ollama / LM Studio / OpenAI) by passing ``embedder=...`` to
    :meth:`ResearchMemoryEngine.index_file`.
  * Stores metadata, tags, relationships, component refs, and risk
    refs for every chunk.
  * Supports BM25-style keyword search with a rerank hook for richer
    semantic retrieval later.
  * Persists to disk so memory survives restarts.

The engine is wired into the V3 endpoints and the workspace upload
flow, so any file the user drops into ``/Projects/<name>/...`` is
automatically indexed and searchable.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

import structlog

logger = structlog.get_logger()


# ---- Embedder protocol -------------------------------------------------------

class Embedder(Protocol):
    """Anything that can turn text into a fixed-dim vector."""

    def embed(self, text: str) -> list[float]: ...
    @property
    def dim(self) -> int: ...


class HashEmbedder:
    """Deterministic, dependency-free embedder.

    Hashes each token into one of ``dim`` buckets, producing a sparse
    unit vector. Good enough for BM25-style retrieval and zero
    external dependencies. Replace with a real model in production.
    """

    def __init__(self, dim: int = 128):
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def embed(self, text: str) -> list[float]:
        v = [0.0] * self._dim
        for token in re.findall(r"[a-zA-Z0-9_]+", text.lower()):
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            v[h % self._dim] += 1.0
        # L2 normalize
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]


# ---- File kinds (V3 spec) ----------------------------------------------------

FILE_KINDS: tuple[str, ...] = (
    "source_code", "screenshot", "pdf", "markdown", "report",
    "log", "har", "api_spec", "documentation", "note", "other",
)


def kind_for(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return "screenshot"
    if ext == ".pdf":
        return "pdf"
    if ext in {".md", ".rst", ".txt"}:
        return "markdown"
    if ext in {".log"}:
        return "log"
    if ext == ".har":
        return "har"
    if ext in {".json", ".yaml", ".yml"}:
        return "api_spec"
    if ext in {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java",
               ".rb", ".php", ".cs", ".cpp", ".c", ".rs"}:
        return "source_code"
    if ext in {".html", ".css"}:
        return "source_code"
    if "report" in path.name.lower():
        return "report"
    if "doc" in path.name.lower():
        return "documentation"
    return "other"


# ---- Data model --------------------------------------------------------------

@dataclass
class MemoryChunk:
    """One chunk of a file, embedded and tagged."""

    chunk_id: str
    project_id: str
    source_file: str
    file_kind: str
    chunk_type: str  # code_block | paragraph | log_line | api_endpoint | etc.
    text: str
    line_start: int
    line_end: int
    language: str = ""
    component: str = ""
    tags: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)
    component_refs: list[str] = field(default_factory=list)
    embedding: list[float] = field(default_factory=list)
    embedding_model: str = "hash-128"
    indexed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResearchReport:
    """A summary of an indexing operation."""

    project_id: str
    files_indexed: int = 0
    chunks_indexed: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    by_file: dict[str, int] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---- Engine ------------------------------------------------------------------

class ResearchMemoryEngine:
    """Chunk + embed + search every artifact in a project workspace."""

    def __init__(
        self,
        base_path: Path | None = None,
        embedder: Embedder | None = None,
        chunk_size: int = 30,
        chunk_overlap: int = 5,
    ):
        self.base_path = base_path
        self.embedder: Embedder = embedder or HashEmbedder()
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        # project_id -> {chunk_id: MemoryChunk}
        self._index: dict[str, dict[str, MemoryChunk]] = {}
        # ensure on-disk persistence is initialized
        if self.base_path is not None:
            self.base_path.mkdir(parents=True, exist_ok=True)

    # ---- file IO ----------------------------------------------------------

    def _index_path(self, project_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in project_id)
        if self.base_path is None:
            return Path(f"<memory>/research_memory/{safe}.json")
        d = self.base_path / "research_memory"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe}.json"

    def _save(self, project_id: str) -> None:
        if self.base_path is None:
            return
        chunks = list(self._index.get(project_id, {}).values())
        self._index_path(project_id).write_text(
            json.dumps(
                {
                    "project_id": project_id,
                    "embedding_model": self.embedder.dim and f"hash-{self.embedder.dim}" or "unknown",
                    "chunks": [c.to_dict() for c in chunks],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def _load(self, project_id: str) -> None:
        if self.base_path is None:
            return
        p = self._index_path(project_id)
        if not p.exists():
            self._index[project_id] = {}
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            self._index[project_id] = {
                c["chunk_id"]: MemoryChunk(**c)
                for c in data.get("chunks", [])
            }
        except Exception as e:  # pragma: no cover
            logger.error("research_memory_load_failed", project_id=project_id, error=str(e))
            self._index[project_id] = {}

    # ---- chunking ---------------------------------------------------------

    def _split_chunks(self, text: str) -> list[tuple[str, int, int]]:
        """Return (chunk_text, line_start, line_end) tuples."""
        lines = text.splitlines()
        if not lines:
            return []
        if len(lines) <= self.chunk_size:
            return [(text, 0, len(lines))]
        chunks: list[tuple[str, int, int]] = []
        step = self.chunk_size - self.chunk_overlap
        i = 0
        while i < len(lines):
            end = min(i + self.chunk_size, len(lines))
            chunk_text = "\n".join(lines[i:end])
            chunks.append((chunk_text, i, end))
            if end >= len(lines):
                break
            i += step
        return chunks

    # ---- detection of refs and tags --------------------------------------

    _COMPONENT_HINT = re.compile(
        r"\b([A-Z][a-zA-Z0-9]+(?:Service|Controller|Manager|Repository|"
        r"Handler|Router|Middleware|Auth|Session|Token|User))\b"
    )
    _RISK_HINT = re.compile(
        r"\b(sql\s*injection|xss|csrf|ssrf|xxe|rce|"
        r"command\s*injection|path\s*traversal|idor|bola|"
        r"open\s*redirect|deserialization|ssti)\b",
        re.IGNORECASE,
    )

    def _detect_component_refs(self, text: str) -> list[str]:
        return list({m.group(0) for m in self._COMPONENT_HINT.finditer(text)})[:8]

    def _detect_risk_tags(self, text: str) -> list[str]:
        return list({m.group(0).lower().replace(" ", "_") for m in self._RISK_HINT.finditer(text)})

    def _detect_chunk_type(self, kind: str, text: str) -> str:
        head = text.lstrip().split("\n", 1)[0]
        if kind == "source_code":
            if head.startswith("def ") or head.startswith("function "):
                return "function"
            if head.startswith("class "):
                return "class"
            if head.startswith("import ") or head.startswith("from "):
                return "import"
            return "code_block"
        if kind in {"markdown", "documentation"}:
            if head.startswith("# "):
                return "heading"
            return "paragraph"
        if kind == "log":
            return "log_line"
        if kind == "api_spec":
            return "api_endpoint"
        if kind == "report":
            return "report_section"
        return "text"

    # ---- indexing ---------------------------------------------------------

    def index_file(
        self,
        project_id: str,
        file_path: Path | str,
        *,
        content: str | None = None,
        component: str = "",
        tags: Iterable[str] | None = None,
    ) -> list[MemoryChunk]:
        """Chunk + embed a file, returning the new chunks (also persisted)."""
        if project_id not in self._index:
            self._load(project_id)

        path = Path(file_path)
        if content is None:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                logger.warning(
                    "research_memory_index_failed",
                    path=str(path), error=str(e),
                )
                return []
        if not content:
            return []

        kind = kind_for(path)
        new_chunks: list[MemoryChunk] = []
        model_name = f"hash-{self.embedder.dim}"
        indexed_at = datetime.utcnow().isoformat()
        all_tags = list(tags or [])

        for chunk_text, line_start, line_end in self._split_chunks(content):
            comp_refs = self._detect_component_refs(chunk_text)
            risk_tags = self._detect_risk_tags(chunk_text)
            chunk = MemoryChunk(
                chunk_id=str(uuid.uuid4()),
                project_id=project_id,
                source_file=str(path),
                file_kind=kind,
                chunk_type=self._detect_chunk_type(kind, chunk_text),
                text=chunk_text,
                line_start=line_start,
                line_end=line_end,
                language=path.suffix.lstrip(".") or "",
                component=component,
                tags=all_tags + comp_refs,
                risk_tags=risk_tags,
                relationships=comp_refs,
                component_refs=comp_refs,
                embedding=self.embedder.embed(chunk_text),
                embedding_model=model_name,
                indexed_at=indexed_at,
            )
            self._index.setdefault(project_id, {})[chunk.chunk_id] = chunk
            new_chunks.append(chunk)

        self._save(project_id)
        logger.info(
            "research_memory_indexed",
            project_id=project_id,
            file=str(path),
            chunks=len(new_chunks),
            kind=kind,
        )
        return new_chunks

    def index_text(
        self,
        project_id: str,
        kind: str,
        text: str,
        *,
        source_label: str = "<inline>",
        component: str = "",
        tags: Iterable[str] | None = None,
    ) -> list[MemoryChunk]:
        """Index an in-memory text blob (e.g. a note or report section)."""
        if project_id not in self._index:
            self._load(project_id)
        new_chunks: list[MemoryChunk] = []
        model_name = f"hash-{self.embedder.dim}"
        indexed_at = datetime.utcnow().isoformat()
        all_tags = list(tags or [])

        for chunk_text, line_start, line_end in self._split_chunks(text):
            comp_refs = self._detect_component_refs(chunk_text)
            risk_tags = self._detect_risk_tags(chunk_text)
            chunk = MemoryChunk(
                chunk_id=str(uuid.uuid4()),
                project_id=project_id,
                source_file=source_label,
                file_kind=kind if kind in FILE_KINDS else "other",
                chunk_type=self._detect_chunk_type(kind, chunk_text),
                text=chunk_text,
                line_start=line_start,
                line_end=line_end,
                component=component,
                tags=all_tags + comp_refs,
                risk_tags=risk_tags,
                relationships=comp_refs,
                component_refs=comp_refs,
                embedding=self.embedder.embed(chunk_text),
                embedding_model=model_name,
                indexed_at=indexed_at,
            )
            self._index.setdefault(project_id, {})[chunk.chunk_id] = chunk
            new_chunks.append(chunk)

        self._save(project_id)
        return new_chunks

    # ---- search -----------------------------------------------------------

    def _cosine(self, a: list[float], b: list[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        return sum(x * y for x, y in zip(a, b))

    def _bm25_score(self, query_tokens: list[str], doc_tokens: list[str]) -> float:
        if not query_tokens or not doc_tokens:
            return 0.0
        tf = Counter(doc_tokens)
        hits = sum(tf.get(t, 0) for t in query_tokens)
        return hits / max(1, len(doc_tokens))

    def search(
        self,
        project_id: str,
        query: str,
        *,
        top_k: int = 10,
        kind: str | None = None,
        tag: str | None = None,
        risk: str | None = None,
        rerank: Callable[[list[MemoryChunk], str], list[MemoryChunk]] | None = None,
    ) -> list[MemoryChunk]:
        """Search chunks by combined BM25 + cosine similarity."""
        if project_id not in self._index:
            self._load(project_id)
        chunks = list(self._index.get(project_id, {}).values())
        if not chunks:
            return []
        if kind:
            chunks = [c for c in chunks if c.file_kind == kind]
        if tag:
            chunks = [c for c in chunks if tag in c.tags]
        if risk:
            chunks = [c for c in chunks if risk in c.risk_tags]

        query_tokens = re.findall(r"[a-zA-Z0-9_]+", query.lower())
        q_emb = self.embedder.embed(query)
        scored: list[tuple[float, MemoryChunk]] = []
        # If a filter (kind/tag/risk) is applied we still want to surface the
        # filtered chunks even when the query doesn't lexically match the
        # content — the user is explicitly narrowing the corpus. In that
        # case we assign a tiny base score so they still appear.
        has_filter = bool(kind or tag or risk)
        for c in chunks:
            doc_tokens = re.findall(r"[a-zA-Z0-9_]+", c.text.lower())
            bm = self._bm25_score(query_tokens, doc_tokens)
            cos = self._cosine(q_emb, c.embedding)
            score = 0.6 * max(0.0, cos) + 0.4 * min(1.0, bm * 4.0)
            if score > 0 or has_filter:
                scored.append((score or 0.01, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        top = [c for _, c in scored[:top_k]]
        if rerank is not None:
            top = rerank(top, query)
        return top

    # ---- queries ----------------------------------------------------------

    def stats(self, project_id: str) -> ResearchReport:
        if project_id not in self._index:
            self._load(project_id)
        chunks = list(self._index.get(project_id, {}).values())
        by_kind: dict[str, int] = {}
        by_file: dict[str, int] = {}
        for c in chunks:
            by_kind[c.file_kind] = by_kind.get(c.file_kind, 0) + 1
            by_file[c.source_file] = by_file.get(c.source_file, 0) + 1
        return ResearchReport(
            project_id=project_id,
            files_indexed=len(by_file),
            chunks_indexed=len(chunks),
            by_kind=by_kind,
            by_file=by_file,
            finished_at=datetime.utcnow().isoformat(),
        )

    def all(self, project_id: str) -> list[MemoryChunk]:
        if project_id not in self._index:
            self._load(project_id)
        return list(self._index.get(project_id, {}).values())


# Module-level singleton (lazy).
_engine: ResearchMemoryEngine | None = None


def get_research_memory(
    base_path: Path | None = None,
    embedder: Embedder | None = None,
) -> ResearchMemoryEngine:
    global _engine
    if _engine is None:
        _engine = ResearchMemoryEngine(base_path=base_path, embedder=embedder)
    elif embedder is not None and not isinstance(_engine.embedder, OllamaEmbedder):
        # Allow swapping in a real embedder after first creation.
        _engine.embedder = embedder
    return _engine
