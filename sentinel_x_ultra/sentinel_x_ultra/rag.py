"""RAG Intelligence System - Indexing and Retrieval."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ChunkMetadata:
    """Metadata for an indexed chunk."""
    chunk_id: str
    source_file: str
    source_type: str  # code | documentation | api_spec | scope | finding
    component: str
    chunk_type: str  # function | class | endpoint | config | doc_section
    language: str | None = None
    risk_tags: list[str] = field(default_factory=list)
    function_name: str | None = None
    line_start: int = 0
    line_end: int = 0
    embedding_model: str = ""
    indexed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "source_file": self.source_file,
            "source_type": self.source_type,
            "component": self.component,
            "chunk_type": self.chunk_type,
            "language": self.language,
            "risk_tags": self.risk_tags,
            "function_name": self.function_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "embedding_model": self.embedding_model,
            "indexed_at": self.indexed_at,
        }


@dataclass
class RetrievalResult:
    """Result from retrieval query."""
    chunk: ChunkMetadata
    score: float
    rerank_score: float
    text: str
    source_confidence: str  # high | medium | low


class RAGIndexer:
    """Document chunking and indexing."""

    def __init__(self, llm_router: Any):
        self.llm_router = llm_router
        self._chunks: dict[str, ChunkMetadata] = {}
        self._chunks_by_source: dict[str, list[str]] = {}
        self._chunks_by_component: dict[str, list[str]] = {}

    def _compute_chunk_id(self, source_file: str, chunk_type: str, line_start: int) -> str:
        """Compute a unique ID for a chunk."""
        data = f"{source_file}:{chunk_type}:{line_start}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def index_code(
        self,
        file_path: str,
        code: str,
        language: str | None = None,
        component: str = "",
        chunk_size: int = 500,
        overlap: int = 50,
    ) -> list[str]:
        """Index source code into chunks."""
        chunk_ids = []

        # Simple line-based chunking
        lines = code.split("\n")
        total_lines = len(lines)

        for start in range(0, total_lines, chunk_size - overlap):
            end = min(start + chunk_size, total_lines)
            chunk_text = "\n".join(lines[start:end])

            chunk_id = self._compute_chunk_id(file_path, "code", start)

            metadata = ChunkMetadata(
                chunk_id=chunk_id,
                source_file=file_path,
                source_type="code",
                component=component,
                chunk_type="function",  # TODO: detect actual type
                language=language,
                line_start=start,
                line_end=end,
                indexed_at=datetime.utcnow().isoformat(),
            )

            self._chunks[chunk_id] = metadata
            chunk_ids.append(chunk_id)

            if file_path not in self._chunks_by_source:
                self._chunks_by_source[file_path] = []
            self._chunks_by_source[file_path].append(chunk_id)

            if component not in self._chunks_by_component:
                self._chunks_by_component[component] = []
            self._chunks_by_component[component].append(chunk_id)

        logger.info("code_indexed", file=file_path, chunks=len(chunk_ids))
        return chunk_ids

    def index_documentation(
        self,
        doc_id: str,
        content: str,
        doc_type: str = "doc_section",
        component: str = "",
    ) -> str:
        """Index documentation content."""
        chunk_id = self._compute_chunk_id(doc_id, "doc", 0)

        metadata = ChunkMetadata(
            chunk_id=chunk_id,
            source_file=doc_id,
            source_type="documentation",
            component=component,
            chunk_type=doc_type,
            indexed_at=datetime.utcnow().isoformat(),
        )

        self._chunks[chunk_id] = metadata

        if doc_id not in self._chunks_by_source:
            self._chunks_by_source[doc_id] = []
        self._chunks_by_source[doc_id].append(chunk_id)

        logger.info("doc_indexed", doc_id=doc_id)
        return chunk_id

    def get_chunk(self, chunk_id: str) -> ChunkMetadata | None:
        """Get chunk metadata by ID."""
        return self._chunks.get(chunk_id)

    def get_chunks_for_source(self, source_file: str) -> list[ChunkMetadata]:
        """Get all chunks for a source file."""
        chunk_ids = self._chunks_by_source.get(source_file, [])
        return [self._chunks[cid] for cid in chunk_ids if cid in self._chunks]

    def get_chunks_by_component(self, component: str) -> list[ChunkMetadata]:
        """Get all chunks for a component."""
        chunk_ids = self._chunks_by_component.get(component, [])
        return [self._chunks[cid] for cid in chunk_ids if cid in self._chunks]

    def clear(self):
        """Clear all indexed content."""
        self._chunks.clear()
        self._chunks_by_source.clear()
        self._chunks_by_component.clear()
        logger.info("rag_index_cleared")


class RAGRetriever:
    """Retrieval with reranking."""

    def __init__(self, indexer: RAGIndexer, llm_router: Any):
        self.indexer = indexer
        self.llm_router = llm_router
        self._chunk_texts: dict[str, str] = {}  # chunk_id -> text

    def add_chunk_text(self, chunk_id: str, text: str):
        """Add the actual text for a chunk."""
        self._chunk_texts[chunk_id] = text

    async def retrieve(
        self,
        query: str,
        top_k: int = 10,
        component_filter: str | None = None,
    ) -> list[RetrievalResult]:
        """Retrieve relevant chunks for a query."""
        # For now, simple keyword matching
        # TODO: Implement vector search with embeddings
        results = []

        chunks = list(self.indexer._chunks.values())

        if component_filter:
            chunks = [c for c in chunks if c.component == component_filter]

        for chunk in chunks:
            text = self._chunk_texts.get(chunk.chunk_id, "")

            # Simple scoring based on keyword overlap
            query_words = set(query.lower().split())
            text_words = set(text.lower().split())
            overlap = len(query_words & text_words)

            if overlap > 0:
                score = overlap / len(query_words)
                results.append(RetrievalResult(
                    chunk=chunk,
                    score=score,
                    rerank_score=score,
                    text=text[:500],  # Truncate
                    source_confidence="medium",
                ))

        # Sort by score and return top_k
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_k]

    async def rerank(self, results: list[RetrievalResult], query: str) -> list[RetrievalResult]:
        """Rerank retrieval results using LLM."""
        # TODO: Implement LLM-based reranking
        return results


class RAGEngine:
    """Combined RAG system."""

    def __init__(self, llm_router: Any):
        self.llm_router = llm_router
        self.indexer = RAGIndexer(llm_router)
        self.retriever = RAGRetriever(self.indexer, llm_router)

    async def index_file(self, file_path: str, content: str, file_type: str = "code"):
        """Index a file for retrieval."""
        if file_type == "code":
            language = self._detect_language(file_path)
            chunk_ids = self.indexer.index_code(file_path, content, language=language)
            # Store the content for each chunk so retrieval can return it
            lines = content.split("\n")
            for chunk_id in chunk_ids:
                metadata = self.indexer.get_chunk(chunk_id)
                if metadata:
                    chunk_lines = lines[metadata.line_start:metadata.line_end]
                    self.retriever.add_chunk_text(chunk_id, "\n".join(chunk_lines))
        else:
            chunk_id = self.indexer.index_documentation(file_path, content)
            self.retriever.add_chunk_text(chunk_id, content)

    def _detect_language(self, file_path: str) -> str | None:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".rb": "ruby",
            ".php": "php",
            ".cs": "csharp",
            ".cpp": "cpp",
            ".c": "c",
            ".rs": "rust",
        }
        import os
        _, ext = os.path.splitext(file_path)
        return ext_map.get(ext.lower())

    async def retrieve_for_reasoning(
        self,
        query: str,
        context_type: str = "code",
        top_k: int = 5,
    ) -> list[RetrievalResult]:
        """Retrieve context for reasoning tasks."""
        results = await self.retriever.retrieve(query, top_k=top_k)
        return await self.retriever.rerank(results, query)

    async def retrieve_evidence(
        self,
        finding_topic: str,
        component: str | None = None,
    ) -> list[RetrievalResult]:
        """Retrieve evidence for a finding."""
        results = await self.retriever.retrieve(
            finding_topic,
            top_k=5,
            component_filter=component,
        )
        return await self.retriever.rerank(results, finding_topic)
