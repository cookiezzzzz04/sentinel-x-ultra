"""Project Workspace System — V3.

Every project automatically creates a standard folder layout under
``<base>/Projects/<project-name>/``:

    /source-code        — uploaded source files
    /documentation      — markdown / PDF / specs
    /reports            — generated reports
    /screenshots        — image evidence
    /findings           — finding artifacts
    /notes              — analyst notes
    /logs               — terminal / agent logs (mirrors AUDIT_LOG)
    /scope              — scope files (rules of engagement, etc.)
    /exports            — export bundles
    /agent-memory       — per-agent knowledge stores
    /vector-index       — RAG index artifacts
    /graphs             — knowledge / permission graph artifacts

All uploaded files are *automatically* copied into the workspace, indexed,
categorized, and tagged so that agents can later find them through the
research memory engine.
"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


# The canonical folder names from the V3 spec.
WORKSPACE_DIRS: tuple[str, ...] = (
    "source-code",
    "documentation",
    "reports",
    "screenshots",
    "findings",
    "notes",
    "logs",
    "scope",
    "exports",
    "agent-memory",
    "vector-index",
    "graphs",
)


class FileCategory(str, Enum):
    """How an uploaded file is classified for storage + tagging."""

    SOURCE_CODE = "source_code"
    DOCUMENTATION = "documentation"
    REPORT = "report"
    SCREENSHOT = "screenshot"
    FINDING = "finding"
    NOTE = "note"
    LOG = "log"
    SCOPE = "scope"
    HAR = "har"
    API_SPEC = "api_spec"
    OTHER = "other"


# Extension → category heuristic used during auto-categorization.
_CATEGORY_BY_EXT: dict[str, FileCategory] = {
    # Source
    ".py": FileCategory.SOURCE_CODE,
    ".js": FileCategory.SOURCE_CODE,
    ".ts": FileCategory.SOURCE_CODE,
    ".tsx": FileCategory.SOURCE_CODE,
    ".jsx": FileCategory.SOURCE_CODE,
    ".go": FileCategory.SOURCE_CODE,
    ".java": FileCategory.SOURCE_CODE,
    ".rb": FileCategory.SOURCE_CODE,
    ".php": FileCategory.SOURCE_CODE,
    ".cs": FileCategory.SOURCE_CODE,
    ".cpp": FileCategory.SOURCE_CODE,
    ".c": FileCategory.SOURCE_CODE,
    ".rs": FileCategory.SOURCE_CODE,
    # Docs
    ".md": FileCategory.DOCUMENTATION,
    ".rst": FileCategory.DOCUMENTATION,
    ".txt": FileCategory.DOCUMENTATION,
    ".pdf": FileCategory.DOCUMENTATION,
    # Specs
    ".json": FileCategory.API_SPEC,
    ".yaml": FileCategory.API_SPEC,
    ".yml": FileCategory.API_SPEC,
    # Images
    ".png": FileCategory.SCREENSHOT,
    ".jpg": FileCategory.SCREENSHOT,
    ".jpeg": FileCategory.SCREENSHOT,
    ".gif": FileCategory.SCREENSHOT,
    ".webp": FileCategory.SCREENSHOT,
    # Logs
    ".log": FileCategory.LOG,
    # Trace
    ".har": FileCategory.HAR,
}


# Default tags applied per category — agents extend these.
_CATEGORY_TAGS: dict[FileCategory, list[str]] = {
    FileCategory.SOURCE_CODE: ["source", "code"],
    FileCategory.DOCUMENTATION: ["doc", "reference"],
    FileCategory.REPORT: ["report", "output"],
    FileCategory.SCREENSHOT: ["evidence", "image"],
    FileCategory.FINDING: ["finding", "evidence"],
    FileCategory.NOTE: ["note", "analyst"],
    FileCategory.LOG: ["log", "audit"],
    FileCategory.SCOPE: ["scope", "rules-of-engagement"],
    FileCategory.HAR: ["har", "traffic"],
    FileCategory.API_SPEC: ["api", "spec"],
    FileCategory.OTHER: ["misc"],
}


# Map each FileCategory to its on-disk directory name from the V3 spec.
# Some enum values use underscores; the spec directory names use hyphens.
CATEGORY_DIR_NAME: dict[FileCategory, str] = {
    FileCategory.SOURCE_CODE: "source-code",
    FileCategory.DOCUMENTATION: "documentation",
    FileCategory.REPORT: "reports",
    FileCategory.SCREENSHOT: "screenshots",
    FileCategory.FINDING: "findings",
    FileCategory.NOTE: "notes",
    FileCategory.LOG: "logs",
    FileCategory.SCOPE: "scope",
    FileCategory.HAR: "documentation",  # HARs live under documentation
    FileCategory.API_SPEC: "documentation",  # API specs live under documentation
    FileCategory.OTHER: "documentation",
}


def _dir_name_for(category: FileCategory | str) -> str:
    if isinstance(category, FileCategory):
        return CATEGORY_DIR_NAME.get(category, "documentation")
    return category  # already a directory name


@dataclass
class IndexedFile:
    """Metadata about a file living inside the workspace."""

    file_id: str
    project_id: str
    relative_path: str
    category: str
    tags: list[str] = field(default_factory=list)
    size_bytes: int = 0
    sha256: str = ""
    agent_owners: list[str] = field(default_factory=list)
    indexed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Workspace:
    """In-memory handle for a project workspace on disk."""

    project_id: str
    name: str
    root: Path
    files: dict[str, IndexedFile] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "root": str(self.root),
            "dirs": [d for d in WORKSPACE_DIRS],
            "file_count": len(self.files),
            "files": [f.to_dict() for f in self.files.values()],
            "created_at": self.created_at,
        }


def _safe_dir_name(name: str) -> str:
    """Make a project name filesystem-safe across OSes."""
    bad = '<>:"/\\|?*'
    cleaned = "".join("_" if c in bad else c for c in name).strip().strip(".")
    return cleaned or "project"


def _category_for(path: Path) -> FileCategory:
    return _CATEGORY_BY_EXT.get(path.suffix.lower(), FileCategory.OTHER)


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


class ProjectWorkspaceManager:
    """Creates, manages, and queries per-project workspaces."""

    def __init__(self, base_path: Path | None = None):
        # Spec: /Projects/<project-name>
        self.base_path = base_path or (Path.home() / ".sentinel-x" / "Projects")
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._workspaces: dict[str, Workspace] = {}

    # ---- creation ---------------------------------------------------------

    def create_workspace(self, project_id: str, name: str) -> Workspace:
        """Create the full folder layout for a new project."""
        if project_id in self._workspaces:
            return self._workspaces[project_id]

        project_dir = self.base_path / _safe_dir_name(name)
        project_dir.mkdir(parents=True, exist_ok=True)

        for sub in WORKSPACE_DIRS:
            (project_dir / sub).mkdir(parents=True, exist_ok=True)

        ws = Workspace(
            project_id=project_id,
            name=name,
            root=project_dir,
            created_at=datetime.utcnow().isoformat(),
        )
        self._workspaces[project_id] = ws

        # Persist workspace manifest
        (project_dir / "workspace.json").write_text(
            __import__("json").dumps(ws.to_dict(), indent=2)
        )

        logger.info(
            "workspace_created",
            project_id=project_id,
            name=name,
            root=str(project_dir),
        )
        return ws

    # ---- access -----------------------------------------------------------

    def get_workspace(self, project_id: str) -> Workspace | None:
        return self._workspaces.get(project_id)

    def dir_for(self, project_id: str, category: FileCategory | str) -> Path | None:
        ws = self.get_workspace(project_id)
        if ws is None:
            return None
        sub = category.value if isinstance(category, FileCategory) else category
        target = ws.root / sub
        return target if target.exists() else None

    # ---- file ingestion ---------------------------------------------------

    def add_file(
        self,
        project_id: str,
        source_path: Path | str,
        *,
        category: FileCategory | None = None,
        tags: Iterable[str] | None = None,
        agent_owners: Iterable[str] | None = None,
    ) -> IndexedFile | None:
        """Copy a file into the workspace, categorize, tag, and index it."""
        ws = self.get_workspace(project_id)
        if ws is None:
            logger.warning("add_file_no_workspace", project_id=project_id)
            return None

        source = Path(source_path)
        if not source.exists() or not source.is_file():
            logger.warning("add_file_missing", path=str(source))
            return None

        cat = category or _category_for(source)
        target_dir = ws.root / _dir_name_for(cat)
        target_dir.mkdir(parents=True, exist_ok=True)

        target = target_dir / source.name
        # Avoid clobbering existing files
        if target.exists():
            stem, suffix = target.stem, target.suffix
            i = 1
            while target.exists():
                target = target_dir / f"{stem}_{i}{suffix}"
                i += 1

        shutil.copy2(source, target)

        all_tags = list(_CATEGORY_TAGS.get(cat, []))
        if tags:
            all_tags.extend(tags)

        file_id = hashlib.sha256(str(target).encode()).hexdigest()[:16]
        indexed = IndexedFile(
            file_id=file_id,
            project_id=project_id,
            relative_path=str(target.relative_to(ws.root)),
            category=cat.value,
            tags=all_tags,
            size_bytes=target.stat().st_size,
            sha256=_hash_file(target),
            agent_owners=list(agent_owners or []),
            indexed_at=datetime.utcnow().isoformat(),
        )
        ws.files[file_id] = indexed
        logger.info(
            "workspace_file_indexed",
            project_id=project_id,
            path=indexed.relative_path,
            category=cat.value,
        )
        return indexed

    def add_text_file(
        self,
        project_id: str,
        category: FileCategory | str,
        filename: str,
        content: str,
        *,
        tags: Iterable[str] | None = None,
        agent_owners: Iterable[str] | None = None,
    ) -> IndexedFile | None:
        """Create a text file directly in the workspace (e.g. notes, reports)."""
        ws = self.get_workspace(project_id)
        if ws is None:
            return None
        sub = _dir_name_for(category)
        target_dir = ws.root / sub
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / filename
        target.write_text(content, encoding="utf-8")

        file_id = hashlib.sha256(str(target).encode()).hexdigest()[:16]
        all_tags = list(_CATEGORY_TAGS.get(
            category if isinstance(category, FileCategory) else FileCategory.OTHER, []
        ))
        if tags:
            all_tags.extend(tags)

        indexed = IndexedFile(
            file_id=file_id,
            project_id=project_id,
            relative_path=str(target.relative_to(ws.root)),
            category=sub,
            tags=all_tags,
            size_bytes=target.stat().st_size,
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            agent_owners=list(agent_owners or []),
            indexed_at=datetime.utcnow().isoformat(),
        )
        ws.files[file_id] = indexed
        return indexed

    # ---- queries ----------------------------------------------------------

    def search(
        self,
        project_id: str,
        *,
        category: FileCategory | str | None = None,
        tag: str | None = None,
        agent: str | None = None,
    ) -> list[IndexedFile]:
        """Search indexed files by category / tag / owning agent."""
        ws = self.get_workspace(project_id)
        if ws is None:
            return []
        # Match the logical category (enum value) rather than the on-disk dir name.
        cat_val = category.value if isinstance(category, FileCategory) else category
        out: list[IndexedFile] = []
        for f in ws.files.values():
            if cat_val and f.category != cat_val:
                continue
            if tag and tag not in f.tags:
                continue
            if agent and agent not in f.agent_owners:
                continue
            out.append(f)
        return out


# Module-level singleton — created lazily so tests can override.
_manager: ProjectWorkspaceManager | None = None


def get_workspace_manager(base_path: Path | None = None) -> ProjectWorkspaceManager:
    global _manager
    if _manager is None:
        _manager = ProjectWorkspaceManager(base_path)
    return _manager
