"""Agent-Centric Knowledge System — V3.

The V3 spec removes the *separate* knowledge tabs and makes **agents** the
owners of all knowledge. Each knowledge type maps to a specific agent
role::

    Documentation Agent
        - Program rules
        - Scope documents
        - Security policies
        - Architecture documents
        - Notes

    Tooling Agent
        - Tool references
        - Workflow references
        - Research references
        - Methodology references

    Reporting Agent
        - Report templates
        - Severity guidelines
        - Finding formats
        - Remediation patterns

    Architecture Agent
        - Data flow maps
        - Service maps
        - Trust boundaries
        - Identity systems

    Business Logic Agent
        - User journeys
        - Workflow models
        - Ownership models
        - Payment models

The :class:`AgentKnowledgeStore` persists each agent's knowledge in a
project workspace (``/agent-memory/<agent>.json``) and keeps a fast
in-process cache for retrieval.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import structlog

logger = structlog.get_logger()


class KnowledgeKind(str):
    """Names of knowledge kinds (kept as plain strings for forward compat)."""

    # Documentation agent
    PROGRAM_RULES = "program_rules"
    SCOPE_DOCUMENTS = "scope_documents"
    SECURITY_POLICIES = "security_policies"
    ARCHITECTURE_DOCUMENTS = "architecture_documents"
    NOTES = "notes"

    # Tooling agent
    TOOL_REFERENCES = "tool_references"
    WORKFLOW_REFERENCES = "workflow_references"
    RESEARCH_REFERENCES = "research_references"
    METHODOLOGY_REFERENCES = "methodology_references"

    # Reporting agent
    REPORT_TEMPLATES = "report_templates"
    SEVERITY_GUIDELINES = "severity_guidelines"
    FINDING_FORMATS = "finding_formats"
    REMEDIATION_PATTERNS = "remediation_patterns"

    # Architecture agent
    DATA_FLOW_MAPS = "data_flow_maps"
    SERVICE_MAPS = "service_maps"
    TRUST_BOUNDARIES = "trust_boundaries"
    IDENTITY_SYSTEMS = "identity_systems"

    # Business logic agent
    USER_JOURNEYS = "user_journeys"
    WORKFLOW_MODELS = "workflow_models"
    OWNERSHIP_MODELS = "ownership_models"
    PAYMENT_MODELS = "payment_models"


# Maps an agent role to the kinds of knowledge it owns.
AGENT_OWNERSHIP: dict[str, tuple[str, ...]] = {
    "documentation": (
        KnowledgeKind.PROGRAM_RULES,
        KnowledgeKind.SCOPE_DOCUMENTS,
        KnowledgeKind.SECURITY_POLICIES,
        KnowledgeKind.ARCHITECTURE_DOCUMENTS,
        KnowledgeKind.NOTES,
    ),
    "tooling": (
        KnowledgeKind.TOOL_REFERENCES,
        KnowledgeKind.WORKFLOW_REFERENCES,
        KnowledgeKind.RESEARCH_REFERENCES,
        KnowledgeKind.METHODOLOGY_REFERENCES,
    ),
    "reporting": (
        KnowledgeKind.REPORT_TEMPLATES,
        KnowledgeKind.SEVERITY_GUIDELINES,
        KnowledgeKind.FINDING_FORMATS,
        KnowledgeKind.REMEDIATION_PATTERNS,
    ),
    "architecture": (
        KnowledgeKind.DATA_FLOW_MAPS,
        KnowledgeKind.SERVICE_MAPS,
        KnowledgeKind.TRUST_BOUNDARIES,
        KnowledgeKind.IDENTITY_SYSTEMS,
    ),
    "business_logic": (
        KnowledgeKind.USER_JOURNEYS,
        KnowledgeKind.WORKFLOW_MODELS,
        KnowledgeKind.OWNERSHIP_MODELS,
        KnowledgeKind.PAYMENT_MODELS,
    ),
}


@dataclass
class KnowledgeItem:
    """A single piece of knowledge owned by an agent."""

    item_id: str
    agent: str
    kind: str
    title: str
    body: str = ""
    tags: list[str] = field(default_factory=list)
    related_files: list[str] = field(default_factory=list)  # workspace-relative
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KnowledgeItem":
        return cls(**data)


@dataclass
class AgentKnowledgeBundle:
    """All knowledge owned by a single agent within a single project."""

    project_id: str
    agent: str
    items: dict[str, KnowledgeItem] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "agent": self.agent,
            "items": [i.to_dict() for i in self.items.values()],
            "count": len(self.items),
        }


class AgentKnowledgeStore:
    """Persists and queries per-agent knowledge inside a project workspace."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = Path(workspace_root)
        self.memory_dir = self.workspace_root / "agent-memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        # project_id -> agent -> bundle
        self._bundles: dict[str, dict[str, AgentKnowledgeBundle]] = {}

    # ---- file IO ----------------------------------------------------------

    def _bundle_path(self, project_id: str, agent: str) -> Path:
        safe_agent = "".join(c if c.isalnum() or c in "_-" else "_" for c in agent)
        safe_pid = "".join(c if c.isalnum() or c in "_-" else "_" for c in project_id)
        return self.memory_dir / f"{safe_pid}__{safe_agent}.json"

    def _load_bundle(self, project_id: str, agent: str) -> AgentKnowledgeBundle:
        bundle = self._bundles.setdefault(project_id, {}).get(agent)
        if bundle is not None:
            return bundle
        bundle = AgentKnowledgeBundle(project_id=project_id, agent=agent)
        path = self._bundle_path(project_id, agent)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for raw in data.get("items", []):
                    item = KnowledgeItem.from_dict(raw)
                    bundle.items[item.item_id] = item
            except Exception as e:  # pragma: no cover - defensive
                logger.error("agent_knowledge_load_failed", path=str(path), error=str(e))
        self._bundles.setdefault(project_id, {})[agent] = bundle
        return bundle

    def _save_bundle(self, bundle: AgentKnowledgeBundle) -> None:
        path = self._bundle_path(bundle.project_id, bundle.agent)
        path.write_text(
            json.dumps(bundle.to_dict(), indent=2), encoding="utf-8"
        )

    # ---- ownership validation -------------------------------------------

    @staticmethod
    def kinds_for(agent: str) -> tuple[str, ...]:
        return AGENT_OWNERSHIP.get(agent, ())

    @staticmethod
    def validate_ownership(agent: str, kind: str) -> bool:
        return kind in AGENT_OWNERSHIP.get(agent, ())

    # ---- CRUD -------------------------------------------------------------

    def add(
        self,
        project_id: str,
        agent: str,
        kind: str,
        title: str,
        body: str = "",
        *,
        tags: Iterable[str] | None = None,
        related_files: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> KnowledgeItem:
        if not self.validate_ownership(agent, kind):
            raise ValueError(
                f"Agent '{agent}' does not own knowledge of kind '{kind}'. "
                f"Allowed kinds: {list(self.kinds_for(agent))}"
            )
        bundle = self._load_bundle(project_id, agent)
        now = datetime.utcnow().isoformat()
        item = KnowledgeItem(
            item_id=str(uuid.uuid4()),
            agent=agent,
            kind=kind,
            title=title,
            body=body,
            tags=list(tags or []),
            related_files=list(related_files or []),
            metadata=dict(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        bundle.items[item.item_id] = item
        self._save_bundle(bundle)
        logger.info(
            "agent_knowledge_added",
            project_id=project_id,
            agent=agent,
            kind=kind,
            title=title,
        )
        return item

    def get(self, project_id: str, agent: str, item_id: str) -> KnowledgeItem | None:
        bundle = self._load_bundle(project_id, agent)
        return bundle.items.get(item_id)

    def list(
        self,
        project_id: str,
        agent: str,
        *,
        kind: str | None = None,
        tag: str | None = None,
    ) -> list[KnowledgeItem]:
        bundle = self._load_bundle(project_id, agent)
        out: list[KnowledgeItem] = []
        for item in bundle.items.values():
            if kind and item.kind != kind:
                continue
            if tag and tag not in item.tags:
                continue
            out.append(item)
        return out

    def update(
        self,
        project_id: str,
        agent: str,
        item_id: str,
        *,
        title: str | None = None,
        body: str | None = None,
        tags: Iterable[str] | None = None,
        related_files: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> KnowledgeItem | None:
        bundle = self._load_bundle(project_id, agent)
        item = bundle.items.get(item_id)
        if item is None:
            return None
        if title is not None:
            item.title = title
        if body is not None:
            item.body = body
        if tags is not None:
            item.tags = list(tags)
        if related_files is not None:
            item.related_files = list(related_files)
        if metadata is not None:
            item.metadata = dict(metadata)
        item.updated_at = datetime.utcnow().isoformat()
        self._save_bundle(bundle)
        return item

    def delete(self, project_id: str, agent: str, item_id: str) -> bool:
        bundle = self._load_bundle(project_id, agent)
        if item_id not in bundle.items:
            return False
        del bundle.items[item_id]
        self._save_bundle(bundle)
        return True

    # ---- cross-agent queries --------------------------------------------

    def search(
        self,
        project_id: str,
        *,
        text: str | None = None,
        kind: str | None = None,
        agent: str | None = None,
        tag: str | None = None,
    ) -> list[KnowledgeItem]:
        """Search across all agents in a project."""
        agents = [agent] if agent else list(AGENT_OWNERSHIP.keys())
        out: list[KnowledgeItem] = []
        needle = text.lower() if text else None
        for a in agents:
            for item in self.list(project_id, a, kind=kind):
                if tag and tag not in item.tags:
                    continue
                if needle:
                    hay = f"{item.title}\n{item.body}\n{' '.join(item.tags)}".lower()
                    if needle not in hay:
                        continue
                out.append(item)
        return out

    def ownership_map(self, project_id: str) -> dict[str, list[str]]:
        """Return {agent: [kind, ...]} plus item counts for the project."""
        out: dict[str, list[str]] = {}
        for agent, kinds in AGENT_OWNERSHIP.items():
            bundle = self._load_bundle(project_id, agent)
            header = f"kinds={list(kinds)} items={len(bundle.items)}"
            out[agent] = [header]
        return out


# Per-project registry so server.py can look up the right store.
class AgentKnowledgeRegistry:
    def __init__(self) -> None:
        self._by_project: dict[str, AgentKnowledgeStore] = {}

    def get_or_create(self, project_id: str, workspace_root: Path) -> AgentKnowledgeStore:
        if project_id not in self._by_project:
            self._by_project[project_id] = AgentKnowledgeStore(workspace_root)
        return self._by_project[project_id]

    def get(self, project_id: str) -> AgentKnowledgeStore | None:
        return self._by_project.get(project_id)
