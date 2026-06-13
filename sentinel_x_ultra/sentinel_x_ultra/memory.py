"""Memory Engine - Project state management and persistence."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ScopeGraph:
    """Scope definition and management."""
    authorized_assets: list[str] = field(default_factory=list)
    excluded_assets: list[str] = field(default_factory=list)
    safe_harbor_terms: str = ""
    reward_categories: list[str] = field(default_factory=list)
    severity_definitions: dict[str, Any] = field(default_factory=dict)
    rules_of_engagement: list[str] = field(default_factory=list)
    program_name: str = ""
    last_updated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized_assets": self.authorized_assets,
            "excluded_assets": self.excluded_assets,
            "safe_harbor_terms": self.safe_harbor_terms,
            "reward_categories": self.reward_categories,
            "severity_definitions": self.severity_definitions,
            "rules_of_engagement": self.rules_of_engagement,
            "program_name": self.program_name,
            "last_updated": self.last_updated,
        }


@dataclass
class Finding:
    """Security finding."""
    id: str
    title: str
    severity: str  # Critical | High | Medium | Low | Informational
    confidence: str  # Verified | High | Medium | Low | Informational
    affected_components: list[str]
    description: str
    evidence: list[dict[str, Any]]
    attack_scenario: str
    business_impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    source_agent: str = ""
    debate_verdict: str = "PENDING"
    created_at: str = ""


@dataclass
class AnomalyRecord:
    """Anomaly that needs human review."""
    id: str
    anomaly_type: str
    component: str
    description: str
    confidence: str
    created_at: str


@dataclass
class ProjectMemory:
    """Complete project memory state."""
    project_id: str
    name: str
    scope: ScopeGraph
    assets: list[dict[str, Any]] = field(default_factory=list)
    knowledge_graph: dict[str, Any] = field(default_factory=dict)
    permission_graph: dict[str, Any] = field(default_factory=dict)
    business_rules: list[dict[str, Any]] = field(default_factory=list)
    journeys: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    debate_transcripts: list[dict[str, Any]] = field(default_factory=list)
    anomaly_register: list[AnomalyRecord] = field(default_factory=list)
    technology_stack: dict[str, Any] = field(default_factory=dict)
    investigation_log: list[dict[str, Any]] = field(default_factory=list)
    user_notes: list[str] = field(default_factory=list)
    report_history: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        # Manual serialization to handle nested dataclasses and Enums properly
        return {
            "project_id": self.project_id,
            "name": self.name,
            "scope": self.scope.to_dict() if isinstance(self.scope, ScopeGraph) else self.scope,
            "assets": self.assets,
            "knowledge_graph": self.knowledge_graph,
            "permission_graph": self.permission_graph,
            "business_rules": self.business_rules,
            "journeys": self.journeys,
            "findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.findings],
            "debate_transcripts": self.debate_transcripts,
            "anomaly_register": [a.to_dict() if hasattr(a, 'to_dict') else a for a in self.anomaly_register],
            "technology_stack": self.technology_stack,
            "investigation_log": self.investigation_log,
            "user_notes": self.user_notes,
            "report_history": self.report_history,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectMemory":
        if "scope" in data and isinstance(data["scope"], dict):
            data["scope"] = ScopeGraph(**data["scope"])
        if "findings" in data:
            data["findings"] = [Finding(**f) if isinstance(f, dict) else f for f in data["findings"]]
        if "anomaly_register" in data:
            data["anomaly_register"] = [AnomalyRecord(**a) if isinstance(a, dict) else a for a in data["anomaly_register"]]
        return cls(**data)


class MemoryEngine:
    """Manages project memory and persistence."""

    def __init__(self, storage_path: Path | None = None):
        self.storage_path = storage_path or Path.home() / ".sentinel-x" / "projects"
        self._current_project: ProjectMemory | None = None
        self._ensure_storage_dir()

    def _ensure_storage_dir(self):
        """Ensure storage directory exists."""
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def create_project(self, name: str, scope: ScopeGraph | None = None) -> ProjectMemory:
        """Create a new project."""
        project_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        project = ProjectMemory(
            project_id=project_id,
            name=name,
            scope=scope or ScopeGraph(),
            created_at=now,
            updated_at=now,
        )

        self._current_project = project
        logger.info("project_created", project_id=project_id, name=name)
        return project

    def load_project(self, project_id: str) -> ProjectMemory | None:
        """Load a project from storage."""
        project_file = self.storage_path / f"{project_id}.json"

        if not project_file.exists():
            logger.warning("project_not_found", project_id=project_id)
            return None

        try:
            with open(project_file) as f:
                data = json.load(f)
            self._current_project = ProjectMemory.from_dict(data)
            logger.info("project_loaded", project_id=project_id)
            return self._current_project
        except Exception as e:
            logger.error("project_load_error", project_id=project_id, error=str(e))
            return None

    def save_project(self, project: ProjectMemory | None = None):
        """Save project to storage."""
        if project is None:
            project = self._current_project

        if project is None:
            raise ValueError("No project to save")

        project.updated_at = datetime.utcnow().isoformat()

        project_file = self.storage_path / f"{project.project_id}.json"
        with open(project_file, "w") as f:
            json.dump(project.to_dict(), f, indent=2)

        logger.info("project_saved", project_id=project.project_id)

    def get_current_project(self) -> ProjectMemory | None:
        """Get the current active project."""
        return self._current_project

    def set_current_project(self, project: ProjectMemory):
        """Set the current active project."""
        self._current_project = project

    def list_projects(self) -> list[dict[str, Any]]:
        """List all saved projects."""
        projects = []
        for project_file in self.storage_path.glob("*.json"):
            try:
                with open(project_file) as f:
                    data = json.load(f)
                projects.append({
                    "project_id": data.get("project_id"),
                    "name": data.get("name"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                })
            except Exception as e:
                logger.error("project_list_error", file=str(project_file), error=str(e))
        return projects

    def add_finding(self, finding: Finding):
        """Add a finding to the current project."""
        if self._current_project is None:
            raise ValueError("No active project")

        finding.created_at = datetime.utcnow().isoformat()
        self._current_project.findings.append(finding)
        self.save_project()
        logger.info("finding_added", finding_id=finding.id, title=finding.title)

    def add_anomaly(self, anomaly: AnomalyRecord):
        """Add an anomaly to the current project."""
        if self._current_project is None:
            raise ValueError("No active project")

        anomaly.created_at = datetime.utcnow().isoformat()
        self._current_project.anomaly_register.append(anomaly)
        self.save_project()
        logger.info("anomaly_added", anomaly_id=anomaly.id)

    def update_scope(self, scope: ScopeGraph):
        """Update the scope of the current project."""
        if self._current_project is None:
            raise ValueError("No active project")

        self._current_project.scope = scope
        scope.last_updated = datetime.utcnow().isoformat()
        self.save_project()
        logger.info("scope_updated")

    def add_investigation_log(self, entry: dict[str, Any]):
        """Add an entry to the investigation log."""
        if self._current_project is None:
            raise ValueError("No active project")

        entry["timestamp"] = datetime.utcnow().isoformat()
        self._current_project.investigation_log.append(entry)
        self.save_project()

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """Get all findings of a specific severity."""
        if self._current_project is None:
            return []
        return [f for f in self._current_project.findings if f.severity == severity]

    def get_findings_by_confidence(self, confidence: str) -> list[Finding]:
        """Get all findings of a specific confidence level."""
        if self._current_project is None:
            return []
        return [f for f in self._current_project.findings if f.confidence == confidence]
