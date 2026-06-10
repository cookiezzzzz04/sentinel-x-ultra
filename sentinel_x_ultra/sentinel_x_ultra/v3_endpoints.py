"""V3 additions: FastAPI endpoints for Project Workspace, Terminal, and Agent Knowledge.

Importing and calling :func:`register_v3_endpoints` from ``server.py`` wires the
following V3 spec features into the running app:

1. Project Workspace System — ``/Projects/<name>/{source-code, ...}`` layout.
2. Terminal Execution Workspace — sandboxed shell exec with ``AUDIT_LOG``.
3. Agent-Centric Knowledge System — knowledge lives on agents.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .workspace import (
    FileCategory,
    ProjectWorkspaceManager,
    WORKSPACE_DIRS,
    get_workspace_manager,
)
from .terminal import DEFAULT_ALLOWLIST, TerminalRegistry
from .agent_knowledge import (
    AGENT_OWNERSHIP,
    AgentKnowledgeRegistry,
    KnowledgeKind,
)
from .methodology import (
    AWESOME_BBB_TOOLS_CATEGORIES,
    BLANK_MD_TEMPLATE_SECTIONS,
    BURP_SUITE_PHASES,
    MethodologyReference,
    MethodologyReferenceEngine,
    ReferenceKind,
    get_methodology_engine,
)
from .validation import (
    CandidateFinding,
    EvidenceItem,
    FindingStatus,
    FindingValidationPipeline,
    PipelineStage,
    ValidationOutcome,
    get_validation_pipeline,
)
from .report_template import (
    BlankReportRenderer,
    ReportFinding,
    finding_to_report_finding,
)
from .coverage import (
    CoverageEngine,
    CoverageReport,
    DIMENSIONS,
    DIMENSION_LABELS,
    get_coverage_engine,
)
from .agent_models import (
    AgentModelAssignment,
    AgentModelRegistry,
    DEFAULT_AGENT_MODELS,
)
from .research_memory import (
    HashEmbedder,
    ResearchMemoryEngine,
    get_research_memory,
)
from .ollama_embedder import OllamaEmbedder


# ---- Request / response models ------------------------------------------------

class WorkspaceInitRequest(BaseModel):
    name: str | None = None


class WorkspaceUploadRequest(BaseModel):
    source_path: str
    category: str | None = None
    tags: list[str] | None = None
    agent_owners: list[str] | None = None


class TerminalExecRequest(BaseModel):
    command: str
    agent: str = "system"
    reason: str = ""
    timeout_s: int | None = None
    cwd: str | None = None
    allow_any: bool = False


class AgentKnowledgeAddRequest(BaseModel):
    agent: str
    kind: str
    title: str
    body: str = ""
    tags: list[str] | None = None
    related_files: list[str] | None = None
    metadata: dict | None = None


class AgentKnowledgeUpdateRequest(BaseModel):
    title: str | None = None
    body: str | None = None
    tags: list[str] | None = None
    related_files: list[str] | None = None
    metadata: dict | None = None


# ---- Request models for Methodology, Validation, Reports -----------------

class EvidenceItemModel(BaseModel):
    source: str
    location: str = ""
    confidence: str = "medium"
    context: str = ""
    data: dict | None = None


class CandidateFindingModel(BaseModel):
    finding_id: str = ""
    title: str
    description: str
    severity: str = "Medium"
    confidence: str = "Medium"
    evidence: list[EvidenceItemModel] | None = None
    affected_components: list[str] | None = None
    source_agent: str = ""
    related_finding_ids: list[str] | None = None

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        if self.evidence is None:
            self.evidence = []
        if self.affected_components is None:
            self.affected_components = []
        if self.related_finding_ids is None:
            self.related_finding_ids = []


class ReferenceAddRequest(BaseModel):
    title: str
    kind: str
    url: str
    description: str = ""
    sections: list[str] | None = None
    tags: list[str] | None = None


class ReportRenderRequest(BaseModel):
    view: str = "full"  # full | executive | developer


class CoverageComputeRequest(BaseModel):
    workspace_files: list[str] | None = None
    business_rules: int = 0
    api_endpoints: int = 0
    graph_entities: int = 0
    graph_relationships: int = 0
    findings_count: int = 0
    baseline: dict[str, int] | None = None


class CoverageBaselineRequest(BaseModel):
    baseline: dict[str, int]


class AgentModelAssignRequest(BaseModel):
    agent: str
    model: str
    model_id: str = ""
    purpose: str | None = None
    notes: str = ""


class ResearchIndexRequest(BaseModel):
    path: str
    content: str | None = None
    component: str = ""
    tags: list[str] | None = None


class ResearchSearchRequest(BaseModel):
    query: str
    top_k: int = 10
    kind: str | None = None
    tag: str | None = None
    risk: str | None = None


# ---- Registration -------------------------------------------------------------

def register_v3_endpoints(
    app: FastAPI,
    settings: Any,
    memory_engine: Any,
) -> dict[str, Any]:
    """Attach V3 endpoints to ``app``. Returns the manager registries."""

    workspace_manager: ProjectWorkspaceManager = get_workspace_manager(
        settings.storage.base_path / "Projects"
    )
    terminal_registry = TerminalRegistry()
    agent_knowledge_registry = AgentKnowledgeRegistry()

    def _ensure_workspace(project_id: str) -> Path:
        project = memory_engine.load_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        ws = workspace_manager.get_workspace(project_id)
        if ws is None:
            ws = workspace_manager.create_workspace(project_id, project.name)
        return ws.root

    # ---- Project Workspace System ----

    @app.post("/api/projects/{project_id}/workspace/init")
    async def init_project_workspace(
        project_id: str, req: WorkspaceInitRequest | None = None
    ):
        project = memory_engine.load_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        folder_name = (req.name if req and req.name else project.name)
        ws = workspace_manager.create_workspace(project_id, folder_name)
        return {"status": "ok", "workspace": ws.to_dict()}

    @app.get("/api/projects/{project_id}/workspace")
    async def get_project_workspace(project_id: str):
        project = memory_engine.load_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        ws = workspace_manager.get_workspace(project_id)
        if ws is None:
            ws = workspace_manager.create_workspace(project_id, project.name)
        return {"status": "ok", "workspace": ws.to_dict()}

    @app.post("/api/projects/{project_id}/workspace/upload")
    async def workspace_upload(project_id: str, req: WorkspaceUploadRequest):
        project = memory_engine.load_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if workspace_manager.get_workspace(project_id) is None:
            workspace_manager.create_workspace(project_id, project.name)
        cat = None
        if req.category:
            try:
                cat = FileCategory(req.category)
            except ValueError:
                cat = None
        indexed = workspace_manager.add_file(
            project_id,
            req.source_path,
            category=cat,
            tags=req.tags,
            agent_owners=req.agent_owners,
        )
        if indexed is None:
            raise HTTPException(
                status_code=400, detail="Source file not found or unreadable"
            )
        # Auto-index into the Research Memory Engine so the file is
        # immediately searchable (V3: every uploaded file is indexed).
        indexed_chunks: list = []
        try:
            from pathlib import Path as _P
            _src = _P(req.source_path)
            if _src.exists() and _src.is_file():
                # The file's copy lives at workspace_root / <dir> / basename
                ws_root = workspace_manager.get_workspace(project_id).root
                target = ws_root / indexed.relative_path
                if target.exists():
                    indexed_chunks = _research_memory.index_file(
                        project_id,
                        target,
                        component=indexed.relative_path,
                        tags=indexed.tags,
                    )
        except Exception as e:  # pragma: no cover
            logger.warning("auto_index_failed", error=str(e), file=indexed.relative_path)
        return {
            "status": "ok",
            "file": indexed.to_dict(),
            "chunks_indexed": len(indexed_chunks),
        }

    @app.get("/api/projects/{project_id}/workspace/search")
    async def workspace_search(
        project_id: str,
        category: str | None = None,
        tag: str | None = None,
        agent: str | None = None,
    ):
        project = memory_engine.load_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="Project not found")
        if workspace_manager.get_workspace(project_id) is None:
            workspace_manager.create_workspace(project_id, project.name)
        cat_enum = None
        if category:
            try:
                cat_enum = FileCategory(category)
            except ValueError:
                cat_enum = None
        results = workspace_manager.search(
            project_id, category=cat_enum, tag=tag, agent=agent
        )
        return {
            "status": "ok",
            "count": len(results),
            "files": [r.to_dict() for r in results],
        }

    # ---- Terminal Execution Workspace + AUDIT_LOG ----

    @app.post("/api/projects/{project_id}/terminal/exec")
    async def terminal_exec(project_id: str, req: TerminalExecRequest):
        ws_root = _ensure_workspace(project_id)
        kwargs: dict = {}
        if req.allow_any:
            kwargs["allow_any"] = True
        term = terminal_registry.get_or_create(project_id, ws_root, **kwargs)
        cwd = Path(req.cwd) if req.cwd else None
        result = await term.execute(
            req.command,
            agent=req.agent,
            reason=req.reason,
            timeout_s=req.timeout_s,
            cwd=cwd,
        )
        return {
            "status": "ok",
            "success": result.success,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_ms": result.duration_ms,
            "audit": result.audit.to_dict(),
        }

    @app.get("/api/projects/{project_id}/terminal/audit")
    async def terminal_audit(project_id: str, limit: int | None = None):
        _ensure_workspace(project_id)
        term = terminal_registry.get(project_id)
        if term is None:
            return {"status": "ok", "count": 0, "entries": [], "log_path": None}
        entries = term.get_audit_log(limit=limit)
        return {
            "status": "ok",
            "count": len(entries),
            "entries": [e.to_dict() for e in entries],
            "log_path": str(term.get_audit_log_path()),
        }

    @app.get("/api/projects/{project_id}/terminal/allowlist")
    async def terminal_allowlist(project_id: str):
        _ensure_workspace(project_id)
        term = terminal_registry.get(project_id)
        if term is None:
            return {"status": "ok", "allowlist": list(DEFAULT_ALLOWLIST), "allow_any": False}
        return {
            "status": "ok",
            "allowlist": list(term.allowlist),
            "allow_any": term.allow_any,
        }

    # ---- Agent-Centric Knowledge System ----

    @app.get("/api/projects/{project_id}/agents/knowledge/ownership")
    async def knowledge_ownership(project_id: str):
        _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(
            project_id, workspace_manager.get_workspace(project_id).root
        )
        return {
            "status": "ok",
            "ownership": AGENT_OWNERSHIP,
            "project": store.ownership_map(project_id),
        }

    @app.post("/api/projects/{project_id}/agents/knowledge")
    async def add_agent_knowledge(project_id: str, req: AgentKnowledgeAddRequest):
        ws_root = _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(project_id, ws_root)
        if not store.validate_ownership(req.agent, req.kind):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Agent '{req.agent}' does not own kind '{req.kind}'. "
                    f"Allowed: {list(store.kinds_for(req.agent))}"
                ),
            )
        item = store.add(
            project_id,
            req.agent,
            req.kind,
            req.title,
            req.body,
            tags=req.tags,
            related_files=req.related_files,
            metadata=req.metadata,
        )
        return {"status": "ok", "item": item.to_dict()}

    @app.get("/api/projects/{project_id}/agents/{agent}/knowledge")
    async def list_agent_knowledge(
        project_id: str,
        agent: str,
        kind: str | None = None,
        tag: str | None = None,
    ):
        ws_root = _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(project_id, ws_root)
        items = store.list(project_id, agent, kind=kind, tag=tag)
        return {
            "status": "ok",
            "agent": agent,
            "count": len(items),
            "items": [i.to_dict() for i in items],
        }

    @app.get("/api/projects/{project_id}/agents/{agent}/knowledge/{item_id}")
    async def get_agent_knowledge(project_id: str, agent: str, item_id: str):
        ws_root = _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(project_id, ws_root)
        item = store.get(project_id, agent, item_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Knowledge item not found")
        return {"status": "ok", "item": item.to_dict()}

    @app.patch("/api/projects/{project_id}/agents/{agent}/knowledge/{item_id}")
    async def update_agent_knowledge(
        project_id: str, agent: str, item_id: str, req: AgentKnowledgeUpdateRequest
    ):
        ws_root = _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(project_id, ws_root)
        item = store.update(
            project_id,
            agent,
            item_id,
            title=req.title,
            body=req.body,
            tags=req.tags,
            related_files=req.related_files,
            metadata=req.metadata,
        )
        if item is None:
            raise HTTPException(status_code=404, detail="Knowledge item not found")
        return {"status": "ok", "item": item.to_dict()}

    @app.delete("/api/projects/{project_id}/agents/{agent}/knowledge/{item_id}")
    async def delete_agent_knowledge(project_id: str, agent: str, item_id: str):
        ws_root = _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(project_id, ws_root)
        ok = store.delete(project_id, agent, item_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Knowledge item not found")
        return {"status": "ok"}

    @app.get("/api/projects/{project_id}/agents/knowledge/search")
    async def search_agent_knowledge(
        project_id: str,
        q: str | None = None,
        agent: str | None = None,
        kind: str | None = None,
        tag: str | None = None,
    ):
        ws_root = _ensure_workspace(project_id)
        store = agent_knowledge_registry.get_or_create(project_id, ws_root)
        items = store.search(project_id, text=q, agent=agent, kind=kind, tag=tag)
        return {
            "status": "ok",
            "count": len(items),
            "items": [i.to_dict() for i in items],
        }

    # ---- Methodology Reference Engine ----
    _methodology = get_methodology_engine(
        settings.storage.base_path / "methodology.json"
    )
    _pipeline = get_validation_pipeline()

    @app.get("/api/methodology/references")
    async def list_references(kind: str | None = None, tag: str | None = None):
        refs = _methodology.list_references(kind=kind, tag=tag)
        return {
            "status": "ok",
            "count": len(refs),
            "references": [r.to_dict() for r in refs],
        }

    @app.get("/api/methodology/references/{reference_id}")
    async def get_reference(reference_id: str):
        ref = _methodology.get_reference(reference_id)
        if ref is None:
            raise HTTPException(status_code=404, detail="Reference not found")
        return {"status": "ok", "reference": ref.to_dict()}

    @app.post("/api/methodology/references")
    async def add_reference(req: ReferenceAddRequest):
        ref = _methodology.add_reference(
            req.title, req.kind, req.url,
            description=req.description,
            sections=req.sections,
            tags=req.tags,
        )
        return {"status": "ok", "reference": ref.to_dict()}

    @app.get("/api/methodology/categories")
    async def methodology_categories():
        return {
            "status": "ok",
            "categories": _methodology.categories(),
            "burp_suite_phases": list(BURP_SUITE_PHASES),
            "report_template_sections": list(BLANK_MD_TEMPLATE_SECTIONS),
            "tool_categories": list(AWESOME_BBB_TOOLS_CATEGORIES),
        }

    @app.get("/api/methodology/tools")
    async def methodology_tools(category: str | None = None):
        tools = (
            _methodology.tools_by_category(category)
            if category else _methodology.all_tools()
        )
        return {"status": "ok", "count": len(tools), "tools": tools}

    # ---- Finding Validation Pipeline ----

    @app.post("/api/findings/validate")
    async def validate_finding(req: CandidateFindingModel):
        evidence = [EvidenceItem(**e.model_dump()) for e in (req.evidence or [])]
        finding = CandidateFinding(
            finding_id=req.finding_id or "",
            title=req.title,
            description=req.description,
            severity=req.severity,
            confidence=req.confidence,
            evidence=evidence,
            affected_components=req.affected_components or [],
            source_agent=req.source_agent,
            related_finding_ids=req.related_finding_ids or [],
        )
        outcome = _pipeline.submit(finding)
        return {"status": "ok", "outcome": outcome.to_dict()}

    @app.get("/api/findings/review-queue")
    async def review_queue():
        items = _pipeline.get_review_queue()
        return {"status": "ok", "count": len(items), "items": [o.to_dict() for o in items]}

    @app.get("/api/findings/promoted")
    async def promoted_findings():
        items = _pipeline.get_promoted()
        return {"status": "ok", "count": len(items), "items": [o.to_dict() for o in items]}

    @app.post("/api/findings/{finding_id}/retry")
    async def retry_finding(finding_id: str):
        outcome = _pipeline.retry(finding_id)
        if outcome is None:
            raise HTTPException(status_code=404, detail="Finding not in review queue")
        return {"status": "ok", "outcome": outcome.to_dict()}

    # ---- Report Intelligence (Blank.md) ----

    @app.get("/api/reports/templates")
    async def report_templates():
        return {
            "status": "ok",
            "sections": list(BLANK_MD_TEMPLATE_SECTIONS),
            "pipeline_order": [s.value for s in PipelineStage],
        }

    @app.post("/api/reports/render")
    async def render_report(req: ReportRenderRequest):
        renderer = BlankReportRenderer(project_name="SENTINEL-X ULTRA Project")
        findings: list[ReportFinding] = []
        for fid, outcome in _pipeline.promoted.items():
            cf = _pipeline.promoted[fid][0]
            if cf.finding_id == outcome.finding_id:
                findings.append(finding_to_report_finding(cf, outcome))
        view = (req.view or "full").lower()
        if view == "executive":
            md = renderer.render_executive(findings)
        elif view == "developer":
            md = renderer.render_developer(findings)
        else:
            md = renderer.render_report(findings)
        return {"status": "ok", "view": view, "markdown": md, "findings": len(findings)}

    # ---- Coverage Tracking Engine ----
    _coverage = get_coverage_engine(settings.storage.base_path)

    @app.get("/api/coverage/dimensions")
    async def coverage_dimensions():
        return {
            "status": "ok",
            "dimensions": list(DIMENSIONS),
            "labels": DIMENSION_LABELS,
        }

    @app.get("/api/projects/{project_id}/coverage")
    async def get_project_coverage(project_id: str):
        report = _coverage.get(project_id)
        if report is None:
            return {
                "status": "ok",
                "project_id": project_id,
                "metrics": {},
                "details": {},
                "computed_at": None,
                "overall": 0.0,
                "note": "no coverage report yet; POST /api/projects/{id}/coverage/compute to compute one",
            }
        return {
            "status": "ok",
            "project_id": project_id,
            "metrics": report.metrics,
            "details": report.details,
            "computed_at": report.computed_at,
            "overall": report.overall(),
        }

    @app.post("/api/projects/{project_id}/coverage/compute")
    async def compute_project_coverage(
        project_id: str, req: CoverageComputeRequest | None = None
    ):
        # Try to augment with the live workspace if one exists.
        ws = workspace_manager.get_workspace(project_id)
        workspace_files: list[str] = list(req.workspace_files or []) if req else []
        if ws is not None:
            for f in ws.files.values():
                workspace_files.append(f.relative_path)
        report = _coverage.compute(
            project_id,
            workspace_files=workspace_files,
            findings=[{"title": f.title, "description": f.description}
                      for f in (_pipeline.promoted.get(pid, (None,))[0]
                                for pid in _pipeline.promoted)
                      if f is not None],
            business_rules=[None] * (req.business_rules if req else 0),
            api_endpoints=[None] * (req.api_endpoints if req else 0),
            graph_entities=[None] * (req.graph_entities if req else 0),
            graph_relationships=[None] * (req.graph_relationships if req else 0),
            baseline=(req.baseline if req else None),
        )
        return {"status": "ok", "report": report.to_dict(), "overall": report.overall()}

    @app.post("/api/projects/{project_id}/coverage/baseline")
    async def set_coverage_baseline(project_id: str, req: CoverageBaselineRequest):
        _coverage.set_baseline(project_id, req.baseline)
        return {"status": "ok", "baseline": req.baseline}

    # ---- Agent Model Registry (persistent JSON) ----
    _agent_model_registry = AgentModelRegistry(
        settings.storage.base_path / "agent_models.json"
    )

    @app.get("/api/agent-models")
    async def list_agent_models():
        return {
            "status": "ok",
            "file": str(_agent_model_registry.file_path),
            "agents": [a.to_dict() for a in _agent_model_registry.list()],
        }

    @app.get("/api/agent-models/{agent}")
    async def get_agent_model(agent: str):
        a = _agent_model_registry.get(agent)
        if a is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"status": "ok", "assignment": a.to_dict()}

    @app.put("/api/agent-models")
    async def assign_agent_model(req: AgentModelAssignRequest):
        a = _agent_model_registry.assign(req.agent, req.model, req.purpose)
        return {"status": "ok", "assignment": a.to_dict()}

    @app.post("/api/agent-models/reset")
    async def reset_agent_models():
        _agent_model_registry.reset()
        return {"status": "ok", "agents": [a.to_dict() for a in _agent_model_registry.list()]}

    # ---- Report injection: every render includes coverage if present ----
    @app.get("/api/projects/{project_id}/reports/coverage")
    async def report_with_coverage(project_id: str, view: str = "full"):
        """Render a Blank.md report with the project's coverage footer."""
        renderer = BlankReportRenderer(project_name="SENTINEL-X ULTRA Project")
        findings: list[ReportFinding] = []
        for fid in list(_pipeline.promoted.keys()):
            cf, outcome = _pipeline.promoted[fid]
            findings.append(finding_to_report_finding(cf, outcome))
        cov = _coverage.get(project_id)
        if view == "executive":
            md = renderer.render_executive(findings)
        elif view == "developer":
            md = renderer.render_developer(findings)
        else:
            md = renderer.render_report(
                findings,
                coverage=(
                    {d: cov.percent(d) for d in DIMENSIONS} if cov else None
                ),
                overall_coverage=(cov.overall() if cov else None),
            )
        return {
            "status": "ok",
            "view": view,
            "markdown": md,
            "findings": len(findings),
            "coverage": cov.to_dict() if cov else None,
        }

    # ---- Research Memory Engine ----
    # Try to use a real local Ollama embedder; fall back to the
    # dependency-free HashEmbedder if Ollama isn't running.
    _ollama = OllamaEmbedder(model="nomic-embed-text", base_url="http://localhost:11434")
    _research_memory = get_research_memory(
        base_path=settings.storage.base_path,
        embedder=_ollama,
    )

    @app.get("/api/research/embedder")
    async def research_embedder_info():
        return {
            "status": "ok",
            "embedder": _research_memory.embedder.__class__.__name__,
            "dim": _research_memory.embedder.dim,
            "health": (
                _ollama.healthcheck()
                if isinstance(_research_memory.embedder, OllamaEmbedder)
                else {"ok": True, "model": "hash", "dim": _research_memory.embedder.dim}
            ),
        }

    @app.get("/api/projects/{project_id}/research/stats")
    async def research_stats(project_id: str):
        return {"status": "ok", "stats": _research_memory.stats(project_id).to_dict()}

    @app.post("/api/projects/{project_id}/research/index")
    async def research_index(project_id: str, req: ResearchIndexRequest):
        chunks = _research_memory.index_file(
            project_id,
            req.path,
            content=req.content,
            component=req.component,
            tags=req.tags,
        )
        return {"status": "ok", "chunks_indexed": len(chunks)}

    @app.post("/api/projects/{project_id}/research/search")
    async def research_search(project_id: str, req: ResearchSearchRequest):
        results = _research_memory.search(
            project_id,
            req.query,
            top_k=req.top_k,
            kind=req.kind,
            tag=req.tag,
            risk=req.risk,
        )
        return {
            "status": "ok",
            "count": len(results),
            "results": [
                {
                    "chunk_id": c.chunk_id,
                    "source_file": c.source_file,
                    "file_kind": c.file_kind,
                    "chunk_type": c.chunk_type,
                    "line_start": c.line_start,
                    "line_end": c.line_end,
                    "tags": c.tags,
                    "risk_tags": c.risk_tags,
                    "component_refs": c.component_refs,
                    "text": c.text[:500],
                }
                for c in results
            ],
        }

    return {
        "workspace_manager": workspace_manager,
        "terminal_registry": terminal_registry,
        "agent_knowledge_registry": agent_knowledge_registry,
        "methodology_engine": _methodology,
        "validation_pipeline": _pipeline,
        "coverage_engine": _coverage,
        "agent_model_registry": _agent_model_registry,
        "research_memory": _research_memory,
    }
