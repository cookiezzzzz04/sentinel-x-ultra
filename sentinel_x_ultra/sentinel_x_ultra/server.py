"""FastAPI Web Server - Main application entry point."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx

from .config import Settings, load_settings
from .memory import MemoryEngine, ProjectMemory, ScopeGraph
from .providers import (
    ProviderRegistry,
    MultiProviderRouter,
    ProviderConfig,
    LLMMessage,
    MessageRole,
    ProviderType,
)
from .agents import (
    MessageBus,
    AgentRegistry,
    BaseAgent,
    AgentType,
    TaskPayload,
    AgentMessage,
    MessageType,
)

# Phase 2 imports - Engines and Analyzers
from .engines import (
    KnowledgeGraphEngine,
    PermissionGraphEngine,
    BusinessRuleEngine,
)
from .analyzers import (
    CodeAnalyzer,
    WebAnalyzer,
)
from .rag import RAGEngine

# Phase 3 imports - Agents
from .agents.phase3 import (
    ReconAgent,
    CodeReviewAgent,
    ThreatModelingAgent,
    DependencyAgent,
    DebateAgent,
)

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ]
)
logger = structlog.get_logger()


# Global instances
settings = load_settings()
memory_engine = MemoryEngine(settings.storage.base_path / settings.storage.projects_dir)
message_bus = MessageBus()
provider_registry = ProviderRegistry()
llm_router: MultiProviderRouter | None = None
agent_registry: AgentRegistry | None = None
provider_key_map: dict[str, dict] = {}  # Store API keys in memory

# Phase 2 - Engines and Analyzers
knowledge_graphs: dict[str, KnowledgeGraphEngine] = {}  # project_id -> engine
permission_graphs: dict[str, PermissionGraphEngine] = {}  # project_id -> engine
business_rule_engines: dict[str, BusinessRuleEngine] = {}  # project_id -> engine
code_analyzers: dict[str, CodeAnalyzer] = {}  # project_id -> analyzer
web_analyzers: dict[str, WebAnalyzer] = {}  # project_id -> analyzer
rag_engines: dict[str, RAGEngine] = {}  # project_id -> engine

# Phase 3 - Agents
phase3_agents: dict[str, dict[str, Any]] = {}  # project_id -> {agent_type: agent_instance}

# Path to frontend dist (relative to this file)
FRONTEND_DIST = Path(__file__).parent.parent / "frontend/dist"


class CreateProjectRequest(BaseModel):
    name: str
    scope: ScopeGraph | None = None


class SendMessageRequest(BaseModel):
    project_id: str
    message: str


class ApiKeyRequest(BaseModel):
    provider: str
    api_key: str
    base_url: str | None = None


class WebSocketMessage(BaseModel):
    type: str
    data: dict


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global llm_router, agent_registry

    logger.info("starting_sentinel_x", version="0.1.0", phase="phase-2")

    # Initialize message bus
    try:
        await message_bus.start()
        logger.info("message_bus_started")
    except Exception as e:
        logger.error("message_bus_init_failed", error=str(e), exc_info=True)

    # Initialize LLM router with error handling
    try:
        provider_config = settings.get_provider_config()
        logger.info("provider_config_loaded", provider=provider_config.provider.value)
        llm_router = MultiProviderRouter(provider_registry, provider_config)
        await llm_router.initialize()
        logger.info("llm_router_initialized")
    except Exception as e:
        logger.error("llm_router_init_failed", error=str(e), exc_info=True)
        # Continue with llm_router = None, endpoints will handle it

    # Initialize agent registry (safely)
    try:
        agent_registry = AgentRegistry(message_bus, llm_router)
        logger.info("agent_registry_initialized")
    except Exception as e:
        logger.error("agent_registry_init_failed", error=str(e), exc_info=True)

    logger.info("sentinel_x_ready", port=settings.server.port, phase="phase-3-complete")

    yield

    # Cleanup
    if agent_registry:
        try:
            await agent_registry.stop_all()
        except Exception as e:
            logger.error("agent_registry_stop_failed", error=str(e))
    await message_bus.stop()
    if llm_router:
        try:
            await llm_router.close()
        except Exception as e:
            logger.error("llm_router_close_failed", error=str(e))
    
    # Cleanup Phase 2 engines
    knowledge_graphs.clear()
    permission_graphs.clear()
    business_rule_engines.clear()
    code_analyzers.clear()
    web_analyzers.clear()
    rag_engines.clear()
    
    logger.info("sentinel_x_stopped")


# Create FastAPI app
app = FastAPI(
    title="SENTINEL-X ULTRA",
    description="Autonomous Security Analysis Intelligence Framework",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Serve React UI
@app.get("/")
async def root():
    """Serve the React UI."""
    return FileResponse(FRONTEND_DIST / "index.html")


# Serve static assets from built frontend
app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="static")


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "version": "0.1.0",
        "providers": list(ProviderType),
    }


# Project Management
@app.post("/api/projects")
async def create_project(req: CreateProjectRequest):
    """Create a new project."""
    project = memory_engine.create_project(req.name, req.scope)
    memory_engine.save_project(project)
    return {"project_id": project.project_id, "name": project.name}


@app.get("/api/projects")
async def list_projects():
    """List all projects."""
    projects = memory_engine.list_projects()
    return {"projects": projects}


@app.get("/api/projects/{project_id}")
async def get_project(project_id: str):
    """Get a project by ID."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.to_dict()


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str):
    """Delete a project."""
    project_dir = memory_engine.storage.projects_dir / project_id
    if project_dir.exists():
        import shutil
        shutil.rmtree(project_dir)
        return {"status": "ok", "message": f"Project {project_id} deleted"}
    raise HTTPException(status_code=404, detail="Project not found")


# Scope Management
@app.post("/api/projects/{project_id}/scope")
async def update_scope(project_id: str, scope: ScopeGraph):
    """Update project scope."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    memory_engine.set_current_project(project)
    memory_engine.update_scope(scope)
    return {"status": "ok"}


# LLM Configuration
@app.get("/api/config/models")
async def get_model_config():
    """Get available model configuration."""
    return {
        "providers": [p.value for p in ProviderType],
        "current_provider": settings.default_provider.value,
        "models": {
            "reasoning": settings.models.reasoning,
            "code": settings.models.code,
            "embedding": settings.models.embedding,
            "report": settings.models.report,
        },
    }


@app.post("/api/config/save-key")
async def save_api_key(req: ApiKeyRequest):
    """Save API key for a provider."""
    # Store in memory for now - in production you'd want encrypted file storage
    provider_key_map[req.provider] = {"api_key": req.api_key, "base_url": req.base_url}
    return {"status": "ok", "provider": req.provider}


class TestProviderRequest(BaseModel):
    api_key: str | None = None
    model: str | None = None


@app.post("/api/config/test")
async def test_provider(provider: ProviderType, base_url: str, req: TestProviderRequest):
    """Test a provider connection."""
    # Use provided key or check stored keys
    test_key = req.api_key
    if not test_key and provider.value in provider_key_map:
        test_key = provider_key_map[provider.value].get("api_key")
    
    # Get base_url from stored config if not provided
    test_base_url = base_url
    if not test_base_url and provider.value in provider_key_map:
        test_base_url = provider_key_map[provider.value].get("base_url")

    # Validate base_url is provided
    if not test_base_url or test_base_url.strip() == "":
        return {"status": "error", "error": "Base URL is required. Please enter a valid API endpoint URL (e.g., https://api.groq.com for Groq)."}
    
    # Normalize base_url - remove /openai/v1 or /v1 suffixes as providers add these
    test_base_url = test_base_url.rstrip('/')
    # Check longer suffix first to avoid incorrectly stripping /v1 from /openai/v1
    if test_base_url.endswith('/openai/v1'):
        test_base_url = test_base_url[:-11]
    elif test_base_url.endswith('/v1'):
        test_base_url = test_base_url[:-3]

    # Validate the URL looks reasonable (has scheme and host)
    if not test_base_url.startswith('http://') and not test_base_url.startswith('https://'):
        return {"status": "error", "error": "Invalid URL format. Base URL must start with http:// or https://."}
    
    if 'localhost' not in test_base_url and '.' not in test_base_url:
        return {"status": "error", "error": "Invalid URL. Expected format: https://api.provider.com or http://localhost:port"}

    config = ProviderConfig(provider=provider, base_url=test_base_url, api_key=test_key)
    provider_obj = ProviderRegistry.create_from_config(config)
    
    # If no model specified, use provider-specific defaults
    test_model = req.model
    if not test_model or test_model.strip() == "":
        default_models = {
            ProviderType.ANTHROPIC: "claude-3-5-sonnet-20241022",
            ProviderType.OPENAI: "gpt-4o",
            ProviderType.GROQ: "llama-3.1-8b-instant",
            ProviderType.OPENROUTER: "meta-llama/llama-3.1-8b-instant",
            ProviderType.OPENCODE: "auto",
            ProviderType.OLLAMA: "llama3.1",
            ProviderType.LMSTUDIO: "llama3.1",
            ProviderType.VLLM: "llama3.1",
            ProviderType.GEMINI: "gemini-1.5-flash",
            ProviderType.MISTRAL: "mistral-small-latest",
            ProviderType.LOCAL: "auto",
        }
        test_model = default_models.get(provider, "auto")
    
    if not test_key:
        return {"status": "error", "error": "API key is required. Please enter your API key."}
    
    try:
        messages = [LLMMessage(role=MessageRole.USER, content="Say 'OK' if you can hear me.")]
        response = await provider_obj.complete(messages, test_model, max_tokens=10)
        return {"status": "ok", "response": response.content[:100], "latency_ms": response.latency_ms, "model": test_model}
    except httpx.HTTPStatusError as e:
        error_detail = e.response.text
        if e.response.status_code == 401:
            return {"status": "error", "error": f"Unauthorized (401) - Invalid API key or insufficient permissions. Please check your API key at the provider's keys page."}
        elif e.response.status_code == 404:
            # Try alternative models if default fails (only for 404, not for auth errors)
            alt_models = {
                ProviderType.GROQ: ["mixtral-8x7b-32768", "llama-3.3-70b-versatile"],
                ProviderType.OPENROUTER: ["google/gemini-pro", "openai/gpt-4o-mini"],
            }
            alternatives = alt_models.get(provider, [])
            last_error = f"Model '{test_model}' not found. Tried alternatives but all failed."
            for alt_model in alternatives:
                try:
                    messages = [LLMMessage(role=MessageRole.USER, content="Say 'OK' if you can hear me.")]
                    response = await provider_obj.complete(messages, alt_model, max_tokens=10)
                    return {"status": "ok", "response": response.content[:100], "latency_ms": response.latency_ms, "model": alt_model, "note": f"Default model '{test_model}' not available, using '{alt_model}'"}
                except httpx.HTTPStatusError as alt_e:
                    if alt_e.response.status_code == 404:
                        last_error = f"Model '{alt_model}' not found either."
                        continue  # Try next alternative
                    else:
                        last_error = f"Alternative model '{alt_model}' returned HTTP {alt_e.response.status_code}"
                        break  # Don't try more if it's a different error
                except Exception:
                    last_error = f"Alternative model '{alt_model}' failed."
                    continue
            return {"status": "error", "error": f"Not Found (404) - {last_error} Try selecting a different model from the dropdown."}
        elif e.response.status_code == 429:
            return {"status": "error", "error": "Rate Limited (429) - Too many requests. Please wait and try again."}
        else:
            return {"status": "error", "error": f"HTTP {e.response.status_code}: {error_detail[:200]}"}
    except OSError as e:
        # Handle DNS resolution errors like getaddrinfo failed
        if "getaddrinfo failed" in str(e) or "Name or service not known" in str(e):
            return {"status": "error", "error": f"Connection Error - Could not reach '{test_base_url}'. Check your internet connection and verify the URL is correct."}
        return {"status": "error", "error": f"Connection Error: {str(e)}"}
    except Exception as e:
        error_str = str(e)
        if "getaddrinfo failed" in error_str:
            return {"status": "error", "error": f"Connection Error - Could not reach '{test_base_url}'. Check your internet connection and verify the URL is correct."}
        return {"status": "error", "error": error_str}


# Analysis endpoints
# ============ Phase 2: Analysis Endpoints ============

@app.post("/api/projects/{project_id}/analyze")
async def start_analysis(project_id: str, input_type: str, input_data: dict):
    """Start an analysis task."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    memory_engine.set_current_project(project)

    # Log the analysis start
    memory_engine.add_investigation_log({
        "action": "analysis_started",
        "input_type": input_type,
    })

    # TODO: Dispatch to appropriate agent based on input_type
    # For now, return a placeholder response
    return {
        "status": "started",
        "conversation_id": project_id,
        "message": "Analysis started. Connect via WebSocket for real-time updates.",
    }


# --- Code Analysis (SAST) ---

class CodeAnalysisRequest(BaseModel):
    code: str
    file_path: str
    language: str | None = None


@app.post("/api/projects/{project_id}/analyze/code")
async def analyze_code(project_id: str, req: CodeAnalysisRequest):
    """Analyze code for security patterns."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get or create code analyzer for this project
    if project_id not in code_analyzers:
        code_analyzers[project_id] = CodeAnalyzer(project_id)

    analyzer = code_analyzers[project_id]
    patterns = analyzer.analyze_file(req.file_path, req.code, req.language)
    data_flows = analyzer.analyze_data_flow(req.file_path, req.code)
    auth_flows = [analyzer.analyze_auth_flow(req.file_path, req.code)]

    return {
        "patterns": [p.to_dict() for p in patterns],
        "data_flows": [f.to_dict() for f in data_flows],
        "auth_flows": [a.to_dict() for a in auth_flows],
        "summary": {
            "patterns_found": len(patterns),
            "critical": len([p for p in patterns if p.severity.value == "critical"]),
            "high": len([p for p in patterns if p.severity.value == "high"]),
            "data_flows": len(data_flows),
            "unsafe_flows": len([f for f in data_flows if not f.is_safe]),
        },
    }


# --- Web Vulnerability Analysis ---

class WebAnalysisRequest(BaseModel):
    method: str
    path: str
    parameters: list[dict] | None = None
    auth_required: bool = False


@app.post("/api/projects/{project_id}/analyze/web/endpoint")
async def analyze_web_endpoint(project_id: str, req: WebAnalysisRequest):
    """Analyze a web endpoint for vulnerabilities."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get or create web analyzer for this project
    if project_id not in web_analyzers:
        web_analyzers[project_id] = WebAnalyzer(project_id)

    analyzer = web_analyzers[project_id]
    from .analyzers.web_analyzer import Parameter
    params = [Parameter(**p) for p in (req.parameters or [])]
    endpoint_id = analyzer.add_endpoint(req.method, req.path, params, req.auth_required)
    endpoint = next(e for e in analyzer.get_endpoints() if e.id == endpoint_id)
    vulnerabilities = analyzer.analyze_endpoint(endpoint)

    return {
        "endpoint": endpoint.to_dict(),
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "summary": analyzer.get_vulnerability_summary(),
    }


# --- Knowledge Graph ---

@app.get("/api/projects/{project_id}/knowledge-graph")
async def get_knowledge_graph(project_id: str):
    """Get the knowledge graph for a project."""
    if project_id not in knowledge_graphs:
        return {"entities": [], "relationships": [], "attack_paths": []}
    kg = knowledge_graphs[project_id]
    return kg.to_dict()


@app.post("/api/projects/{project_id}/knowledge-graph/entity")
async def add_knowledge_entity(project_id: str, entity_data: dict):
    """Add an entity to the knowledge graph."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_id not in knowledge_graphs:
        knowledge_graphs[project_id] = KnowledgeGraphEngine(project_id)

    from .engines.knowledge_graph import EntityNode, EntityType
    entity_data["entity_type"] = EntityType(entity_data.get("entity_type", "service"))
    entity = EntityNode(**entity_data)
    knowledge_graphs[project_id].add_entity(entity)

    return {"status": "ok", "entity_id": entity.id}


@app.post("/api/projects/{project_id}/knowledge-graph/relationship")
async def add_knowledge_relationship(project_id: str, rel_data: dict):
    """Add a relationship to the knowledge graph."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_id not in knowledge_graphs:
        knowledge_graphs[project_id] = KnowledgeGraphEngine(project_id)

    from .engines.knowledge_graph import RelationshipEdge, RelationshipType
    rel_data["relationship_type"] = RelationshipType(rel_data.get("relationship_type", "calls"))
    rel = RelationshipEdge(**rel_data)
    knowledge_graphs[project_id].add_relationship(rel)

    return {"status": "ok", "relationship_id": rel.id}


@app.post("/api/projects/{project_id}/knowledge-graph/attack-paths")
async def discover_attack_paths(project_id: str):
    """Discover attack paths in the knowledge graph."""
    if project_id not in knowledge_graphs:
        return {"attack_paths": []}

    kg = knowledge_graphs[project_id]
    paths = kg.discover_attack_paths()

    return {"attack_paths": [p.to_dict() for p in paths]}


# --- Permission Graph ---

@app.get("/api/projects/{project_id}/permission-graph")
async def get_permission_graph(project_id: str):
    """Get the permission graph for a project."""
    if project_id not in permission_graphs:
        return {"subjects": [], "objects": [], "permissions": [], "gaps": []}
    pg = permission_graphs[project_id]
    return pg.to_dict()


@app.post("/api/projects/{project_id}/permission-graph/gaps")
async def analyze_permission_gaps(project_id: str):
    """Analyze permission graph for security gaps."""
    if project_id not in permission_graphs:
        return {"gaps": []}

    pg = permission_graphs[project_id]
    gaps = pg.analyze_gaps()

    return {"gaps": [g.to_dict() for g in gaps]}


# --- Business Rules ---

@app.get("/api/projects/{project_id}/business-rules")
async def get_business_rules(project_id: str):
    """Get business rules for a project."""
    if project_id not in business_rule_engines:
        return {"rules": [], "violations": []}
    bre = business_rule_engines[project_id]
    return bre.to_dict()


@app.post("/api/projects/{project_id}/business-rules/extract")
async def extract_business_rules(project_id: str, file_path: str = "", code: str = ""):
    """Extract business rules from code."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_id not in business_rule_engines:
        business_rule_engines[project_id] = BusinessRuleEngine(project_id)

    bre = business_rule_engines[project_id]
    rules = bre.extract_rules_from_code(file_path, code)
    violations = bre.detect_violations(code, file_path)

    return {
        "rules": [r.to_dict() for r in rules],
        "violations": [v.to_dict() for v in violations],
    }


# --- RAG Indexing ---

@app.post("/api/projects/{project_id}/rag/index")
async def index_for_rag(project_id: str, file_path: str = "", content: str = "", file_type: str = "code"):
    """Index content for RAG retrieval."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if project_id not in rag_engines:
        rag_engines[project_id] = RAGEngine(llm_router)

    rag = rag_engines[project_id]
    await rag.index_file(file_path, content, file_type)

    return {"status": "ok", "indexed": file_path}


@app.get("/api/projects/{project_id}/rag/query")
async def rag_query(project_id: str, query: str = "", top_k: int = 5):
    """Query RAG for relevant context."""
    if project_id not in rag_engines:
        return {"results": []}
    rag = rag_engines[project_id]
    results = await rag.retrieve_for_reasoning(query, top_k=top_k)

    return {
        "results": [
            {
                "chunk_id": r.chunk.chunk_id,
                "text": r.text,
                "score": r.score,
                "rerank_score": r.rerank_score,
                "source_file": r.chunk.source_file,
            }
            for r in results
        ]
    }


# --- Analysis Summary ---

@app.get("/api/projects/{project_id}/analysis-summary")
async def get_analysis_summary(project_id: str):
    """Get combined analysis results from all Phase 2 components."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    summary = {
        "code_analysis": {
            "patterns_found": 0,
            "critical_issues": 0,
            "data_flows_unsafe": 0,
        },
        "web_analysis": {
            "endpoints": 0,
            "vulnerabilities": 0,
        },
        "knowledge_graph": {
            "entities": 0,
            "relationships": 0,
            "attack_paths": 0,
        },
        "permission_graph": {
            "subjects": 0,
            "gaps": 0,
        },
        "business_rules": {
            "rules": 0,
            "violations": 0,
        },
    }

    if project_id in code_analyzers:
        analyzer = code_analyzers[project_id]
        patterns = analyzer.get_all_patterns()
        summary["code_analysis"]["patterns_found"] = len(patterns)
        summary["code_analysis"]["critical_issues"] = len([p for p in patterns if p.severity.value == "critical"])
        unsafe_flows = [f for f in analyzer.get_all_data_flows() if not f.is_safe]
        summary["code_analysis"]["data_flows_unsafe"] = len(unsafe_flows)

    if project_id in web_analyzers:
        analyzer = web_analyzers[project_id]
        summary["web_analysis"]["endpoints"] = len(analyzer.get_endpoints())
        summary["web_analysis"]["vulnerabilities"] = len(analyzer.get_all_vulnerabilities())

    if project_id in knowledge_graphs:
        kg = knowledge_graphs[project_id]
        summary["knowledge_graph"]["entities"] = len(kg.get_all_entities())
        summary["knowledge_graph"]["relationships"] = len(list(kg._relationships.values()))
        summary["knowledge_graph"]["attack_paths"] = len(kg._attack_paths)

    if project_id in permission_graphs:
        pg = permission_graphs[project_id]
        summary["permission_graph"]["subjects"] = len(pg.get_all_subjects())
        summary["permission_graph"]["gaps"] = len(pg._gaps)

    if project_id in business_rule_engines:
        bre = business_rule_engines[project_id]
        summary["business_rules"]["rules"] = len(bre.get_all_rules())
        summary["business_rules"]["violations"] = len(bre._violations)

    return summary


# ============ Phase 3: Agent Endpoints ============

class AgentTaskRequest(BaseModel):
    action: str
    input_data: dict = {}  # Using dict without generics to avoid PEP 563 forward ref issues with Pydantic


# ============ Debug Endpoints ============

@app.post("/api/debug/test")
async def debug_test(req: AgentTaskRequest):
    """Debug endpoint to test request parsing."""
    return {"status": "ok", "received_action": req.action, "input_data_keys": list(req.input_data.keys())}


def _get_or_create_agent(project_id: str, agent_type: str):
    """Get or create a Phase 3 agent for a project."""
    if llm_router is None:
        raise RuntimeError("LLM router not initialized. Please configure a provider in Settings.")
    
    if project_id not in phase3_agents:
        phase3_agents[project_id] = {}
    
    agents = phase3_agents[project_id]
    if agent_type not in agents:
        # Create the appropriate agent
        if agent_type == "recon":
            agents[agent_type] = ReconAgent(message_bus, llm_router, project_id)
        elif agent_type == "code_review":
            # Get or create code analyzer
            if project_id not in code_analyzers:
                code_analyzers[project_id] = CodeAnalyzer(project_id)
            agents[agent_type] = CodeReviewAgent(message_bus, llm_router, project_id, code_analyzers[project_id])
        elif agent_type == "threat_modeling":
            # Get or create knowledge graph
            if project_id not in knowledge_graphs:
                knowledge_graphs[project_id] = KnowledgeGraphEngine(project_id)
            agents[agent_type] = ThreatModelingAgent(message_bus, llm_router, project_id, knowledge_graphs[project_id])
        elif agent_type == "dependency":
            agents[agent_type] = DependencyAgent(message_bus, llm_router, project_id)
        elif agent_type == "debate":
            agents[agent_type] = DebateAgent(message_bus, llm_router, project_id)
    
    return agents[agent_type]


# --- Reconnaissance ---

@app.post("/api/projects/{project_id}/agents/recon")
async def run_recon_agent(project_id: str, req: AgentTaskRequest):
    """Run reconnaissance agent tasks."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_agent(project_id, "recon")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="recon",
            input_data=req.input_data,
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "recon",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("recon_agent_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# --- Code Review ---

@app.post("/api/projects/{project_id}/agents/code-review")
async def run_code_review_agent(project_id: str, req: AgentTaskRequest):
    """Run code review agent tasks."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_agent(project_id, "code_review")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="code_review",
            input_data=req.input_data,
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "code_review",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("code_review_agent_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# --- Threat Modeling ---

@app.post("/api/projects/{project_id}/agents/threat-modeling")
async def run_threat_modeling_agent(project_id: str, req: AgentTaskRequest):
    """Run threat modeling agent tasks."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_agent(project_id, "threat_modeling")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="threat_modeling",
            input_data=req.input_data,
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "threat_modeling",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("threat_modeling_agent_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# --- Dependency Scanning ---

@app.post("/api/projects/{project_id}/agents/dependency")
async def run_dependency_agent(project_id: str, req: AgentTaskRequest):
    """Run dependency scanning agent tasks."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_agent(project_id, "dependency")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="dependency",
            input_data=req.input_data,
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "dependency",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("dependency_agent_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# --- Debate Engine ---

@app.post("/api/projects/{project_id}/agents/debate")
async def run_debate_agent(project_id: str, req: AgentTaskRequest):
    """Run adversarial debate on findings."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_agent(project_id, "debate")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="debate",
            input_data=req.input_data,
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "debate",
            "result": result,
        }
    except Exception as e:
        logger.error("debate_agent_error", error=str(e), project_id=project_id)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@app.get("/api/projects/{project_id}/agents")
async def list_agents(project_id: str):
    """List all available agents for a project."""
    return {
        "agents": [
            {"type": "recon", "name": "Reconnaissance Agent", "description": "Target discovery and OSINT"},
            {"type": "code_review", "name": "Code Review Agent", "description": "SAST with deep code analysis"},
            {"type": "threat_modeling", "name": "Threat Modeling Agent", "description": "Attack path analysis"},
            {"type": "dependency", "name": "Dependency Agent", "description": "Vulnerability scanning"},
            {"type": "debate", "name": "Debate Engine", "description": "5-role adversarial validation"},
        ],
        "active_count": len(phase3_agents.get(project_id, {})),
    }


# WebSocket for real-time updates
@app.websocket("/ws/{project_id}")
async def websocket_endpoint(websocket: WebSocket, project_id: str):
    """WebSocket endpoint for real-time agent updates."""
    await websocket.accept()

    # Load project
    project = memory_engine.load_project(project_id)
    if project is None:
        await websocket.send_json({"type": "error", "data": {"message": "Project not found"}})
        await websocket.close()
        return

    memory_engine.set_current_project(project)

    # Subscribe to message bus for this project
    async def handle_message(message: AgentMessage):
        if message.conversation_id == project_id:
            await websocket.send_json({
                "type": "agent_message",
                "data": {
                    "source": message.source_agent.value,
                    "message_type": message.message_type.value,
                    "payload": message.payload,
                    "timestamp": message.timestamp.isoformat(),
                },
            })

    await message_bus.subscribe_global(handle_message)

    try:
        # Send initial state
        await websocket.send_json({
            "type": "connected",
            "data": {
                "project_id": project_id,
                "findings_count": len(project.findings),
                "status": "ready",
            },
        })

        # Keep connection alive and handle client messages
        while True:
            try:
                data = await websocket.receive_json()
                msg_type = data.get("type")

                if msg_type == "ping":
                    await websocket.send_json({"type": "pong"})
                elif msg_type == "send_message":
                    # Handle chat messages from UI
                    await websocket.send_json({
                        "type": "message_received",
                        "data": {"content": "Message received. Processing..."},
                    })
                elif msg_type == "get_findings":
                    findings = project.findings
                    await websocket.send_json({
                        "type": "findings",
                        "data": {"findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]},
                    })

            except WebSocketDisconnect:
                break

    except Exception as e:
        logger.error("websocket_error", error=str(e))
    finally:
        # Unsubscribe the handler to prevent memory leak
        if handle_message in message_bus._global_handlers:
            message_bus._global_handlers.remove(handle_message)


def create_app() -> FastAPI:
    """Factory function to create the app."""
    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "sentinel_x_ultra.server:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.reload,
    )