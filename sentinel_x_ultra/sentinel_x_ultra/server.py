"""FastAPI Web Server - Main application entry point."""

from __future__ import annotations

import asyncio
import uuid
import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Any, Dict

import structlog
import json
from dotenv import load_dotenv  # Load .env file for Phase 5 API keys
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx

# Load environment variables from .env file (for Phase 5 API keys)
_env_path = Path(__file__).parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
    print(f"[SENTINEL-X] Loaded environment variables from {_env_path}")

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
    Finding,
)

# Phase 4 imports - Remediation, Reporting, Compliance
from .agents.phase4 import (
    RemediationAgent,
    ReportGenerator,
    ComplianceEngine,
)

# Phase 5 imports - Advanced Security Operations
from .agents.phase5 import (
    ThreatIntelligenceAgent,
    SecurityOperationsAgent,
    AdaptiveDefenseAgent,
    SupplyChainAgent,
    APISecurityAgent,
)

# Reconnaissance tools integration (Phase 3 extended)
from .recon_api import register_recon_endpoints

# Bug Bounty Multi-Agent Framework v7.0 (10 specialized agents)
from .bug_bounty import (
    BugBountyOrchestrator,
    URLParserAgent,
    PolicyEnforcerAgent,
    ScopeGuardianAgent,
    PassiveIntelligenceAgent,
    ActiveEnumerationAgent,
    VulnerabilityScannerAgent,
    ValidationEngineAgent,
    ExploitationAgent,
    AnalysisAgent,
    ReportGenerationAgent,
    get_full_system_prompt,
    FOUNDATIONAL_PRINCIPLES,
    DECISION_HIERARCHY,
    AGENT_ARCHITECTURE,
)

# Bug Bounty Multi-Agent Framework v7.0 (10 specialized agents)
from .bug_bounty import (
    BugBountyOrchestrator,
    URLParserAgent,
    PolicyEnforcerAgent,
    ScopeGuardianAgent,
    PassiveIntelligenceAgent,
    ActiveEnumerationAgent,
    VulnerabilityScannerAgent,
    ValidationEngineAgent,
    ExploitationAgent,
    AnalysisAgent,
    ReportGenerationAgent,
    get_full_system_prompt,
    FOUNDATIONAL_PRINCIPLES,
    DECISION_HIERARCHY,
    AGENT_ARCHITECTURE,
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
provider_config_file: Path = settings.storage.base_path / "providers.json"

# Agent model configurations
agent_model_configs: dict[str, str] = {}  # agent_id -> model
agent_config_file: Path = settings.storage.base_path / "agent_models.json"

def _load_provider_configs():
    """Load provider configurations from file."""
    global provider_key_map
    if provider_config_file.exists():
        try:
            with open(provider_config_file, 'r') as f:
                data = json.load(f)
                provider_key_map = data.get('providers', {})
                logger.info("provider_configs_loaded", count=len(provider_key_map))
        except Exception as e:
            logger.error("failed_to_load_provider_configs", error=str(e))

def _save_provider_configs():
    """Save provider configurations to file."""
    try:
        settings.storage.base_path.mkdir(parents=True, exist_ok=True)
        with open(provider_config_file, 'w') as f:
            json.dump({'providers': provider_key_map}, f, indent=2)
        logger.info("provider_configs_saved", count=len(provider_key_map))
    except Exception as e:
        logger.error("failed_to_save_provider_configs", error=str(e))

def _load_agent_configs():
    """Load agent model configurations from file."""
    global agent_model_configs
    if agent_config_file.exists():
        try:
            with open(agent_config_file, 'r') as f:
                data = json.load(f)
                agent_model_configs = data.get('agents', {})
                logger.info("agent_configs_loaded", count=len(agent_model_configs))
        except Exception as e:
            logger.error("failed_to_load_agent_configs", error=str(e))

def _save_agent_configs():
    """Save agent model configurations to file."""
    try:
        settings.storage.base_path.mkdir(parents=True, exist_ok=True)
        with open(agent_config_file, 'w') as f:
            json.dump({'agents': agent_model_configs}, f, indent=2)
        logger.info("agent_configs_saved", count=len(agent_model_configs))
    except Exception as e:
        logger.error("failed_to_save_agent_configs", error=str(e))

# Phase 2 - Engines and Analyzers
knowledge_graphs: dict[str, KnowledgeGraphEngine] = {}  # project_id -> engine
permission_graphs: dict[str, PermissionGraphEngine] = {}  # project_id -> engine
business_rule_engines: dict[str, BusinessRuleEngine] = {}  # project_id -> engine
code_analyzers: dict[str, CodeAnalyzer] = {}  # project_id -> analyzer
web_analyzers: dict[str, WebAnalyzer] = {}  # project_id -> analyzer
rag_engines: dict[str, RAGEngine] = {}  # project_id -> engine

# Phase 3 - Agents
phase3_agents: dict[str, dict[str, Any]] = {}  # project_id -> {agent_type: agent_instance}

# Phase 4 - Remediation & Compliance
phase4_engines: dict[str, dict[str, Any]] = {}  # project_id -> {engine_type: engine_instance}

# Phase 5 - Advanced Security Operations
phase5_agents: dict[str, dict[str, Any]] = {}  # project_id -> {agent_type: agent_instance}


# Bug Bounty Orchestrator (10-agent pipeline with ethical rules)
bug_bounty_orchestrator: BugBountyOrchestrator | None = None

# Path to frontend dist (relative to this file)
FRONTEND_DIST = Path(__file__).parent.parent / "frontend/dist"


# ============ AUTO-AGENT SELECTION MAPPING ============
# Maps vulnerability types to the best Phase 5 agents for detection and remediation
VULN_TO_AGENTS = {
    "sql_injection": {
        "primary": "api_security",
        "secondary": ["threat_intelligence", "security_operations"],
        "description": "SQL Injection requires API Security agent with comprehensive SQL injection payloads",
        "owasp": ["A01", "A05"],
        "severity": "critical",
        "payloads": ["' OR '1'='1", "1' UNION SELECT NULL--", "'; DROP TABLE users; --", "1' ORDER BY 1--", "admin'--"],
        "indicators": ["sql_error", "database_timeout", "auth_bypass", "data_leak"],
    },
    "xss": {
        "primary": "api_security",
        "secondary": ["threat_intelligence"],
        "description": "XSS requires API Security agent for fuzzing with XSS payloads and DOM analysis",
        "owasp": ["A05", "A07"],
        "severity": "high",
        "payloads": ["<script>alert(document.domain)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "#\"><img src=x onerror=alert(1)>", "javascript:alert(document.domain)"],
        "indicators": ["script_tag", "event_handler", "javascript_protocol", "dom_manipulation"],
    },
    "idor": {
        "primary": "api_security",
        "secondary": ["threat_intelligence", "adaptive_defense"],
        "description": "IDOR requires API Security agent for authorization testing and resource enumeration",
        "owasp": ["A01"],
        "severity": "high",
        "payloads": ["/api/users/123 â†’ /api/users/124", "POST ID manipulation", "UUID enumeration", "HTTP parameter pollution"],
        "indicators": ["object_reference", "missing_authz", "sequential_id", "direct_access"],
    },
    "ssrf": {
        "primary": "api_security",
        "secondary": ["threat_intelligence", "supply_chain"],
        "description": "SSRF requires API Security agent for protocol testing and internal network probing",
        "owasp": ["A01", "A05", "A10"],
        "severity": "critical",
        "payloads": ["http://169.254.169.254/", "http://localhost:8500", "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO", "dict://localhost:11211/%0astats"],
        "indicators": ["url_parameter", "file_protocol", "internal_ip", "metadata_endpoint"],
    },
    "rce": {
        "primary": "api_security",
        "secondary": ["threat_intelligence", "adaptive_defense", "security_operations"],
        "description": "RCE requires API Security agent with command injection payloads + Threat Intel for malware analysis",
        "owasp": ["A05", "A08"],
        "severity": "critical",
        "payloads": ["`whoami`", "$(whoami)", "| whoami", "; whoami", "&& whoami", "'; exec master..xp_cmdshell 'whoami'--", "{{7*7}}", "${exec whoami}"],
        "indicators": ["command_injection", "eval_function", "system_call", "template_engine", "deserialization"],
    },
    "xxe": {
        "primary": "api_security",
        "secondary": ["supply_chain"],
        "description": "XXE requires API Security agent for XML parsing testing and file read exploitation",
        "owasp": ["A05", "A08"],
        "severity": "critical",
        "payloads": ["<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>", "Billion Laughs attack payload", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>"],
        "indicators": ["xml_upload", "xml_parser", "external_entity", "xxe_injection"],
    },
    "ssti": {
        "primary": "api_security",
        "secondary": ["threat_intelligence"],
        "description": "SSTI requires API Security agent with template injection payloads for code execution",
        "owasp": ["A05", "A10"],
        "severity": "critical",
        "payloads": ["{{7*7}}", "{{config}}", "${7*7}", "${T(SYSTEM)}", "{{request|attr('application')}}", "{% for x in ().__class__.__base__.__subclasses__() %}{{x()}}{% endfor %}"],
        "indicators": ["template_syntax", "double_brace", "template_injection", "render_template"],
    },
    "graphql": {
        "primary": "api_security",
        "secondary": ["supply_chain"],
        "description": "GraphQL requires API Security agent with introspection and batch attack testing",
        "owasp": ["A01", "A05"],
        "severity": "high",
        "payloads": [
            # Introspection Attacks
            "{__schema{types{name fields{name}}}}",
            "{__type(name:\"User\"){name fields{type{name}}}}",
            "{__schema{mutationType{fields{name description args{name type{name}}}}}}",
            # Batching Attacks (Alias Abuse)
            "mutation{login1:login(user:\"admin\",pass:\"1111\"){success}login2:login(user:\"admin\",pass:\"1112\"){success}}",
            "{a1:user(id:\"1\"){name}a2:user(id:\"1\"){name}a3:user(id:\"1\"){name}a4:user(id:\"1\"){name}a5:user(id:\"1\"){name}}",
            # JSON List Batching
            "[{\"query\":\"mutation{login(user:\"admin\",pass:\"1111\")}\"},{\"query\":\"mutation{login(user:\"admin\",pass:\"1112\")}\"}]",
            # Nested Query DoS
            "{user{friends{friends{friends{friends{name}}}}}}",
            # Circular Reference DoS
            "{user(id:\"1\"){posts{author{posts{author{name}}}}}}",
            # Mutation Injection
            "mutation{signIn(login:\"Admin\",password:\"secret\"){success token}}",
            # SQL/NoSQL in GraphQL params
            "{doctors(search:\"{$regex:.*,lastName:Admin}\"){firstName}}",
        ],
        "indicators": ["graphql_endpoint", "introspection_query", "query_batching", "nested_query"],
    },
    "nosql": {
        "primary": "api_security",
        "secondary": ["security_operations"],
        "description": "NoSQL Injection requires API Security agent with MongoDB/Redis operator payloads",
        "owasp": ["A05"],
        "severity": "critical",
        "payloads": ["{\"$gt\": \"\"}", "{\"$where\": \"1=1\"}", "{\"$regex\": \".*\"}", "{\"login\": {\"$ne\": null}}", "{\"$expr\": {\"$gt\": [1, 1]}}"],
        "indicators": ["mongodb_operator", "nosql_query", "json_query", "no_sql_syntax"],
    },
    "auth_bypass": {
        "primary": "api_security",
        "secondary": ["adaptive_defense", "security_operations"],
        "description": "Auth bypass requires API Security agent + Adaptive Defense for session analysis",
        "owasp": ["A02", "A07"],
        "severity": "critical",
        "payloads": ["' OR 1=1--", "alg: none JWT attack", "Session fixation", "OAuth redirect_uri manipulation", "Basic Auth bypass", "Bearer: eyJhbGciOiJub25lIn0..."],
        "indicators": ["weak_auth", "missing_rate_limit", "jwt_algorithm", "session_hijack", "credential_stuffing"],
    },
    "oauth": {
        "primary": "api_security",
        "secondary": ["threat_intelligence"],
        "description": "OAuth vulnerabilities require API Security agent with flow manipulation payloads",
        "owasp": ["A01", "A07"],
        "severity": "high",
        "payloads": ["redirect_uri: http://evil.com", "redirect_uri: null/https://expected.com@evil.com", "state parameter missing", "code reuse after logout", "Scope escalation: email â†’ email,full_access"],
        "indicators": ["oauth_flow", "redirect_uri", "state_parameter", "token_reuse"],
    },
    "path_traversal": {
        "primary": "api_security",
        "secondary": ["threat_intelligence"],
        "description": "Path traversal requires API Security agent for file operation fuzzing",
        "owasp": ["A01", "A05"],
        "severity": "high",
        "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "file:///etc/passwd"],
        "indicators": ["file_parameter", "path_traversal", "directory_traversal", "path_injection"],
    },
    "open_redirect": {
        "primary": "api_security",
        "secondary": ["threat_intelligence"],
        "description": "Open redirect requires API Security agent for redirect parameter testing",
        "owasp": ["A01"],
        "severity": "medium",
        "payloads": ["https://evil.com", "//evil.com", "///evil.com", "https://expected.com@evil.com", "\\evil.com"],
        "indicators": ["redirect_parameter", "url_redirect", "location_header", "meta_refresh"],
    },
    "business_logic": {
        "primary": "api_security",
        "secondary": ["adaptive_defense"],
        "description": "Business logic requires API Security agent + Adaptive Defense for concurrent testing",
        "owasp": ["A04", "A08"],
        "severity": "high",
        "payloads": ["Price manipulation: item_price=-100", "Quantity overflow", "Race conditions", "Workflow bypass", "Integer overflow in transactions"],
        "indicators": ["price_parameter", "quantity_parameter", "race_condition", "workflow_bypass"],
    },
    "toctou": {
        "primary": "api_security",
        "secondary": ["adaptive_defense", "security_operations"],
        "description": "TOCTOU race conditions require API Security agent + Adaptive Defense for atomicity testing",
        "owasp": ["A04", "A08"],
        "severity": "high",
        "payloads": ["Symlink attack during file operations", "Concurrent authentication requests", "File race in --skip-existing", "Double-free after check"],
        "indicators": ["atomicity_violation", "race_window", "file_operation", "shared_resource"],
    },
    "deserialization": {
        "primary": "api_security",
        "secondary": ["threat_intelligence"],
        "description": "Deserialization requires API Security agent + Threat Intel for gadget chain analysis",
        "owasp": ["A08", "A05"],
        "severity": "critical",
        "payloads": ["O:10:\"Example\":1:{s:3:\"cmd\";s:8:\"whoami\";}", "rO0ABXQAL1VuZGVmaW5lZEv/////dHJhY2U=", "{{obj.__class__.__mro__[1].__subclasses__()}}", "bash -c {echo,YmFzaCAtaSA+JG1hc2g=}|{base64,-d}|{bash,-i}"],
        "indicators": ["deserialize_data", "pickle_load", "yaml_load", "java_deserialization", "gadget_chain"],
    },
    "memory": {
        "primary": "threat_intelligence",
        "secondary": ["api_security", "adaptive_defense"],
        "description": "Memory corruption requires Threat Intelligence agent + Adaptive Defense for fuzzing",
        "owasp": ["A08", "A10"],
        "severity": "critical",
        "payloads": ["Heap overflow: A'*10000", "Use-after-free patterns", "Double-free: free() same twice", "Format string: %s%s%s%s", "Integer overflow: large value"],
        "indicators": ["buffer_overflow", "heap_overflow", "uaf", "format_string", "memory_corruption"],
    },
    "ci_cd": {
        "primary": "supply_chain",
        "secondary": ["security_operations", "adaptive_defense"],
        "description": "CI/CD security requires Supply Chain agent for pipeline analysis + Security Operations for monitoring",
        "owasp": ["A03", "A08"],
        "severity": "critical",
        "payloads": ["Secrets in workflow files", "Untrusted checkout actions", "Missing security scans", "Exposed credentials in logs", "Privilege escalation in pipelines"],
        "indicators": ["github_actions", "jenkinsfile", "dockerfile", "pipeline_config", "secret_in_env"],
    },
    "sensitive_data": {
        "primary": "api_security",
        "secondary": ["security_operations", "threat_intelligence"],
        "description": "Sensitive data exposure requires API Security agent for data classification + Security Operations for monitoring",
        "owasp": ["A01", "A02", "A03"],
        "severity": "high",
        "payloads": ["API key in response", "Password in plain text", "PII data exposure", "Token in URL", "Credit card in logs"],
        "indicators": ["api_key_exposure", "password_plaintext", "pii_leak", "token_in_url", "data_classification"],
    },
}

# Agent info for UI display
AGENT_INFO = {
    "threat_intelligence": {
        "name": "Threat Intelligence Agent",
        "icon": "ðŸ”",
        "color": "#ff8844",
        "description": "YARA rules, IOC enrichment, threat tracking, malware analysis",
        "phase": 5,
    },
    "security_operations": {
        "name": "Security Operations Agent",
        "icon": "ðŸ›¡ï¸",
        "color": "#00d4ff",
        "description": "SIEM integration, SOAR playbooks, alert triage, incident management",
        "phase": 5,
    },
    "adaptive_defense": {
        "name": "Adaptive Defense Agent",
        "icon": "âš¡",
        "color": "#aa88ff",
        "description": "ML anomaly detection, behavioral analysis, self-healing automation",
        "phase": 5,
    },
    "supply_chain": {
        "name": "Supply Chain Agent",
        "icon": "ðŸ“¦",
        "color": "#00ff88",
        "description": "SBOM generation, dependency analysis, license compliance, CVE scanning",
        "phase": 5,
    },
    "api_security": {
        "name": "API Security Agent",
        "icon": "ðŸ”—",
        "color": "#ffaa00",
        "description": "OpenAPI/GraphQL analysis, fuzzing, authentication testing, rate limiting",
        "phase": 5,
    },
}


class CreateProjectRequest(BaseModel):
    name: str
    scope: ScopeGraph | None = None
    folder: str | None = None       # Folder-first project creation (optional for backward compat)
    target: str | None = None       # Target domain for seeding the recon txt templates


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

    # Load provider configurations from file
    _load_provider_configs()
    
    # Load agent model configurations from file
    _load_agent_configs()

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

# Register reconnaissance API endpoints
register_recon_endpoints(app)

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
    """Create a new project. If `folder` is provided and is empty, seed it with the
    standard recon txt templates (target.txt, AllSubs.txt, AliveSubs.txt, urls.txt,
    param.txt, js.txt, xss.txt, lfi.txt, XSSvulnerable.txt, sqlmap.txt) sourced from
    the live bug-bounty hunting workflow."""
    project = memory_engine.create_project(req.name, req.scope)
    memory_engine.save_project(project)

    seeded_files: list[str] = []
    folder_status = "not_provided"
    if req.folder:
        from pathlib import Path as _P
        from .seed_templates import seed_empty_folder
        folder_path = _P(req.folder)
        try:
            folder_path.mkdir(parents=True, exist_ok=True)
            # Only seed if the folder is empty - never clobber user data
            is_empty = not any(folder_path.iterdir())
            if is_empty:
                seeded_files = seed_empty_folder(folder_path, target=req.target or "example.com")
                folder_status = "seeded_empty_folder"
            else:
                folder_status = "folder_has_files"
            # Persist the folder binding on the project so it shows up everywhere
            project.folder = str(folder_path)
            memory_engine.save_project(project)
        except Exception as exc:
            logger.error("folder_seed_failed", error=str(exc), folder=req.folder)
            folder_status = f"error: {exc}"

    return {
        "project_id": project.project_id,
        "name": project.name,
        "folder": req.folder,
        "folder_status": folder_status,
        "seeded_files": seeded_files,
    }


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
    # Projects are stored as JSON files, not directories
    project_file = memory_engine.storage_path / f"{project_id}.json"
    if project_file.exists():
        project_file.unlink()
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
    # Store in memory and persist to file
    provider_key_map[req.provider] = {"api_key": req.api_key, "base_url": req.base_url}
    try:
        _save_provider_configs()
    except Exception as e:
        logger.error("save_provider_failed", error=str(e))
        return {"status": "error", "error": f"Failed to save configuration: {str(e)}"}
    return {"status": "ok", "provider": req.provider}


@app.get("/api/config/providers")
async def get_configured_providers():
    """Get list of configured providers (those that have an API key saved)."""
    return {
        "providers": list(provider_key_map.keys()),
        "count": len(provider_key_map),
    }


class AgentModelConfigRequest(BaseModel):
    agents: dict[str, str]  # agent_id -> model


@app.get("/api/config/agent-models")
async def get_agent_model_configs():
    """Get agent model configurations."""
    return {
        "agents": agent_model_configs,
    }


@app.post("/api/config/agent-models")
async def save_agent_model_configs(req: AgentModelConfigRequest):
    """Save agent model configurations."""
    global agent_model_configs
    agent_model_configs = req.agents
    try:
        _save_agent_configs()
    except Exception as e:
        logger.error("save_agent_configs_failed", error=str(e))
        return {"status": "error", "error": f"Failed to save agent configs: {str(e)}"}
    return {"status": "ok", "agents": agent_model_configs}


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
    # Note: /openai/v1 is 10 chars, /v1 is 3 chars
    if test_base_url.endswith('/openai/v1'):
        test_base_url = test_base_url[:-10]
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
                ProviderType.OPENROUTER: ["google/gemini-2.0-flash-exp", "meta-llama/llama-3.3-70b-instruct"],
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
    input_data: dict | None = None  # Using dict without generics to avoid PEP 563 forward ref issues with Pydantic
    
    def __init__(self, **data):
        super().__init__(**data)
        if self.input_data is None:
            self.input_data = {}


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
        agent_input = dict(req.input_data)
        agent_input["bug_bounty_system_prompt"] = bb_system_prompt
        agent_input["bug_bounty_ethical_rules"] = bb_ethical_rules
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="recon",
            input_data=agent_input,
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
        agent_input = dict(req.input_data)
        agent_input["bug_bounty_system_prompt"] = bb_system_prompt
        agent_input["bug_bounty_ethical_rules"] = bb_ethical_rules
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="code_review",
            input_data=agent_input,
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
        agent_input = dict(req.input_data)
        agent_input["bug_bounty_system_prompt"] = bb_system_prompt
        agent_input["bug_bounty_ethical_rules"] = bb_ethical_rules
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="threat_modeling",
            input_data=agent_input,
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
        agent_input = dict(req.input_data)
        agent_input["bug_bounty_system_prompt"] = bb_system_prompt
        agent_input["bug_bounty_ethical_rules"] = bb_ethical_rules
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="dependency",
            input_data=agent_input,
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
        agent_input = dict(req.input_data)
        agent_input["bug_bounty_system_prompt"] = bb_system_prompt
        agent_input["bug_bounty_ethical_rules"] = bb_ethical_rules
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="debate",
            input_data=agent_input,
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


# ============ Phase 5: Advanced Security Operations Endpoints ============

def _get_or_create_phase5_agent(project_id: str, agent_type: str):
    """Get or create a Phase 5 agent for a project."""
    if llm_router is None:
        raise RuntimeError("LLM router not initialized. Please configure a provider in Settings.")
    
    if project_id not in phase5_agents:
        phase5_agents[project_id] = {}
    
    agents = phase5_agents[project_id]
    if agent_type not in agents:
        if agent_type == "threat_intelligence":
            agents[agent_type] = ThreatIntelligenceAgent(message_bus, llm_router, project_id)
        elif agent_type == "security_operations":
            agents[agent_type] = SecurityOperationsAgent(message_bus, llm_router, project_id)
        elif agent_type == "adaptive_defense":
            agents[agent_type] = AdaptiveDefenseAgent(message_bus, llm_router, project_id)
        elif agent_type == "supply_chain":
            agents[agent_type] = SupplyChainAgent(message_bus, llm_router, project_id)
        elif agent_type == "api_security":
            agents[agent_type] = APISecurityAgent(message_bus, llm_router, project_id)
    
    return agents[agent_type]


@app.post("/api/projects/{project_id}/agents/threat-intelligence")
async def run_threat_intelligence_agent(project_id: str, req: AgentTaskRequest):
    """Run threat intelligence and hunting agent."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_phase5_agent(project_id, "threat_intelligence")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="threat_intelligence",
            input_data=req.input_data or {},
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "threat_intelligence",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("threat_intelligence_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@app.post("/api/projects/{project_id}/agents/security-operations")
async def run_security_operations_agent(project_id: str, req: AgentTaskRequest):
    """Run security operations and SOAR agent."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_phase5_agent(project_id, "security_operations")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="security_operations",
            input_data=req.input_data or {},
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "security_operations",
            "result": result,
        }
    except Exception as e:
        logger.error("security_operations_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@app.post("/api/projects/{project_id}/agents/adaptive-defense")
async def run_adaptive_defense_agent(project_id: str, req: AgentTaskRequest):
    """Run adaptive defense and anomaly detection agent."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_phase5_agent(project_id, "adaptive_defense")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="adaptive_defense",
            input_data=req.input_data or {},
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "adaptive_defense",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("adaptive_defense_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@app.post("/api/projects/{project_id}/agents/supply-chain")
async def run_supply_chain_agent(project_id: str, req: AgentTaskRequest):
    """Run supply chain security agent."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_phase5_agent(project_id, "supply_chain")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="supply_chain",
            input_data=req.input_data or {},
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "supply_chain",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("supply_chain_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


@app.post("/api/projects/{project_id}/agents/api-security")
async def run_api_security_agent(project_id: str, req: AgentTaskRequest):
    """Run API security testing agent."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        agent = _get_or_create_phase5_agent(project_id, "api_security")
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="api_security",
            input_data=req.input_data or {},
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "api_security",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("api_security_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# ============ Phase 4: Remediation & Compliance Endpoints ============

# --- Remediation Agent ---

@app.post("/api/projects/{project_id}/agents/remediation")
async def run_remediation_agent(project_id: str, req: AgentTaskRequest):
    """Run remediation agent to create/validate/implement remediation plans."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        # Get or create remediation agent
        if project_id not in phase4_engines:
            phase4_engines[project_id] = {}
        
        engines = phase4_engines[project_id]
        if "remediation" not in engines:
            engines["remediation"] = RemediationAgent(message_bus, llm_router, project_id)
        
        agent = engines["remediation"]
        task = TaskPayload(
            task_id=str(uuid.uuid4()),
            task_type="remediation",
            input_data=req.input_data or {},
        )
        result = await agent.execute_task(task)
        
        return {
            "status": "completed",
            "agent": "remediation",
            "result": result,
            "findings_created": len(getattr(agent, 'findings', [])),
        }
    except Exception as e:
        logger.error("remediation_agent_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# --- Report Generator ---

@app.get("/api/projects/{project_id}/reports")
async def list_reports(project_id: str):
    """List available report types."""
    return {
        "reports": [
            {"type": "executive_summary", "name": "Executive Summary", "description": "High-level security overview for leadership"},
            {"type": "detailed_technical", "name": "Detailed Technical Report", "description": "Comprehensive technical security findings"},
            {"type": "compliance", "name": "Compliance Report", "description": "Framework compliance mapping (OWASP, NIST, etc.)"},
        ],
        "project_id": project_id,
    }


@app.post("/api/projects/{project_id}/reports/executive")
async def generate_executive_report(project_id: str):
    """Generate executive summary report."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        # Initialize report generator
        if project_id not in phase4_engines:
            phase4_engines[project_id] = {}
        
        if "report_generator" not in phase4_engines[project_id]:
            phase4_engines[project_id]["report_generator"] = ReportGenerator(project_id, llm_router)
        
        report_gen = phase4_engines[project_id]["report_generator"]
        
        # Get findings from project
        findings = [Finding(**f) if isinstance(f, dict) else f for f in project.findings]
        
        # Generate metrics from project data
        metrics = {
            "scan_timestamp": getattr(project, 'created_at', None),
            "total_files_analyzed": len(getattr(project, 'analyzed_files', [])),
        }
        
        report = await report_gen.generate_executive_summary(findings, metrics)
        
        return {
            "status": "completed",
            "report": report,
        }
    except Exception as e:
        logger.error("executive_report_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation error: {str(e)}")


@app.post("/api/projects/{project_id}/reports/compliance")
async def generate_compliance_report(project_id: str, frameworks: list[str] = ["OWASP Top 10", "NIST CSF"]):
    """Generate compliance report mapping findings to frameworks."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        # Initialize compliance engine
        if project_id not in phase4_engines:
            phase4_engines[project_id] = {}
        
        if "compliance" not in phase4_engines[project_id]:
            phase4_engines[project_id]["compliance"] = ComplianceEngine(project_id)
        
        compliance_eng = phase4_engines[project_id]["compliance"]
        
        # Get findings from project
        findings = [Finding(**f) if isinstance(f, dict) else f for f in project.findings]
        
        report = await compliance_eng.assess_compliance(findings)
        
        return {
            "status": "completed",
            "report": report,
            "frameworks": frameworks,
        }
    except Exception as e:
        logger.error("compliance_report_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Compliance report error: {str(e)}")


@app.post("/api/projects/{project_id}/reports/control-mapping")
async def generate_control_mapping(project_id: str, framework: str = "OWASP Top 10"):
    """Generate detailed control mapping for a specific framework."""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        # Initialize compliance engine
        if project_id not in phase4_engines:
            phase4_engines[project_id] = {}
        
        if "compliance" not in phase4_engines[project_id]:
            phase4_engines[project_id]["compliance"] = ComplianceEngine(project_id)
        
        compliance_eng = phase4_engines[project_id]["compliance"]
        
        # Get findings from project
        findings = [Finding(**f) if isinstance(f, dict) else f for f in project.findings]
        
        mapping = await compliance_eng.generate_control_mapping(findings, framework)
        
        return {
            "status": "completed",
            "mapping": mapping,
        }
    except Exception as e:
        logger.error("control_mapping_error", error=str(e), project_id=project_id, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Control mapping error: {str(e)}")


@app.get("/api/projects/{project_id}/compliance/frameworks")
async def list_compliance_frameworks(project_id: str):
    """List available compliance frameworks."""
    return {
        "frameworks": [
            {"id": "OWASP Top 10", "name": "OWASP Top 10", "version": "2021", "description": "Standard for web application security"},
            {"id": "NIST CSF", "name": "NIST CSF", "version": "2.0", "description": "Cybersecurity Framework"},
            {"id": "SOC2", "name": "SOC 2", "version": "2017", "description": "Service Organization Control 2"},
            {"id": "PCI-DSS", "name": "PCI DSS", "version": "4.0", "description": "Payment Card Industry Data Security Standard"},
        ],
        "project_id": project_id,
    }


@app.get("/api/auto-select/agents")
async def get_auto_select_agents():
    """Get all available vulnerability-to-agent mappings for auto-selection."""
    return {
        "vulnerabilities": VULN_TO_AGENTS,
        "agents": AGENT_INFO,
    }


class AutoSelectRequest(BaseModel):
    vulnerability_type: str
    project_id: str | None = None
    auto_run: bool = False  # If true, automatically run the recommended agent


@app.post("/api/auto-select/recommend")
async def get_agent_recommendation(req: AutoSelectRequest):
    """Get the best agent recommendation for a vulnerability type."""
    vuln_type = req.vulnerability_type.lower().replace(" ", "_").replace("-", "_")
    
    if vuln_type not in VULN_TO_AGENTS:
        # Try to find a close match
        available = list(VULN_TO_AGENTS.keys())
        return {
            "status": "error",
            "message": f"Unknown vulnerability type: {req.vulnerability_type}",
            "available_types": available,
        }
    
    mapping = VULN_TO_AGENTS[vuln_type]
    primary_agent_info = AGENT_INFO.get(mapping["primary"], {})
    
    secondary_agents_info = []
    for sec_agent in mapping.get("secondary", []):
        if sec_agent in AGENT_INFO:
            secondary_agents_info.append(AGENT_INFO[sec_agent])
    
    return {
        "status": "success",
        "vulnerability_type": vuln_type,
        "recommendation": {
            "primary_agent": mapping["primary"],
            "primary_agent_info": primary_agent_info,
            "secondary_agents": mapping.get("secondary", []),
            "secondary_agents_info": secondary_agents_info,
            "description": mapping.get("description", ""),
            "owasp_categories": mapping.get("owasp", []),
            "severity": mapping.get("severity", "high"),
            "payloads": mapping.get("payloads", [])[:5],  # Return first 5 payloads
            "indicators": mapping.get("indicators", []),
        },
        "auto_run": req.auto_run,
    }


class DetectAndRecommendRequest(BaseModel):
    indicators: list[str]  # List of detected indicators (e.g., ["sql_error", "auth_bypass"])
    project_id: str | None = None
    context: dict | None = None  # Additional context about the detected issue


@app.post("/api/auto-select/detect-and-recommend")
async def detect_vulnerability_and_recommend(req: DetectAndRecommendRequest):
    """Given detected indicators, recommend the best agent and suggest next steps."""
    indicators = [ind.lower() for ind in req.indicators]
    
    # Match indicators to vulnerability types
    matched_vulns = []
    for vuln_type, mapping in VULN_TO_AGENTS.items():
        vuln_indicators = [ind.lower() for ind in mapping.get("indicators", [])]
        matches = set(indicators) & set(vuln_indicators)
        if matches:
            matched_vulns.append({
                "vuln_type": vuln_type,
                "match_count": len(matches),
                "matched_indicators": list(matches),
                "severity": mapping.get("severity", "high"),
            })
    
    # Sort by match count and severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matched_vulns.sort(key=lambda x: (-x["match_count"], severity_order.get(x["severity"], 99)))
    
    if not matched_vulns:
        return {
            "status": "no_match",
            "message": "No matching vulnerability type found for the given indicators",
            "indicators": indicators,
            "suggestion": "Consider running a general API security scan or threat intelligence gathering",
        }
    
    # Get recommendation for top match
    top_vuln = matched_vulns[0]
    vuln_type = top_vuln["vuln_type"]
    mapping = VULN_TO_AGENTS[vuln_type]
    primary_agent_info = AGENT_INFO.get(mapping["primary"], {})
    
    return {
        "status": "success",
        "detected_vulnerability": vuln_type,
        "match_confidence": "high" if top_vuln["match_count"] >= 2 else "medium",
        "matched_indicators": top_vuln["matched_indicators"],
        "alternative_matches": matched_vulns[1:3] if len(matched_vulns) > 1 else [],
        "recommendation": {
            "primary_agent": mapping["primary"],
            "primary_agent_info": primary_agent_info,
            "secondary_agents": mapping.get("secondary", []),
            "description": mapping.get("description", ""),
            "owasp_categories": mapping.get("owasp", []),
            "severity": mapping.get("severity", "high"),
            "suggested_payloads": mapping.get("payloads", [])[:3],
        },
        "project_id": req.project_id,
    }


@app.post("/api/auto-select/run-recommended")
async def run_recommended_agent(req: AutoSelectRequest):
    """Run the recommended agent for a vulnerability type."""
    vuln_type = req.vulnerability_type.lower().replace(" ", "_").replace("-", "_")
    
    if vuln_type not in VULN_TO_AGENTS:
        return {
            "status": "error",
            "message": f"Unknown vulnerability type: {req.vulnerability_type}",
        }
    
    mapping = VULN_TO_AGENTS[vuln_type]
    recommended_agent = mapping["primary"]
    
    if not req.project_id:
        return {
            "status": "error",
            "message": "project_id is required to run an agent",
        }
    
    project = memory_engine.load_project(req.project_id)
    if project is None:
        return {
            "status": "error",
            "message": f"Project not found: {req.project_id}",
        }
    
    try:
        # Map agent type to API endpoint path
        agent_endpoint_map = {
            "api_security": "api-security",
            "threat_intelligence": "threat-intelligence",
            "security_operations": "security-operations",
            "adaptive_defense": "adaptive-defense",
            "supply_chain": "supply-chain",
        }
        
        endpoint = agent_endpoint_map.get(recommended_agent)
        if not endpoint:
            return {
                "status": "error",
                "message": f"No endpoint mapped for agent: {recommended_agent}",
            }
        
        # Prepare input data with vulnerability-specific context
        input_data = {
            "scope": req.context or {},
            "vulnerability_type": vuln_type,
            "recommended_payloads": mapping.get("payloads", [])[:5],
            "indicators": mapping.get("indicators", []),
        }
        
        return {
            "status": "prepared",
            "agent": recommended_agent,
            "endpoint": f"/api/projects/{req.project_id}/agents/{endpoint}",
            "input_data": input_data,
            "message": f"Prepared {recommended_agent} agent for {vuln_type}. Submit the input_data to the endpoint to execute.",
        }
    except Exception as e:
        logger.error("run_recommended_agent_error", error=str(e), vuln_type=vuln_type, exc_info=True)
        return {
            "status": "error",
            "message": str(e),
        }


# ============ BURP SUITE INTEGRATION ============

class BurpConnectRequest(BaseModel):
    proxy_url: str = "http://localhost:8080"
    api_key: str | None = None


class BurpHistoryRequest(BaseModel):
    proxy_url: str = "http://localhost:8080"
    api_key: str | None = None
    limit: int = 100


@app.post("/api/burp/connect")
async def burp_connect(req: BurpConnectRequest):
    """Test connection to Burp Suite REST API."""
    import httpx
    
    try:
        headers = {}
        if req.api_key:
            headers["Authorization"] = f"Bearer {req.api_key}"
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            test_url = f"{req.proxy_url.rstrip('/')}/v0.1/scan"
            response = await client.get(test_url, headers=headers)
            
            if response.status_code == 200:
                return {"status": "ok", "message": "Connected to Burp Suite Professional successfully", "version": response.text.strip('"'), "edition": "professional"}
            elif response.status_code == 401:
                return {"status": "error", "error": "Authentication failed. Check your API key.", "edition": "professional"}
            else:
                return {"status": "error", "error": f"Unexpected response: {response.status_code}", "edition": "professional"}
    except httpx.ConnectError:
        return {
            "status": "info",
            "edition": "community",
            "message": "Burp Suite Community Edition detected. Use 'Upload JSON Export' to import proxy history.",
            "hint": "In Burp Suite: Proxy > HTTP History > Export > JSON format",
            "upstream_proxy": req.proxy_url
        }
    except httpx.TimeoutException:
        return {"status": "error", "error": "Connection timed out. Burp Suite may be unresponsive.", "edition": "community"}
    except Exception as e:
        return {"status": "error", "error": str(e), "edition": "community"}


@app.post("/api/burp/history")
async def burp_history(req: BurpHistoryRequest):
    """Fetch HTTP proxy history from Burp Suite."""
    import requests
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
    
    headers = {"Accept": "application/json"}
    if req.api_key:
        headers["Authorization"] = f"Bearer {req.api_key}"
    
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.5)
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))
    
    try:
        history_url = f"{req.proxy_url.rstrip('/')}/v0.1/proxy/history"
        params = {"limit": req.limit}
        response = session.get(history_url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            try:
                history = response.json()
                return {"status": "ok", "history": history, "count": len(history) if isinstance(history, list) else 0}
            except Exception:
                return {"status": "ok", "raw": response.text, "count": 1}
        elif response.status_code == 401:
            return {"status": "error", "error": "Authentication failed. Check your API key."}
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}: {response.text[:200]}"}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "error": f"Could not connect to Burp Suite at {req.proxy_url}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/burp/scan")
async def burp_scan(req: BurpHistoryRequest):
    """Analyze Burp Suite history and create findings for AI analysis."""
    import requests
    
    headers = {"Accept": "application/json"}
    if req.api_key:
        headers["Authorization"] = f"Bearer {req.api_key}"
    
    try:
        history_url = f"{req.proxy_url.rstrip('/')}/v0.1/proxy/history"
        params = {"limit": req.limit}
        response = requests.get(history_url, headers=headers, params=params, timeout=10)
        
        if response.status_code != 200:
            return {"status": "error", "error": f"Failed to fetch history: HTTP {response.status_code}"}
        
        history = response.json() if response.headers.get("content-type", "").startswith("application/json") else []
        
        findings = []
        for item in (history if isinstance(history, list) else []):
            url = item.get("url", "")
            method = item.get("method", "GET")
            response_code = item.get("responseCode", 0)
            
            if response_code >= 400:
                findings.append({"type": "error_response", "url": url, "method": method, "code": response_code})
            if "/api/" in url.lower() or "/rest/" in url.lower():
                findings.append({"type": "api_endpoint", "url": url, "method": method})
            if "authorization" in str(item.get("request", {})).lower() or "bearer" in str(item.get("request", {})).lower():
                findings.append({"type": "auth_header_found", "url": url, "method": method})
        
        return {
            "status": "ok",
            "scan_summary": {
                "total_requests": len(history) if isinstance(history, list) else 0,
                "api_endpoints": len([f for f in findings if f["type"] == "api_endpoint"]),
                "error_responses": len([f for f in findings if f["type"] == "error_response"]),
                "auth_headers": len([f for f in findings if f["type"] == "auth_header_found"]),
            },
            "findings": findings[:20],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ============ INPUT HANDLERS ============

class URLsInputRequest(BaseModel):
    urls: list[str]
    project_id: str | None = None


@app.post("/api/input/urls")
async def process_urls(req: URLsInputRequest):
    """Process URLs for web vulnerability analysis."""
    import httpx
    from bs4 import BeautifulSoup
    
    results = []
    for url in req.urls[:10]:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
                response = await client.get(url)
                
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a.get('href', '') for a in soup.find_all('a', href=True)][:20]
                forms = []
                for form in soup.find_all('form'):
                    form_data = {
                        "action": form.get('action', ''),
                        "method": form.get('method', 'get').upper(),
                        "inputs": [{"name": inp.get('name', ''), "type": inp.get('type', 'text'), "id": inp.get('id', '')} 
                                   for inp in form.find_all('input')[:10]]
                    }
                    forms.append(form_data)
                
                results.append({
                    "url": url,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "links_found": len(links),
                    "forms_found": len(forms),
                    "forms": forms[:5],
                    "technologies": detect_technologies(response.headers, response.text),
                })
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    
    return {
        "status": "ok",
        "results": results,
        "count": len(results),
    }


def detect_technologies(headers: dict, html: str) -> dict:
    """Simple technology detection from headers and HTML."""
    tech = {}
    server = headers.get("server", "").lower()
    if "nginx" in server:
        tech["web_server"] = "nginx"
    elif "apache" in server:
        tech["web_server"] = "apache"
    elif "iis" in server:
        tech["web_server"] = "IIS"
    
    if "x-powered-by" in headers:
        tech["backend"] = headers["x-powered-by"]
    
    if "wordpress" in html.lower():
        tech["cms"] = "WordPress"
    elif "drupal" in html.lower():
        tech["cms"] = "Drupal"
    elif "joomla" in html.lower():
        tech["cms"] = "Joomla"
    
    if "react" in html.lower() or "create-react-app" in html.lower():
        tech["frontend"] = "React"
    elif "vue" in html.lower() or "vue.js" in html.lower():
        tech["frontend"] = "Vue.js"
    elif "angular" in html.lower():
        tech["frontend"] = "Angular"
    
    return tech


class FolderScanRequest(BaseModel):
    folder_path: str
    project_id: str | None = None
    file_types: list[str] | None = None


@app.post("/api/input/folder")
async def scan_folder(req: FolderScanRequest):
    """Scan a folder for source code files."""
    import os
    
    supported_extensions = req.file_types or [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sql", ".cs", ".c", ".cpp", ".h", ".hpp"]
    
    if not os.path.exists(req.folder_path):
        return {"status": "error", "error": f"Folder not found: {req.folder_path}"}
    
    if not os.path.isdir(req.folder_path):
        return {"status": "error", "error": f"Path is not a directory: {req.folder_path}"}
    
    files_found = []
    total_size = 0
    
    for root, dirs, files in os.walk(req.folder_path):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.idea']]
        
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in supported_extensions:
                filepath = os.path.join(root, filename)
                try:
                    size = os.path.getsize(filepath)
                    total_size += size
                    rel_path = os.path.relpath(filepath, req.folder_path)
                    files_found.append({
                        "path": rel_path,
                        "full_path": filepath,
                        "extension": ext,
                        "size_bytes": size,
                    })
                except Exception:
                    pass
    
    files_found.sort(key=lambda x: x["size_bytes"], reverse=True)
    
    return {
        "status": "ok",
        "folder": req.folder_path,
        "files_found": len(files_found),
        "total_size_bytes": total_size,
        "files": files_found[:50],
        "extensions": {ext: len([f for f in files_found if f["extension"] == ext]) for ext in supported_extensions},
    }


class PromptsInputRequest(BaseModel):
    prompt: str
    project_id: str | None = None
    context: dict | None = None


@app.post("/api/input/prompts")
async def process_prompt(req: PromptsInputRequest):
    """Process security testing prompts through AI."""
    if llm_router is None:
        return {"status": "error", "error": "LLM router not initialized. Please configure a provider in Settings."}
    
    from .providers import LLMMessage, MessageRole
    
    try:
        system_context = "You are SENTINEL-X, an autonomous security analysis assistant. Provide concise, actionable security guidance."
        
        messages = [
            LLMMessage(role=MessageRole.SYSTEM, content=system_context),
            LLMMessage(role=MessageRole.USER, content=req.prompt),
        ]
        
        if req.context:
            context_str = f"\nContext: {json.dumps(req.context)}"
            messages[1] = LLMMessage(role=MessageRole.USER, content=req.prompt + context_str)
        
        response = await llm_router.complete(messages, max_tokens=2000)
        
        return {
            "status": "ok",
            "response": response.content,
            "latency_ms": response.latency_ms,
        }
    except Exception as e:
        logger.error("prompt_processing_error", error=str(e))
        return {"status": "error", "error": str(e)}


@app.post("/api/input/code")
async def analyze_input_code(req: CodeAnalysisRequest):
    """Analyze code submitted through input sources."""
    project_id = req.file_path.split("/")[0] if "/" in req.file_path else "default"
    
    if project_id not in code_analyzers:
        code_analyzers[project_id] = CodeAnalyzer(project_id)
    
    analyzer = code_analyzers[project_id]
    patterns = analyzer.analyze_file(req.file_path, req.code, req.language)
    data_flows = analyzer.analyze_data_flow(req.file_path, req.code)
    auth_flows = [analyzer.analyze_auth_flow(req.file_path, req.code)]
    
    return {
        "status": "ok",
        "file_path": req.file_path,
        "patterns": [p.to_dict() for p in patterns],
        "data_flows": [f.to_dict() for f in data_flows],
        "summary": {
            "patterns_found": len(patterns),
            "critical": len([p for p in patterns if p.severity.value == "critical"]),
            "high": len([p for p in patterns if p.severity.value == "high"]),
            "data_flows": len(data_flows),
            "unsafe_flows": len([f for f in data_flows if not f.is_safe]),
        },
    }


# ============ BUG BOUNTY PROGRAM INTEGRATION ============

from .project_context import ProjectContext, BugBountyProgram, get_owasp_top10_prompt, get_bug_bounty_context_prompt

# Initialize project context
project_context = ProjectContext(settings.storage.base_path / "context")


class BugBountyProgramRequest(BaseModel):
    program_url: str
    platform: str = "hackerone"


@app.post("/api/projects/{project_id}/bugbounty")
async def save_bug_bounty_program(project_id: str, req: BugBountyProgramRequest):
    """Save bug bounty program information from a URL"""
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    
    try:
        # Create program info from URL
        program = BugBountyProgram(
            platform=req.platform,
            program_url=req.program_url,
            in_scope=[],
            out_of_scope=[]
        )
        
        # Fetch program info from the platform
        import httpx
        if req.platform.lower() == "hackerone" and "hackerone.com" in req.program_url:
            # Extract program handle from URL
            program_handle = req.program_url.split("/programs/")[-1].split("/")[0] if "/programs/" in req.program_url else None
            if program_handle:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    # Try to fetch public program data
                    try:
                        api_url = f"https://api.hackerone.com/v1/reports/{program_handle}"
                        # This would need authentication for full access
                    except Exception:
                        pass
        
        # Save to project context
        project_context.save_bug_bounty_program(project_id, program)
        
        return {
            "status": "ok",
            "message": f"Bug bounty program saved: {req.platform}",
            "program_url": req.program_url
        }
    except Exception as e:
        logger.error("bug_bounty_save_error", error=str(e))
        return {"status": "error", "error": str(e)}


@app.get("/api/projects/{project_id}/bugbounty")
async def get_bug_bounty_program(project_id: str):
    """Get bug bounty program info for a project"""
    program = project_context.get_bug_bounty_program(project_id)
    if program:
        return program.model_dump()
    return None


@app.get("/api/projects/{project_id}/owasp-context")
async def get_owasp_context(project_id: str):
    """Get OWASP Top 10 knowledge for agents"""
    program = project_context.get_bug_bounty_program(project_id)
    context_prompt = get_owasp_top10_prompt()
    
    if program:
        context_prompt += "\n\n" + get_bug_bounty_context_prompt(program)
    
    return {
        "owasp_knowledge": context_prompt,
        "has_program": program is not None
    }

async def get_agent_memory(project_id: str, agent_type: str):
    """Get agent's memory and model used"""
    memory = project_context.get_agent_memory(project_id, agent_type)
    model = project_context.get_agent_model(project_id, agent_type)
    return {
        "model": model,
        "memory": memory.model_dump() if memory else None
    }


@app.post("/api/projects/{project_id}/agent-memory/{agent_type}")
async def save_agent_memory(project_id: str, agent_type: str, req: dict):
    """Save agent's memory (model, successful payloads, etc.)"""
    from .project_context import AgentMemory
    
    if "model" in req:
        project_context.update_agent_model(project_id, agent_type, req["model"])
    
    if "successful_payload" in req:
        project_context.add_successful_payload(project_id, agent_type, req["successful_payload"])
    
    return {"status": "ok", "agent_type": agent_type, "project_id": project_id}


@app.get("/api/projects/{project_id}/agent-models")
async def get_all_project_agent_models(project_id: str):
    """Get all saved agent models for a project"""
    models = project_context.get_all_agent_models(project_id)
    return {"agents": models}


@app.post("/api/burp/proxy-start")
async def start_burp_proxy(req: dict):
    """
    Start Burp Suite Community Edition proxy mode.
    
    This endpoint configures SENTINEL-X to act as an upstream proxy to Burp Suite,
    allowing the AI to read and analyze traffic in real-time.
    """
    proxy_host = req.get("proxy_host", "localhost")
    proxy_port = req.get("proxy_port", 8080)
    burp_host = req.get("burp_host", "localhost")
    burp_port = req.get("burp_port", 8080)
    
    return {
        "status": "ok",
        "mode": "community_proxy",
        "upstream_proxy": f"{proxy_host}:{proxy_port}",
        "burp_target": f"{burp_host}:{burp_port}",
        "message": "Configure your browser to use SENTINEL-X as proxy, which forwards to Burp Suite Community"
    }


@app.get("/api/burp/proxy-status")
async def get_burp_proxy_status():
    """Get current Burp Suite proxy status"""
    return {
        "mode": "community_proxy",
        "info": "SENTINEL-X can proxy traffic to Burp Suite Community Edition. Configure browser proxy to localhost:8888 -> Burp Suite localhost:8080",
        "hint": "Start Burp Suite with: java -jar burp.jar --user-config-file=project_config.json"
    }

# ============ BURP SUITE PROXY ENDPOINTS (Real-Time Analysis) ============

class BurpProxyRequest(BaseModel):
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] | None = None
    body: str | None = None
    upstream_proxy: str = "http://localhost:8080"


@app.post("/api/burp/proxy-request")
async def burp_proxy_request(req: BurpProxyRequest):
    """Forward request through Burp Suite proxy for analysis."""
    from .burp_proxy import BurpProxyAnalyzer
    
    analyzer = BurpProxyAnalyzer(upstream_proxy=req.upstream_proxy)
    headers = req.headers or {}
    
    result = await analyzer.analyze_request(
        method=req.method,
        url=req.target_url,
        headers=headers,
        body=req.body
    )
    
    return {"status": "ok", "analysis": result}


@app.post("/api/burp/proxy-analyze")
async def burp_proxy_analyze(req: BurpProxyRequest):
    """Analyze a request/response pair through Burp Suite proxy."""
    from .burp_proxy import BurpProxyAnalyzer
    import httpx
    
    analyzer = BurpProxyAnalyzer(upstream_proxy=req.upstream_proxy)
    headers = req.headers or {}
    
    # Analyze request (always succeeds - local analysis)
    request_analysis = await analyzer.analyze_request(
        method=req.method,
        url=req.target_url,
        headers=headers,
        body=req.body
    )
    
    # Try to get response - if Burp Suite isn't running, just return analysis without response
    response_analysis = None
    try:
        # Try direct request first (may work even without Burp)
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            response = await client.request(
                method=req.method,
                url=req.target_url,
                headers=headers,
                content=req.body
            )
            response_analysis = await analyzer.analyze_response(
                url=req.target_url,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text
            )
    except httpx.TimeoutException:
        response_analysis = {"error": "Request timed out - target may be unreachable"}
    except httpx.ConnectError:
        response_analysis = {"error": f"Could not connect to {req.target_url} - check if target is running"}
    except Exception as e:
        response_analysis = {"error": str(e)}
    
    return {
        "status": "ok",
        "request_analysis": request_analysis,
        "response_analysis": response_analysis,
        "summary": analyzer.get_summary()
    }


@app.get("/api/burp/proxy-summary")
async def get_burp_proxy_summary(upstream_proxy: str = "http://localhost:8080"):
    """Get summary of all proxied requests."""
    from .burp_proxy import BurpProxyAnalyzer
    
    analyzer = BurpProxyAnalyzer(upstream_proxy=upstream_proxy)
    return analyzer.get_summary()






@app.get("/api/burp/formats")
async def burp_formats():
    """Get supported Burp Suite export formats."""
    return {
        "formats": [
            {
                "format": "json",
                "name": "JSON (HTTP History)",
                "description": "Standard JSON export from Burp Suite Proxy HTTP History",
                "edition": "community_and_professional",
                "steps": [
                    "1. Go to Proxy > HTTP History tab",
                    "2. Select requests (Ctrl+A for all)",
                    "3. Click 'Export' button",
                    "4. Choose 'JSON' format",
                    "5. Save and upload here"
                ]
            }
        ],
        "note": "Community Edition users: The JSON export is available in all Burp Suite editions"
    }


# ============ INPUT HANDLERS ============

class URLsInputRequest(BaseModel):
    urls: list[str]
    project_id: str | None = None


@app.post("/api/input/folder")
async def scan_folder(req: FolderScanRequest):
    """Scan a folder for source code files."""
    import os
    
    supported_extensions = req.file_types or [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sql", ".cs", ".c", ".cpp", ".h", ".hpp"]
    
    if not os.path.exists(req.folder_path):
        return {"status": "error", "error": f"Folder not found: {req.folder_path}"}
    
    if not os.path.isdir(req.folder_path):
        return {"status": "error", "error": f"Path is not a directory: {req.folder_path}"}
    
    files_found = []
    total_size = 0
    
    for root, dirs, files in os.walk(req.folder_path):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', 'venv', '.venv', 'dist', 'build', '.idea']]
        
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in supported_extensions:
                filepath = os.path.join(root, filename)
                try:
                    size = os.path.getsize(filepath)
                    total_size += size
                    rel_path = os.path.relpath(filepath, req.folder_path)
                    files_found.append({
                        "path": rel_path,
                        "full_path": filepath,
                        "extension": ext,
                        "size_bytes": size,
                    })
                except Exception:
                    pass
    
    files_found.sort(key=lambda x: x["size_bytes"], reverse=True)
    
    return {
        "status": "ok",
        "folder": req.folder_path,
        "files_found": len(files_found),
        "total_size_bytes": total_size,
        "files": files_found[:50],
        "extensions": {ext: len([f for f in files_found if f["extension"] == ext]) for ext in supported_extensions},
    }


class PromptsInputRequest(BaseModel):
    prompt: str
    project_id: str | None = None
    context: dict | None = None


@app.post("/api/input/prompts")
async def process_prompt(req: PromptsInputRequest):
    """Process security testing prompts through AI."""
    if llm_router is None:
        return {"status": "error", "error": "LLM router not initialized. Please configure a provider in Settings."}
    
    from .providers import LLMMessage, MessageRole
    
    try:
        system_context = "You are SENTINEL-X, an autonomous security analysis assistant. Provide concise, actionable security guidance."
        
        messages = [
            LLMMessage(role=MessageRole.SYSTEM, content=system_context),
            LLMMessage(role=MessageRole.USER, content=req.prompt),
        ]
        
        if req.context:
            context_str = f"\nContext: {json.dumps(req.context)}"
            messages[1] = LLMMessage(role=MessageRole.USER, content=req.prompt + context_str)
        
        response = await llm_router.complete(messages, max_tokens=2000)
        
        return {
            "status": "ok",
            "response": response.content,
            "latency_ms": response.latency_ms,
        }
    except Exception as e:
        logger.error("prompt_processing_error", error=str(e))
        return {"status": "error", "error": str(e)}


@app.post("/api/input/code")
async def analyze_input_code(req: CodeAnalysisRequest):
    """Analyze code submitted through input sources."""
    project_id = req.file_path.split("/")[0] if "/" in req.file_path else "default"
    
    if project_id not in code_analyzers:
        code_analyzers[project_id] = CodeAnalyzer(project_id)
    
    analyzer = code_analyzers[project_id]
    patterns = analyzer.analyze_file(req.file_path, req.code, req.language)
    data_flows = analyzer.analyze_data_flow(req.file_path, req.code)
    auth_flows = [analyzer.analyze_auth_flow(req.file_path, req.code)]
    
    return {
        "status": "ok",
        "file_path": req.file_path,
        "patterns": [p.to_dict() for p in patterns],
        "data_flows": [f.to_dict() for f in data_flows],
        "summary": {
            "patterns_found": len(patterns),
            "critical": len([p for p in patterns if p.severity.value == "critical"]),
            "high": len([p for p in patterns if p.severity.value == "high"]),
            "data_flows": len(data_flows),
            "unsafe_flows": len([f for f in data_flows if not f.is_safe]),
        },
    }

@app.get("/api/projects/{project_id}/agents")
async def list_agents(project_id: str):
    """List all available agents for a project."""
    return {
        "agents": [
            {"type": "recon", "name": "Reconnaissance Agent", "description": "Target discovery and OSINT", "phase": 3},
            {"type": "code_review", "name": "Code Review Agent", "description": "SAST with deep code analysis", "phase": 3},
            {"type": "threat_modeling", "name": "Threat Modeling Agent", "description": "Attack path analysis", "phase": 3},
            {"type": "dependency", "name": "Dependency Agent", "description": "Vulnerability scanning", "phase": 3},
            {"type": "debate", "name": "Debate Engine", "description": "5-role adversarial validation", "phase": 3},
            {"type": "remediation", "name": "Remediation Agent", "description": "Automated remediation planning", "phase": 4},
            {"type": "threat_intelligence", "name": "Threat Intelligence Agent", "description": "YARA rules, IOC enrichment, threat hunting", "phase": 5},
            {"type": "security_operations", "name": "Security Operations Agent", "description": "SIEM, SOAR, continuous monitoring", "phase": 5},
            {"type": "adaptive_defense", "name": "Adaptive Defense Agent", "description": "ML anomaly detection, self-healing", "phase": 5},
            {"type": "supply_chain", "name": "Supply Chain Agent", "description": "SBOM, dependency analysis, license compliance", "phase": 5},
            {"type": "api_security", "name": "API Security Agent", "description": "OpenAPI analysis, fuzzing, rate limiting", "phase": 5},
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


# ============ EXTERNAL TOOL INTEGRATION (Gobuster, Nmap, etc.) ============

class ToolRunRequest(BaseModel):
    tool_name: str
    target: str
    mode: str | None = None
    parameters: Dict[str, Any] | None = None


class GobusterScanRequest(BaseModel):
    target: str  # URL or domain
    mode: str = "dir"  # dir, dns, vhost
    wordlist: str | None = None
    threads: int = 10
    extensions: str | None = None  # e.g., "php,html,js"
    status_codes: str | None = None  # e.g., "200,204,301,302,401,403"
    user_agent: str | None = None
    timeout: int = 10
    skip_ssl_verify: bool = False
    headers: Dict[str, str] | None = None


@app.get("/api/tools/list")
async def list_tools():
    """List all available external security tools."""
    from .gobuster_tool import get_gobuster_tool
    from .nmap_tool import get_nmap_tool
    from .ffuf_tool import get_ffuf_tool
    
    tools = []
    
    # Gobuster
    gobuster = get_gobuster_tool()
    tools.append({
        "name": gobuster.name,
        "description": "Directory/File/DNS brute-forcing tool written in Go",
        "modes": gobuster.supported_modes,
        "installed": gobuster.is_available(),
        "version": gobuster.get_version() if gobuster.is_available() else "unknown"
    })
    
    # Nmap
    nmap = get_nmap_tool()
    tools.append({
        "name": nmap.name,
        "description": "Network exploration and security auditing tool",
        "scan_types": nmap.supported_scan_types,
        "installed": nmap.is_available(),
        "version": nmap.get_version() if nmap.is_available() else "unknown"
    })
    
    # FFUF
    ffuf = get_ffuf_tool()
    tools.append({
        "name": ffuf.name,
        "description": "Fast web fuzzing tool for directory and subdomain discovery",
        "modes": ffuf.supported_modes,
        "installed": ffuf.is_available(),
        "version": ffuf.get_version() if ffuf.is_available() else "unknown"
    })
    
    return {
        "tools": tools,
        "total": len(tools)
    }


@app.post("/api/tools/gobuster/scan")
async def run_gobuster_scan(req: GobusterScanRequest):
    """Run a gobuster scan."""
    from .gobuster_tool import GobusterTool, GobusterResult, get_gobuster_tool
    import asyncio
    
    scanner = get_gobuster_tool()
    
    if not scanner.is_available():
        return {
            "status": "error",
            "error": "Gobuster is not installed. Install from: https://github.com/OJ/gobuster/releases"
        }
    
    try:
        result = await scanner.scan(
            target=req.target,
            mode=req.mode,
            wordlist=req.wordlist,
            threads=req.threads,
            extensions=req.extensions,
            status_codes=req.status_codes,
            user_agent=req.user_agent,
            timeout=req.timeout,
            headers=req.headers
        )
        
        return {
            "status": "ok",
            "tool": "gobuster",
            "mode": req.mode,
            "target": req.target,
            "findings": result.found,  # result.found is already a list of dicts
            "summary": {
                "total_found": len(result.found),
                "status_codes": result.status_codes,
                "execution_time_seconds": result.execution_time_seconds,
                "wordlist": result.wordlist,
                "errors": result.errors,
            },
            "tool_version": result.tool_version,
            "duration_seconds": result.execution_time_seconds,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@app.get("/api/tools/gobuster/status")
async def gobuster_status():
    """Check gobuster installation status."""
    from .gobuster_tool import get_gobuster_tool
    
    scanner = get_gobuster_tool()
    return {
        "installed": scanner.is_available(),
        "version": scanner.get_version(),
        "suggestion": "Install from: https://github.com/OJ/gobuster/releases" if not scanner.is_available() else None
    }





# ============ NMAP TOOL ENDPOINTS ============

class NmapScanRequest(BaseModel):
    target: str
    scan_type: str = "basic"  # basic, syn, udp, service, os, full
    ports: str | None = None  # e.g., "1-1000", "80,443,8080"
    timing: int = 4  # 0-5 (higher is faster)
    timeout: int = 300
    scripts: bool = False
    os_detection: bool = False
    service_detection: bool = False


@app.get("/api/tools/nmap/status")
async def nmap_status():
    """Check nmap installation status."""
    from .nmap_tool import get_nmap_tool
    
    scanner = get_nmap_tool()
    return {
        "installed": scanner.is_available(),
        "version": scanner.get_version(),
        "suggestion": "Install from: https://nmap.org/download.html" if not scanner.is_available() else None
    }


@app.post("/api/tools/nmap/scan")
async def run_nmap_scan(req: NmapScanRequest):
    """Run an nmap scan."""
    from .nmap_tool import get_nmap_tool
    
    scanner = get_nmap_tool()
    
    if not scanner.is_available():
        return {
            "status": "error",
            "error": "Nmap is not installed or not in PATH",
            "suggestion": "Install from: https://nmap.org/download.html"
        }
    
    try:
        result = await scanner.scan(
            target=req.target,
            scan_type=req.scan_type,
            ports=req.ports,
            timing=req.timing,
            timeout=req.timeout,
            scripts=req.scripts,
            os_detection=req.os_detection,
            service_detection=req.service_detection
        )
        
        return {
            "status": "ok",
            "tool": "nmap",
            "target": result.target,
            "scan_type": result.scan_type,
            "ports_found": len(result.ports),
            "services_found": len(result.services),
            "ports": result.ports[:50],  # Limit to first 50
            "services": result.services[:20],
            "os_detection": result.os_detection,
            "execution_time_seconds": result.execution_time_seconds,
            "tool_version": result.tool_version,
            "errors": result.errors
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# ============ FFUF TOOL ENDPOINTS ============

class FfufScanRequest(BaseModel):
    target: str  # URL or host
    mode: str = "directory"  # directory, subdomain, vhost, parameter
    wordlist: str | None = None
    threads: int = 40
    extensions: str | None = None  # e.g., "php,html,js"
    status_codes: str = "200,204,301,302,307,401,403,500"
    timeout: int = 300
    rate: int = 0  # Requests per second (0 = unlimited)
    follow_redirects: bool = False


@app.get("/api/tools/ffuf/status")
async def ffuf_status():
    """Check ffuf installation status."""
    from .ffuf_tool import get_ffuf_tool
    
    scanner = get_ffuf_tool()
    return {
        "installed": scanner.is_available(),
        "version": scanner.get_version(),
        "suggestion": "Install from: https://github.com/ffuf/ffuf/releases" if not scanner.is_available() else None
    }


@app.post("/api/tools/ffuf/scan")
async def run_ffuf_scan(req: FfufScanRequest):
    """Run an ffuf web fuzzing scan."""
    from .ffuf_tool import get_ffuf_tool
    
    scanner = get_ffuf_tool()
    
    if not scanner.is_available():
        return {
            "status": "error",
            "error": "FFUF is not installed or not in PATH",
            "suggestion": "Install from: https://github.com/ffuf/ffuf/releases"
        }
    
    try:
        result = await scanner.scan(
            target=req.target,
            mode=req.mode,
            wordlist=req.wordlist,
            threads=req.threads,
            extensions=req.extensions,
            status_codes=req.status_codes,
            timeout=req.timeout,
            follow_redirects=req.follow_redirects,
            rate=req.rate
        )
        
        return {
            "status": "ok",
            "tool": "ffuf",
            "target": result.target,
            "mode": result.mode,
            "findings": result.findings,
            "total_found": len(result.findings),
            "status_codes": result.status_codes,
            "requests_sent": result.requests_sent,
            "execution_time_seconds": result.execution_time_seconds,
            "tool_version": result.tool_version,
            "errors": result.errors
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# Update run_tool to handle nmap and ffuf
@app.post("/api/tools/run")
async def run_tool(req: ToolRunRequest):
    """Run any registered tool by name."""
    if req.tool_name == "gobuster":
        return {
            "status": "redirect",
            "endpoint": "/api/tools/gobuster/scan",
            "note": "Use POST /api/tools/gobuster/scan with GobusterScanRequest body"
        }
    elif req.tool_name == "nmap":
        return {
            "status": "redirect",
            "endpoint": "/api/tools/nmap/scan",
            "note": "Use POST /api/tools/nmap/scan with NmapScanRequest body"
        }
    elif req.tool_name == "ffuf":
        return {
            "status": "redirect",
            "endpoint": "/api/tools/ffuf/scan",
            "note": "Use POST /api/tools/ffuf/scan with FfufScanRequest body"
        }
    else:
        return {
            "status": "error",
            "error": f"Unknown tool: {req.tool_name}"
        }



# ===== V3 endpoints (Project Workspace, Terminal, Agent Knowledge) =====
from .v3_endpoints import register_v3_endpoints
v3_managers = register_v3_endpoints(app, settings, memory_engine)

# ============ BUG BOUNTY MULTI-AGENT FRAMEWORK v7.0 ============

class BugBountyPipelineRequest(BaseModel):
    target_url: str = ""
    target_domain: str = ""
    in_scope: list[str] | None = None
    out_of_scope: list[str] | None = None
    program_url: str | None = None  # HackerOne/BugCrowd URL for Agent 1


@app.get("/api/bug-bounty/system-prompt")
async def get_bug_bounty_system_prompt():
    """Get the full bug bounty system prompt (Foundational Principles + Decision Hierarchy + Agent Architecture).
    This is the complete operational framework for professional ethical security research.
    """
    return {
        "system_prompt": get_full_system_prompt(),
        "principles": FOUNDATIONAL_PRINCIPLES,
        "hierarchy": DECISION_HIERARCHY,
        "architecture": AGENT_ARCHITECTURE,
        "agent_count": 10,
        "version": "7.0",
    }


@app.get("/api/bug-bounty/agents")
async def list_bug_bounty_agents():
    """List all 10 bug bounty agents with their descriptions."""
    return {
        "agents": [
            {"id": 1, "name": "URL Parser Agent", "description": "Parses HackerOne/BugCrowd URLs, extracts program metadata, scope, policy"},
            {"id": 2, "name": "Policy Enforcement Agent", "description": "Gatekeeper - reads program policy, creates vulnerability filtering rules"},
            {"id": 3, "name": "Scope Guardian Agent", "description": "Verifies every action stays within authorized scope boundaries"},
            {"id": 4, "name": "Passive Intelligence Agent", "description": "Non-intrusive reconnaissance using OSINT and third-party data"},
            {"id": 5, "name": "Active Enumeration Agent", "description": "Direct interaction with targets to map attack surface"},
            {"id": 6, "name": "Vulnerability Scanner Agent", "description": "Tests for security flaws using OWASP Top 10 methodology"},
            {"id": 7, "name": "Validation Engine Agent", "description": "Multi-stage validation to eliminate false positives"},
            {"id": 8, "name": "Exploitation Agent", "description": "Creates safe proof-of-concepts with reproducible evidence"},
            {"id": 9, "name": "Analysis Agent", "description": "CVSS scoring, severity assessment, OWASP/CWE mapping"},
            {"id": 10, "name": "Report Generation Agent", "description": "Professional vulnerability reports in Blank.md format"},
        ],
        "total_agents": 10,
    }


@app.get("/api/bug-bounty/ethical-rules")
async def get_ethical_rules():
    """Get the foundational ethical rules that govern all bug bounty operations."""
    return {
        "rules": [
            {"level": 1, "category": "Legal/Ethical", "rules": [
                "NEVER test unauthorized targets",
                "NEVER cause service disruption or data loss",
                "NEVER exfiltrate user data",
                "ALWAYS operate read-only",
                "ALWAYS maintain confidentiality",
            ]},
            {"level": 2, "category": "Vulnerability QA", "rules": [
                "ONLY report REAL vulnerabilities with confirmed exploitation potential",
                "ELIMINATE false positives before reporting",
                "VALIDATE every finding against program policy",
                "CONFIRM reproducibility",
            ]},
            {"level": 3, "category": "Scope Enforcement", "rules": [
                "Scope is law - if not in-scope, it's out-of-scope",
                "Every subdomain cross-checked against scope list",
                "When uncertain: default to blocking",
            ]},
        ],
        "principle": "Lower levels NEVER override higher levels",
    }


@app.post("/api/bug-bounty/pipeline")
async def run_bug_bounty_pipeline(req: BugBountyPipelineRequest):
    """Run the complete 10-agent bug bounty pipeline.

    Uses the Foundational Principles, Decision Hierarchy, and Agent Architecture
    to orchestrate a professional ethical security research workflow.

    Agents run: URL Parser -> Policy Enforcer -> Scope Guardian -> Passive Intel
    -> Active Enum -> Vuln Scanner -> Validation Engine -> Exploitation -> Analysis -> Report
    """
    # Create a fresh orchestrator per request for thread safety
    orch = BugBountyOrchestrator(webhook_manager=bb_webhook_manager)

    try:
        result = await orch.run_pipeline(
            target_url=req.target_url,
            target_domain=req.target_domain,
            in_scope=req.in_scope or [],
            out_of_scope=req.out_of_scope or [],
        )

        summary = orch.get_summary(result)

        # Include policy decisions from the 12-phase Policy Decision Engine
        policy_decisions = getattr(result, "policy_decisions", [])
        policy_summary = summary.get("policy_decisions", {})

        return {
            "status": "completed",
            "pipeline_id": result.pipeline_id,
            "summary": summary,
            "program": result.program_intel.program_name if result.program_intel else None,
            "findings_count": len(result.validation_results),
            "reports_count": len(result.reports),
            "ethical_rules_applied": result.ethical_rules_applied,
            "policy_decisions": policy_decisions,
            "policy_decisions_summary": policy_summary,
            "scope_authorizations": getattr(result, "scope_authorizations", []),
            "scope_authorizations_summary": summary.get("scope_authorizations", {}),
            "osint_intelligence": summary.get("osint_intelligence", {}),
            "downstream_guidance": getattr(result, "downstream_guidance", {}),
            "errors": result.errors[:5] if result.errors else [],
        }
    except Exception as e:
        logger.error("bug_bounty_pipeline_error", error=str(e))
        return {"status": "error", "error": str(e)}



# ============ BUG BOUNTY WEBHOOK ENDPOINTS ============

class WebhookConfigRequest(BaseModel):
    url: str = ""
    enabled: bool = True
    events: list[str] | None = None
    secret: str = ""
    headers: dict[str, str] | None = None
    max_retries: int = 3
    timeout_seconds: int = 10
    rate_limit_max_per_minute: int = 60
    rate_limit_max_per_hour: int = 1000


# Global webhook manager instance (shared across requests)
from .bug_bounty import WebhookManager, WebhookConfig

bb_webhook_manager = WebhookManager()


@app.get("/api/bug-bounty/webhook/config")
async def get_webhook_config():
    """Get the current webhook configuration."""
    config = bb_webhook_manager.get_config()
    return {
        "url": config.url,
        "enabled": config.enabled,
        "events": config.events,
        "has_secret": bool(config.secret),
        "max_retries": config.max_retries,
        "timeout_seconds": config.timeout_seconds,
        "rate_limit_max_per_minute": config.rate_limit_max_per_minute,
        "rate_limit_max_per_hour": config.rate_limit_max_per_hour,
    }


@app.post("/api/bug-bounty/webhook/config")
async def save_webhook_config(req: WebhookConfigRequest):
    """Save webhook configuration."""
    config = WebhookConfig(
        url=req.url,
        enabled=req.enabled,
        events=req.events or ["policy_decision_made", "pipeline_completed"],
        secret=req.secret,
        headers=req.headers or {},
        max_retries=req.max_retries,
        timeout_seconds=req.timeout_seconds,
        rate_limit_max_per_minute=req.rate_limit_max_per_minute,
        rate_limit_max_per_hour=req.rate_limit_max_per_hour,
    )
    bb_webhook_manager.update_config(config)
    return {"status": "ok", "message": "Webhook configuration saved"}


@app.post("/api/bug-bounty/webhook/test")
async def test_webhook():
    """Send a test webhook to verify configuration."""
    delivery = await bb_webhook_manager.test_webhook()
    if delivery:
        return {
            "status": "ok" if delivery.success else "error",
            "delivery_id": delivery.id,
            "success": delivery.success,
            "status_code": delivery.status_code,
            "error": delivery.error,
            "timestamp": delivery.timestamp,
        }
    return {"status": "error", "error": "Webhook not configured or disabled"}


@app.get("/api/bug-bounty/webhook/log")
async def get_webhook_log(limit: int = 20):
    """Get recent webhook delivery log."""
    log = bb_webhook_manager.get_delivery_log(limit=limit)
    return {"deliveries": log, "count": len(log)}


class BugBountyURLParseRequest(BaseModel):
    url: str = ""


class BugBountyPolicyCheckRequest(BaseModel):
    findings: list[dict]


class BugBountyScopeCheckRequest(BaseModel):
    targets: list[str]
    in_scope: list[str] | None = None
    out_of_scope: list[str] | None = None


@app.post("/api/bug-bounty/url-parse")
async def run_url_parser(req: BugBountyURLParseRequest):
    """Run Agent 1: URL Parser. Parses a HackerOne/BugCrowd program URL."""
    agent = URLParserAgent()
    try:
        result = await agent.parse(req.url)
        return {
            "status": "completed",
            "program_name": result.program_name,
            "platform": result.platform,
            "extraction_status": result.extraction_status,
            "extraction_confidence": result.extraction_confidence,
            "program_status": result.program_status,
            "in_scope_domains": result.in_scope_domains[:10],
            "out_of_scope_domains": result.out_of_scope_domains[:5],
            "errors": result.errors,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        await agent.close()


@app.post("/api/bug-bounty/policy-check")
async def run_policy_check(req: BugBountyPolicyCheckRequest):
    """Run Agent 2: Policy Enforcer. Checks findings against program policy."""
    agent = PolicyEnforcerAgent()
    try:
        results = agent.batch_check(req.findings)
        allowed = [r for r in results if r.policy_allowed]
        blocked = [r for r in results if not r.policy_allowed]
        return {
            "status": "completed",
            "total_checked": len(results),
            "allowed": len(allowed),
            "blocked": len(blocked),
            "results": [{"title": r.finding_title, "type": r.finding_type, "allowed": r.policy_allowed, "reason": r.reason} for r in results],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/bug-bounty/scope-check")
async def run_scope_check(req: BugBountyScopeCheckRequest):
    """Run Agent 3: Scope Guardian. Checks targets against scope boundaries."""
    agent = ScopeGuardianAgent()
    try:
        agent.set_scope(req.in_scope or [], req.out_of_scope or [])
        results = agent.batch_check(req.targets)
        in_scope_targets = [t for t, r in zip(req.targets, results) if r.in_scope]
        blocked_targets = [t for t, r in zip(req.targets, results) if not r.in_scope]
        return {
            "status": "completed",
            "total_checked": len(results),
            "in_scope": len(in_scope_targets),
            "blocked": len(blocked_targets),
            "results": [{"target": r.target, "in_scope": r.in_scope, "reason": r.reason} for r in results],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}



# ============ AI REPORT GENERATION ============

class AIReportRequest(BaseModel):
    view: str = "full"  # executive | technical | full
    include_severity: list[str] | None = None  # filter to e.g. ["critical", "high"]


@app.post("/api/projects/{project_id}/report")
async def generate_ai_report(project_id: str, req: AIReportRequest):
    """Have the configured model write a Blank.md report from the project's findings.

    The AI picks the findings it considers worth reporting to the company and
    drafts a professional report in the ZephrFish/BugBountyTemplates/Blank.md shape.
    """
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    findings = list(getattr(project, "findings", []) or [])

    # Optional severity filter
    if req.include_severity:
        wanted = {s.lower() for s in req.include_severity}
        findings = [f for f in findings if str(f.get("severity", "")).lower() in wanted]

    if not findings:
        return {
            "status": "ok",
            "model": None,
        }
    system_prompt = (
        "You are a senior security auditor. You are given a structured list of findings. Your job is to (1) decide which findings are worth reporting to the "
        "company, (2) write a polished Markdown report that includes ONLY those findings and NOTHING ELSE, "
        "(3) add a short Executive Summary, a Technical Summary, a Remediation Summary, and "
        "an overall security score at the bottom. Severity tags, CWE refs, and OWASP Top 10 "
        "references must be preserved when present. CRITICAL: Do NOT fabricate, invent, or hallucinate any findings, vulnerabilities, CVEs, endpoints, or details that are not explicitly present in the supplied list. If the list is empty or contains no actionable items, respond with a brief empty-state report stating no findings were supplied. Be concise, professional, and actionable. Output ONLY "
        "the Markdown - no preamble."
    )
    user_prompt = (
    f"Project: {project.name}\n"
    f"Target: {getattr(project, 'folder', 'unspecified')}\n"
     f"Total findings supplied: {len(findings)}\n"
        f"\1`n"
        f"\1`n"
        "Produce the Blank.md report now."
    )

    if llm_router is None:
        return {
            "status": "error",
            "error": "LLM router not initialized. Configure a provider in Settings first.",
            "findings_count": len(findings),
        }

    from .providers import LLMMessage, MessageRole
    messages = [
        LLMMessage(role=MessageRole.SYSTEM, content=system_prompt),
        LLMMessage(role=MessageRole.USER, content=user_prompt),
    ]
    model_name = settings.models.report
    try:
        response = await llm_router.complete(messages, model_name, max_tokens=4000)
        return {
            "status": "ok",
            "report_markdown": response.content,
            "findings_included": len(findings),
            "model": model_name,
            "latency_ms": getattr(response, "latency_ms", None),
        }
    except Exception as exc:
        logger.error("ai_report_failed", error=str(exc), project_id=project_id)
        raise HTTPException(status_code=500, detail=f"AI report failed: {exc}")



# ============ FULL PROJECT SCAN ============

class FullScanRequest(BaseModel):
    target_url: str | None = None


@app.post("/api/projects/{project_id}/full-scan")
async def full_project_scan(project_id: str, req: FullScanRequest):
    project = memory_engine.load_project(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if llm_router is None:
        raise HTTPException(status_code=503, detail="LLM router not initialized. Configure a provider in Settings first.")

    memory_engine.add_investigation_log({"action": "full_scan_started", "target_url": req.target_url or ""})

    # Seed bug bounty knowledge into the pipeline context so agents
    # operate with the Foundational Principles, Decision Hierarchy,
    # and Agent Architecture from the Bug Bounty v7.0 specification.
    from .bug_bounty import get_full_system_prompt, FOUNDATIONAL_PRINCIPLES, DECISION_HIERARCHY
    pipeline_context = {
        "bug_bounty_system_prompt": get_full_system_prompt(),
        "ethical_rules": [
            "NEVER test unauthorized targets",
            "NEVER cause service disruption or data loss",
            "ALWAYS operate read-only",
            "ALWAYS validate findings before reporting",
            "Scope is law - if not in-scope, it is out-of-scope",
            "Quality over quantity - validate every finding",
        ],
        "decision_hierarchy": (
            "Level 1: Legal/Ethical Boundaries (NEVER violated)\n"
            "Level 2: Program Policy & Scope Enforcement (ALWAYS applied)\n"
            "Level 3: Vulnerability Validation Requirements (STRICTLY enforced)\n"
            "Level 4: Report Quality & Professionalism (MAINTAINED)\n"
            "Level 5: Efficiency & Optimization (ADJUSTED)"
        ),
    }
    memory_engine.add_investigation_log({
        "action": "bug_bounty_knowledge_seeded",
        "context_keys": list(pipeline_context.keys()),
    })
    memory_engine.save_project(project)

    pipeline = [
        ("recon", {"action": "discover", "input_data": {"scope": {"domains": [getattr(project, "folder", "")] or ["example.com"]}, "target_url": req.target_url}}),
        ("code-review", {"action": "analyze", "input_data": {"scope": "full"}}),
        ("threat-modeling", {"action": "analyze", "input_data": {"scope": "full"}}),
        ("dependency", {"action": "scan", "input_data": {"scope": "full"}}),
        ("debate", {"action": "validate", "input_data": {}}),
    ]

    results = []
    findings_total = 0
    started_at = __import__("datetime").datetime.utcnow().isoformat() + "Z"

    for agent_name, payload in pipeline:
        step_start = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        step = {"agent": agent_name, "status": "running", "started_at": step_start}
        try:
            agent = _get_or_create_agent(project_id, agent_name)
            before = len(getattr(agent, "findings", []) or [])
            task = TaskPayload(task_id=str(uuid.uuid4()), task_type=agent_name, input_data=payload.get("input_data", {}))
            result = await agent.execute_task(task)
            after = len(getattr(agent, "findings", []) or [])
            created = max(0, after - before)
            findings_total += created
            step.update({"status": "completed", "findings_created": created, "completed_at": __import__("datetime").datetime.utcnow().isoformat() + "Z"})
            memory_engine.add_investigation_log({"action": f"{agent_name}_completed", "findings": created})
        except Exception as exc:
            step.update({"status": "error", "error": str(exc)[:200]})
            memory_engine.add_investigation_log({"action": f"{agent_name}_failed", "error": str(exc)[:200]})
        results.append(step)

    memory_engine.add_investigation_log({"action": "full_scan_completed", "findings_total": findings_total, "agents_run": len(pipeline)})
    return {
        "status": "ok",
        "project_id": project_id,
        "target_url": req.target_url,
        "started_at": started_at,
        "completed_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "agents_run": len(pipeline),
        "findings_total": findings_total,
        "no_findings": findings_total == 0,
        "results": results,
    }
