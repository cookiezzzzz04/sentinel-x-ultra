# SENTINEL-X ULTRA — Implementation Plan & Specification
## Version 2.0 — Production-Grade Security Analysis Framework

---

## 1. VISION & SCOPE

**Mission:** Build the most accurate and insightful AI-powered security analysis system that combines code review (SAST) and web application pentesting in a unified, agent-based architecture.

**Core Philosophy:**
- Model systems deeply before concluding
- Retrieve evidence before reasoning
- Validate before reporting
- Correlate findings into attack chains
- Never invent or exaggerate findings

**Key Features:**
1. CLI launcher → local web server → browser-based UI
2. Full provider abstraction (OpenAI, Anthropic, Ollama, LM Studio, vLLM, etc.)
3. Multi-agent orchestration with 14 specialized agents
4. RAG-powered knowledge graph for evidence-grounded reasoning
5. 5-agent Debate Engine for finding validation
6. SAST + web app pentesting capabilities
7. Structured report generation

---

## 2. ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL-X ULTRA                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌────────────────────────────────────────┐  │
│  │   CLI       │───▶│         Web Server (FastAPI)           │  │
│  │   Launcher  │    │  ┌─────────┐  ┌─────────┐  ┌─────────┐ │  │
│  └─────────────┘    │  │   UI    │  │  API    │  │  WS     │ │  │
│                     │  │ (React) │  │Endpoint │  │RealTime │ │  │
│                     │  └────┬────┘  └────┬────┘  └────┬────┘ │  │
│                     └───────┼────────────┼────────────┼──────┘  │
│                             │            │            │         │
│  ┌──────────────────────────┴────────────┴────────────┴───────┐ │
│  │                    AGENT ORCHESTRATION LAYER                 │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐│ │
│  │  │  Recon  │ │  Code   │ │ Threat  │ │Business │ │ Debat  ││ │
│  │  │  Agent  │ │ Review  │ │Modeling │ │  Logic  │ │ Engine ││ │
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └───┬────┘│ │
│  │       │           │           │           │          │     │ │
│  │  ┌────┴───────────┴───────────┴───────────┴──────────┴────┐│ │
│  │  │              MESSAGE BUS (Redis / In-Memory)            ││ │
│  │  └─────────────────────────────────────────────────────────┘│ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                    PROVIDER ABSTRACTION LAYER                 │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │ │
│  │  │ OpenAI   │ │ Anthropic│ │  Ollama  │ │ vLLM     │ ...    │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │ │
│  └──────────────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                    CORE SERVICES                              │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │ │
│  │  │  RAG     │ │ Knowledge│ │ Permission│ │ Report   │        │ │
│  │  │ Engine   │ │  Graph   │ │  Graph   │ │ Engine   │        │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │ │
│  └──────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. PROJECT STRUCTURE

```
sentinel-x-ultra/
├── cli/                          # CLI entry point
│   ├── __init__.py
│   ├── main.py                   # CLI launcher
│   └── commands/
│       ├── start.py              # Start server command
│       └── analyze.py            # Analyze command (headless)
├── server/                       # FastAPI web server
│   ├── __init__.py
│   ├── app.py                    # FastAPI application
│   ├── api/
│   │   ├── routes/
│   │   │   ├── analysis.py       # Analysis endpoints
│   │   │   ├── projects.py       # Project management
│   │   │   ├── models.py         # Model configuration
│   │   │   └── scope.py          # Scope management
│   │   ├── websocket.py          # Real-time updates
│   │   └── deps.py               # Dependencies
│   ├── static/                   # Built React UI
│   └── templates/                # HTML templates
├── frontend/                     # React TypeScript UI
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard/
│   │   │   ├── ModelConfig/
│   │   │   ├── ScopeManager/
│   │   │   ├── ResultsViewer/
│   │   │   └── DebateViewer/
│   │   ├── hooks/
│   │   ├── stores/
│   │   ├── api/
│   │   └── App.tsx
│   └── package.json
├── agents/                       # Multi-agent framework
│   ├── __init__.py
│   ├── base.py                   # Base agent class
│   ├── registry.py               # Agent registry
│   ├── message_bus.py            # Inter-agent messaging
│   └── agents/
│       ├── recon.py              # Reconnaissance agent
│       ├── code_review.py        # Code review agent
│       ├── dependency.py         # Dependency/CVE agent
│       ├── architecture.py       # Architecture analysis
│       ├── threat_modeling.py    # Threat modeling (STRIDE)
│       ├── workflow.py           # User journey analysis
│       ├── permission.py         # Permission graph
│       ├── business_logic.py     # Business rule extraction
│       ├── correlation.py        # Finding correlation
│       ├── evidence.py           # Evidence retrieval
│       ├── debate.py             # 5-agent debate engine
│       ├── qa.py                 # Quality assurance
│       └── report.py             # Report generation
├── engines/                      # Core analysis engines
│   ├── __init__.py
│   ├── knowledge_graph.py        # Graph database
│   ├── permission_graph.py       # Permission modeling
│   ├── business_rules.py         # Rule extraction
│   ├── user_journey.py           # Journey modeling
│   ├── anomaly_detection.py      # Anomaly flagging
│   ├── confidence.py             # Confidence scoring
│   ├── memory.py                 # Project memory
│   └── rag/                      # RAG intelligence
│       ├── indexer.py            # Document chunking
│       ├── retriever.py          # Retrieval with reranking
│       └── embedder.py           # Embedding models
├── providers/                    # LLM provider abstraction
│   ├── __init__.py
│   ├── base.py                   # Provider interface
│   ├── openai.py                 # OpenAI-compatible
│   ├── anthropic.py              # Anthropic-compatible
│   ├── ollama.py                 # Ollama local
│   ├── lmstudio.py               # LM Studio
│   ├── vllm.py                   # vLLM
│   ├── gemini.py                 # Gemini API
│   └── mistral.py                # Mistral API
├── models/                       # Data models
│   ├── __init__.py
│   ├── project.py                # Project state
│   ├── scope.py                  # Scope definitions
│   ├── finding.py                # Finding schema
│   ├── graph.py                  # Graph node/edge schemas
│   └── report.py                 # Report templates
├── analyzers/                    # Analysis modules
│   ├── __init__.py
│   ├── code/                     # SAST capabilities
│   │   ├── parser.py             # Multi-language parsing
│   │   ├── patterns.py           # Security patterns
│   │   ├── data_flow.py          # Taint analysis
│   │   └── auth.py               # Auth flow analysis
│   └── web/                      # Web pentesting
│       ├── crawler.py            # Web crawling
│       ├── scanner.py            # Vulnerability scanner
│       └── api.py                # API testing
├── utils/
│   ├── config.py                 # Configuration management
│   ├── logging.py                # Structured logging
│   └── security.py               # Security utilities
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## 4. IMPLEMENTATION PHASES

### Phase 1: Foundation (Week 1-2)
**Goal:** Core infrastructure, provider abstraction, basic agent framework

1. **Project scaffolding** — Create directory structure, install dependencies
2. **Provider Abstraction Layer** — Build the multi-backend LLM interface
3. **Agent Base Class** — Define agent contract with message bus
4. **Message Bus** — Inter-agent communication infrastructure
5. **Memory Engine** — Project state persistence
6. **Basic Web Server** — FastAPI + React UI shell
7. **CLI Launcher** — `sentinel-x start` command

### Phase 2: RAG & Knowledge (Week 2-3)
**Goal:** RAG intelligence, knowledge graph, document indexing

1. **RAG Indexer** — Chunk and index code, docs, specs
2. **Embedding Service** — Local embeddings via Ollama/ LM Studio
3. **Retrieval with Reranking** — BM25 + vector hybrid retrieval
4. **Knowledge Graph Engine** — Graph database for entities/relationships
5. **Permission Graph Engine** — Authorization modeling
6. **Business Rule Extraction** — Document + code rule mining

### Phase 3: Core Agents (Week 3-5)
**Goal:** Implement all 14 specialized agents

1. **Recon Agent** — Asset discovery, fingerprinting
2. **Code Review Agent** — SAST static analysis
3. **Dependency Agent** — CVE scanning, supply chain
4. **Architecture Agent** — System mapping, structural risks
5. **Threat Modeling Agent** — STRIDE + business logic threats
6. **Workflow Agent** — User journey modeling
7. **Permission Agent** — Permission gap detection
8. **Business Logic Agent** — Rule violation detection
9. **Correlation Agent** — Finding amplification/chaining
10. **Evidence Agent** — Evidence retrieval for findings
11. **Debate Agent** — 5-agent structured evaluation
12. **QA Agent** — Report quality review
13. **Report Agent** — Final report synthesis
14. **Documentation Agent** — Doc extraction

### Phase 4: Analysis Engines (Week 5-7)
**Goal:** Deep SAST and web pentesting capabilities

1. **Multi-language Parser** — JS, Python, Go, Java, etc.
2. **Security Pattern Library** — OWASP, CWE patterns
3. **Data Flow Analysis** — Taint tracking for injection
4. **Auth Flow Analysis** — Token, session, OAuth analysis
5. **Web Crawler** — Site mapping, form discovery
6. **Vulnerability Scanner** — XSS, SQLi, IDOR detection
7. **API Tester** — REST/GraphQL security testing

### Phase 5: UI & Polish (Week 7-8)
**Goal:** Full-featured web UI, real-time updates

1. **Dashboard** — Project overview, recent analyses
2. **Model Configuration** — Configure all LLM providers
3. **Scope Manager** — Define and visualize scope
4. **Results Viewer** — Finding details, attack chains
5. **Debate Viewer** — Watch finding debates unfold
6. **Report Export** — PDF, Markdown, HTML exports
7. **WebSocket Real-time** — Live agent progress updates

### Phase 6: Testing & Deployment (Week 8-10)
**Goal:** Production-ready with Docker deployment

1. **End-to-end testing** — Full analysis workflows
2. **Agent integration tests** — Inter-agent communication
3. **UI testing** — Component tests with Playwright
4. **Docker build** — Multi-stage Dockerfile
5. **docker-compose** — Full stack deployment
6. **Documentation** — Usage guides, API docs

---

## 5. PROVIDER ABSTRACTION LAYER

### Configuration Schema

```yaml
providers:
  primary:
    provider: "anthropic"           # anthropic | openai | ollama | vllm | gemini | mistral | local
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"
    models:
      reasoning: "claude-sonnet-4-20250514"
      code: "claude-sonnet-4-20250514"
      embedding: "embed-english-v3.0"
      report: "claude-sonnet-4-20250514"
  
  openai_compatible:
    provider: "openai"
    base_url: "http://localhost:11434"  # Ollama
    api_key: "not-required"
    models:
      reasoning: "llama3.1:70b"
      code: "llama3.1:70b"
```

### Routing Rules

| Task Type | Model Purpose | Routing |
|---|---|---|
| Threat modeling | REASONING_MODEL | Highest capability |
| Debate evaluation | REASONING_MODEL | Highest capability |
| Architecture reasoning | REASONING_MODEL | Highest capability |
| Code analysis | CODE_MODEL | Fast, cost-effective |
| Simple extraction | CODE_MODEL | Fast, cost-effective |
| Report synthesis | REPORT_MODEL | Balanced |
| Embedding | EMBEDDING_MODEL | Local when possible |
| Reranking | RERANK_MODEL | Local when possible |

---

## 6. AGENT MESSAGE SCHEMA

```python
class AgentMessage(BaseModel):
    id: str                           # UUID
    source_agent: AgentType           # Who sent this
    target_agent: Optional[AgentType] # Who should receive (None = broadcast)
    message_type: MessageType         # TASK | RESPONSE | EVENT | ERROR
    payload: dict                     # Structured payload
    timestamp: datetime
    conversation_id: str              # For tracing
    reply_to: Optional[str]           # Original message ID
    
class TaskPayload(BaseModel):
    task_id: str
    task_type: str                    # analyze_code | map_scope | etc.
    input_data: dict
    context: dict                     # RAG context, project state
    routing_hints: dict               # Preferred models
```

---

## 7. DEBATE ENGINE SCHEMA

### 5-Agent Structure

```
┌─────────────────────────────────────────────────────────┐
│                    DEBATE ENGINE                         │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │ ADVOCATE │    │  SKEPTIC │    │INVESTIGATOR│         │
│  │  (Agent  │◄──►│  (Agent  │◄──►│  (Agent   │         │
│  │    A)    │    │    B)    │    │    C)     │         │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘          │
│       │               │               │                 │
│       ▼               ▼               ▼                 │
│  ┌──────────┐    ┌──────────┐                          │
│  │  IMPACT  │    │  ARBITER │◄─────────────────────────┤
│  │ ANALYST  │    │  (Agent  │                          │
│  │    D)    │    │    E)    │                          │
│  └──────────┘    └──────────┘                          │
│                                                         │
│  VERDICT: PROMOTE | NEEDS_REVIEW | REJECT               │
└─────────────────────────────────────────────────────────┘
```

### Debate Output Schema

```python
class DebateResult(BaseModel):
    finding_id: str
    verdict: Literal["PROMOTE", "NEEDS_REVIEW", "REJECT"]
    confidence: Literal["Verified", "High", "Medium", "Low", "Informational"]
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    advocate_summary: str
    skeptic_challenges: List[str]
    missing_evidence: List[str]
    impact_analysis: str
    attack_scenario: str
    debate_transcript: List[dict]
```

---

## 8. RAG INDEXING SCHEMA

### Chunk Metadata

```python
class ChunkMetadata(BaseModel):
    chunk_id: str
    source_file: str
    source_type: Literal["code", "documentation", "api_spec", "scope", "finding"]
    component: str                    # Which component this belongs to
    chunk_type: Literal["function", "class", "endpoint", "config", "doc_section"]
    language: Optional[str]           # For code chunks
    risk_tags: List[str]              # CWE, OWASP tags
    function_name: Optional[str]      # For code chunks
    line_start: int
    line_end: int
    embedding_model: str
    indexed_at: datetime
```

### Retrieval Result

```python
class RetrievalResult(BaseModel):
    chunk: ChunkMetadata
    score: float                      # Combined relevance score
    rerank_score: float               # After reranking
    text: str                         # The actual chunk text
    source_confidence: Literal["high", "medium", "low"]
```

---

## 9. UI SPECIFICATION

### Pages

1. **Dashboard** (`/`)
   - Active projects list
   - Recent analysis results
   - Quick start actions

2. **Model Configuration** (`/models`)
   - Configure all LLM providers
   - Test connections
   - Set default routing

3. **Project Workspace** (`/project/:id`)
   - Scope definition
   - Asset management
   - Analysis controls
   - Real-time agent progress

4. **Results** (`/project/:id/results`)
   - Findings list (filterable by severity)
   - Attack chain visualizations
   - Finding detail + debate transcript

5. **Report** (`/project/:id/report`)
   - Executive summary
   - Full findings with evidence
   - Export options (PDF, MD, HTML)

### UI Components

- **Scope Graph Visualizer** — D3.js force-directed graph of assets
- **Finding Cards** — Severity badge, confidence, affected components
- **Debate Timeline** — Real-time debate step visualization
- **Attack Chain Builder** — Visual chain builder for correlated findings
- **Code Viewer** — Syntax highlighted with finding markers
- **Model Status Panel** — Connection status for all providers

---

## 10. KEY TECHNICAL DECISIONS

| Decision | Choice | Rationale |
|---|---|---|
| Backend Language | Python | Rich security tooling ecosystem, easy LLM integration |
| Web Framework | FastAPI | Async, OpenAPI generation, WebSocket support |
| Frontend | React + TypeScript | Strong typing, component ecosystem |
| Message Bus | Redis + asyncio | Can run in-memory for single-instance, Redis for scale |
| Graph Database | NetworkX (in-process) | Simple, Pythonic; swap for Neo4j for scale |
| Embeddings | Ollama/LM Studio (local) | No API costs, privacy |
| Code Parsing | Tree-sitter | Multi-language, accurate AST |
| Real-time | WebSocket + SSE | Live agent updates in UI |

---

## 11. HARD LIMITS (Non-Negotiable)

These rules are enforced in code, not configurable:

1. **Never analyze out-of-scope assets** — Hard block, no override
2. **Never store credentials outside secrets store** — Encrypted at rest
3. **Never include credentials in reports** — Stripped before output
4. **Never generate working exploits** — Only POC concepts
5. **No exploitation beyond confirmation** — Read-only validation
6. **Always surface uncertainty** — Never hide knowledge gaps

---

## 12. SUCCESS METRICS

- All 14 agents operational and communicating
- SAST finds real vulnerabilities in test repos (Snyk.io test cases)
- Web testing identifiesOWASP Top 10 in test applications
- Debate engine correctly rejects false positives
- Report generation produces valid, well-structured output
- UI provides real-time visibility into agent reasoning
- Full provider abstraction works with 5+ different backends

---

## 13. NEXT STEPS

1. **Start Phase 1** — Create project structure, install dependencies
2. **Build Provider Layer** — Implement multi-backend LLM interface
3. **Get agents talking** — Basic message bus + 2 test agents
4. **UI shell** — Get React app connected to FastAPI
5. **First analysis** — Run a simple code review end-to-end