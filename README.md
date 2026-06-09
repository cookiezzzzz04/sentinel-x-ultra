# SENTINEL-X ULTRA

**Autonomous Security Analysis Intelligence Framework**

An advanced security analysis platform that combines Phase 2 analytical engines with Phase 3 autonomous AI agents for comprehensive vulnerability discovery and threat modeling.

## Features

### Phase 2: Analysis Engines
- **Code Analysis (SAST)** - Pattern-based security scanning with data flow and authentication flow analysis
- **Web Vulnerability Analysis** - Endpoint analysis for OWASP Top 10 vulnerabilities
- **Knowledge Graph** - Entity relationship modeling and attack path discovery
- **Permission Graph** - Access control analysis and security gap detection
- **Business Rule Engine** - Compliance and security policy validation
- **RAG Indexing** - Retrieval-augmented generation for security reasoning

### Phase 3: Autonomous Agents
- **Reconnaissance Agent** - Target discovery, OSINT, and subdomain enumeration
- **Code Review Agent** - Deep security analysis with LLM assistance
- **Threat Modeling Agent** - Attack path analysis using knowledge graphs
- **Dependency Agent** - CVE scanning for third-party vulnerabilities
- **Debate Engine** - 5-role adversarial validation for finding quality

## Quick Start

### Prerequisites
- Python 3.11+
- API keys for LLM providers (Anthropic, OpenAI, Groq, etc.)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd sentinel_x_ultra
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API keys:
   - Run the application and navigate to Settings
   - Enter your LLM provider API key and base URL

### Running the Server

```bash
cd sentinel_x_ultra
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

Access the web UI at: http://127.0.0.1:7860

## API Endpoints

### Health Check
```bash
GET /api/health
```

### Project Management
```bash
POST   /api/projects          # Create project
GET    /api/projects          # List projects
GET    /api/projects/{id}     # Get project details
DELETE /api/projects/{id}     # Delete project
```

### Phase 2 Analysis
```bash
POST /api/projects/{id}/analyze/code        # Code security analysis
POST /api/projects/{id}/analyze/web/endpoint # Web vulnerability scan
GET  /api/projects/{id}/knowledge-graph     # Get knowledge graph
POST /api/projects/{id}/knowledge-graph/attack-paths # Discover attack paths
GET  /api/projects/{id}/permission-graph    # Get permission graph
POST /api/projects/{id}/business-rules/extract # Extract business rules
```

### Phase 3 Agents
```bash
POST /api/projects/{id}/agents/recon         # Run reconnaissance
POST /api/projects/{id}/agents/code-review   # Run code review
POST /api/projects/{id}/agents/threat-modeling # Run threat modeling
POST /api/projects/{id}/agents/dependency    # Scan dependencies
POST /api/projects/{id}/agents/debate        # Validate findings
GET  /api/projects/{id}/agents               # List available agents
```

### WebSocket
```bash
WS /ws/{project_id}  # Real-time agent updates
```

## Architecture

```
sentinel_x_ultra/                    # Project root
├── sentinel_x_ultra/               # Main package
│   ├── agents/                    # AI agent implementations
│   │   └── phase3.py             # Phase 3 autonomous agents
│   ├── analyzers/                # Static analysis engines
│   │   ├── code_analyzer.py     # SAST engine
│   │   └── web_analyzer.py      # Web vulnerability scanner
│   ├── engines/                  # Analysis engines
│   │   ├── knowledge_graph.py   # Attack path discovery
│   │   ├── permission_graph.py  # Access control analysis
│   │   └── business_rules.py    # Policy validation
│   ├── providers/                # LLM provider integrations
│   ├── memory.py                 # Project memory/storage
│   ├── config.py                 # Configuration management
│   └── server.py                 # FastAPI web server
├── frontend/                      # React frontend (Vite)
│   └── dist/                     # Built UI assets
├── pyproject.toml
└── requirements.txt
```

**Note:** The frontend is a React/Vite application that gets built into `frontend/dist/` and is served by the FastAPI server.

## License

Proprietary - All rights reserved