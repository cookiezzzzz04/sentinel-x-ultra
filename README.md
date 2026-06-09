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

## Supported LLM Providers

- **OpenAI** - GPT-4o, GPT-4o-mini, GPT-4 Turbo
- **Anthropic** - Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku
- **Google** - Gemini Pro, Gemini 2.0 Flash, Gemma
- **Groq** - Llama 3.1, Mixtral
- **Ollama** - Local models (Llama 3, Mistral, etc.)
- **DeepSeek** - DeepSeek Chat
- **Mistral AI** - Mistral Large, Mistral 7B
- **OpenRouter** - Access to 100+ models including Meta-Llama, Google, Anthropic via unified API

## Quick Start

### Prerequisites
- Python 3.11+
- API keys for LLM providers (Anthropic, OpenAI, Groq, OpenRouter, etc.)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/cookiezzzzz04/sentinel-x-ultra.git
cd sentinel_x_ultra
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Build the frontend:
```bash
cd frontend
npm install
npm run build
cd ..
```

### Running the Server

**Windows:**
```powershell
cd "C:\Users\YourName\path\to\sentinel-x-ultra"
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

**Linux/Mac:**
```bash
cd sentinel_x_ultra
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

Access the web UI at: **http://127.0.0.1:7860**

## Configuration

### Web UI Setup
1. Navigate to **Settings** in the web UI
2. Select your LLM provider (OpenAI, Anthropic, OpenRouter, etc.)
3. Enter your API key and base URL (if required)
4. Choose a default model from the dropdown
5. Click **Save**

### Provider Base URLs
| Provider | Base URL |
|----------|----------|
| OpenAI | `https://api.openai.com/v1` |
| Anthropic | `https://api.anthropic.com` |
| Google | `https://generativelanguage.googleapis.com/v1beta` |
| Groq | `https://api.groq.com/openai/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| DeepSeek | `https://api.deepseek.com/v1` |
| Mistral AI | `https://api.mistral.ai/v1` |
| Ollama | `http://localhost:11434/v1` |

### OpenRouter Setup
OpenRouter provides access to many models through a single API key. To use OpenRouter:
1. Get an API key from https://openrouter.ai/
2. In Settings, select **OpenRouter** as the provider
3. Enter your OpenRouter API key
4. Select a model like `openrouter/auto` (auto-select best model) or specific models like `meta-llama/llama-3.1-8b-instant`
5. Save and restart the server if needed

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

### Provider Configuration
```bash
GET  /api/config/providers    # List available providers
GET  /api/config/models       # List available models
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
│   │   └── providers.py         # Multi-provider support
│   ├── memory.py                 # Project memory/storage
│   ├── config.py                 # Configuration management
│   └── server.py                 # FastAPI web server
├── frontend/                      # React frontend (Vite)
│   └── dist/                     # Built UI assets
├── pyproject.toml
└── requirements.txt
```

**Note:** The frontend is a React/Vite application that gets built into `frontend/dist/` and is served by the FastAPI server.

## Troubleshooting

### Server won't start
- Ensure Python 3.11+ is installed: `python --version`
- Check that port 7860 is not already in use
- Verify you're in the correct directory with `requirements.txt`

### OpenRouter errors (404)
- Ensure you have a valid OpenRouter API key
- Restart the server after changing API keys
- Try using `openrouter/auto` for automatic model selection

### Provider connection issues
- Verify your API key is correct
- Check that the base URL matches your provider
- Some providers require specific model names in their catalog

## License

Proprietary - All rights reserved