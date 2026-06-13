# SENTINEL-X ULTRA 🛡️

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/typescript-5.0%2B-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript 5.0+">
  <img src="https://img.shields.io/badge/license-proprietary-ff4444?style=for-the-badge" alt="License: Proprietary">
  <img src="https://img.shields.io/badge/status-active-00d4ff?style=for-the-badge" alt="Status: Active">
  <img src="https://img.shields.io/badge/agents-10-aa88ff?style=for-the-badge" alt="10 Bug Bounty Agents">
  <img src="https://img.shields.io/badge/tools-20%2B-00ff88?style=for-the-badge" alt="20+ Integrated Tools">
</p>

> An AI-powered bug bounty hunting platform with 10 specialized agents, 20+ hacking tools, and 3 analysis engines — all in one place.

Think of it like having a team of security researchers working 24/7 on your laptop. It scans websites, code, and networks for vulnerabilities, validates the findings, and writes professional reports. You just open the web UI and click a button.

---

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Install Python stuff
pip install -r sentinel_x_ultra/requirements.txt

# 2. Set up your API key
cp .env.example .env
# Edit .env — you need at least one LLM key (OpenAI, Anthropic, or run locally with Ollama)

# 3. Start the server
cd sentinel_x_ultra
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860

# That's it. Open http://127.0.0.1:7860 in your browser.
```

### Or use the frontend dev server (for editing the UI)

```bash
cd sentinel_x_ultra/frontend
npm install
npx vite --host 0.0.0.0 --port 5173
```

This runs the UI on port 5173 with hot reload, while the backend runs on 7860.

---

## 🤝 Contributing

There's a full **[CONTRIBUTING.md](CONTRIBUTING.md)** that covers everything — development setup, how to add a new agent, how to integrate a new hacking tool, code style, testing conventions, and the PR process. Also check out:

- **[SECURITY.md](SECURITY.md)** — How to responsibly report security issues
- **[CHANGELOG.md](CHANGELOG.md)** — What changed in each version

---

## 📖 What's In The Box

### 🏴 10 Bug Bounty Agents (The Main Event)

Click **Bug Bounty** in any project and run the full pipeline. All 10 agents work in sequence, each one using AI to think through its decisions:

| # | Agent | What it does |
|---|-------|-------------|
| 1 | **URL Parser** | Reads HackerOne/BugCrowd pages → figures out scope, policy, rewards |
| 2 | **Policy Enforcer** | Decides if a finding is ALLOWED, needs REVIEW, or gets REJECTED |
| 3 | **Scope Guardian** | Checks every target is authorized — blocks third-party domains |
| 4 | **Passive Intel** | OSINT recon — Shodan, Censys, SecurityTrails, certificate search |
| 5 | **Active Enumeration** | Maps attack surface with dirsearch, gobuster, ffuf, nmap |
| 6 | **Vuln Scanner** | Scans with nuclei, sqlmap, dalfox + generates AI hypotheses |
| 7 | **Validation Engine** | Skeptic mode — tries to prove each finding is wrong before approving |
| 8 | **Exploitation** | Creates safe, reproducible proof-of-concept exploits |
| 9 | **Analysis** | Scores severity (CVSS 3.1), classifies (CWE), maps to OWASP |
| 10 | **Report Generation** | Writes professional vulnerability reports in Blank.md format |

### 🧠 Phase 3 Agents (Analysis & Reasoning)

| Agent | What it does |
|-------|-------------|
| **Reconnaissance** | AI-powered recon — gathers intel, analyzes scope, identifies targets |
| **Code Review** | Reads your code and flags security issues without running it |
| **Threat Modeling** | Maps out attack paths using a knowledge graph of your app |
| **Dependency Scan** | Checks for known CVEs in your dependencies |
| **Adversarial Debate** | Two AI agents argue about a finding — one defends, one attacks. Only survivors get reported |

### 🔬 Phase 4 (Reports & Compliance)

| Engine | What it does |
|--------|-------------|
| **Remediation** | Creates step-by-step fix plans for each finding |
| **Report Generator** | Writes executive summaries and detailed technical reports |
| **Compliance Engine** | Maps findings to OWASP Top 10, NIST CSF, SOC 2, PCI-DSS |

### ⚡ Phase 5 (Advanced Security)

| Agent | What it does |
|-------|-------------|
| **Threat Intelligence** | YARA rules, IOC enrichment, threat tracking, malware analysis |
| **Security Operations** | SIEM integration, SOAR playbooks, alert triage, incident management |
| **Adaptive Defense** | ML anomaly detection, behavioral analysis, self-healing automation |
| **Supply Chain** | SBOM generation, dependency analysis, license compliance, CVE scanning |
| **API Security** | OpenAPI/GraphQL analysis, fuzzing, auth testing, rate limiting |

### 🛠️ 20+ Hacking Tools

All integrated with structured result parsing and async execution. The platform auto-detects which ones you have installed.

**Reconnaissance:**
- **SubFinder** — Passive subdomain enumeration from 30+ sources
- **Amass** — Attack surface mapping (deep subdomain enumeration)
- **Sublist3r** — Fast passive subdomain discovery
- **Knockpy** — Subdomain brute-force
- **Dnscan** — DNS brute-force
- **MassDNS** — High-performance DNS resolution
- **Dnsx** — Multi-purpose DNS toolkit

**Content Discovery:**
- **Gobuster** — Directory/file bruteforce + DNS + vhost modes
- **FFUF** — Fast web fuzzer with auto-calibration
- **Dirsearch** — Web path discovery
- **Wfuzz** — Parameter fuzzing and injection testing

**Network Scanning:**
- **Nmap** — Port scanning, service detection, OS fingerprinting, NSE scripts

**Vulnerability Scanners:**
- **Nuclei** — Fast template-based scanner (13,000+ templates)
- **Dalfox** — XSS vulnerability scanner
- **Sqlifinder** — SQL injection discovery
- **SQLMap** — Automatic SQL injection exploitation

**Password Cracking:**
- **John the Ripper** — Hash cracking with 30+ format support
- **Hydra** — Network login brute-forcing (SSH, FTP, HTTP, etc.)

**Web Analysis:**
- **Httpx** — HTTP probe + technology detection
- **Waybackurls** — Historical URL collection from Wayback Machine
- **Gau** — Get all URLs (AlienVault + Wayback + Common Crawl)
- **Katana** — Crawler for URL discovery

**Mobile & JavaScript:**
- **Mobile Security Framework (MobSF)** — Mobile app analysis
- **Apktool** — Android APK reverse engineering
- **RetireJS** — JavaScript library vulnerability scanner
- **GitTools** — Git repository analysis

**CMS & Config:**
- **WPScan** — WordPress vulnerability scanner
- **CMSMap** — CMS detection and scanning
- **EyeWitness** — Web screenshot capture
- **CorsTest** — CORS misconfiguration testing
- **JWT Toolkit** — JWT token testing
- **TkoSubs** — Subdomain takeover detection
- **Git Secrets** — Secrets scanning in git history

**Built-in (no install needed):**
- **XXE Tool** — Generates XXE payloads for file read, SSRF, blind testing
- **Deserialization Tool** — Generates PHP, Java, Python, Ruby, .NET deserialization payloads

### 📡 Live Activity Stream (WebSocket)

The whole platform runs on a **live event system**. Every action — agent starting, tool executing, finding created — generates a real-time event:

- **WebSocket endpoint:** `ws://localhost:7860/ws` (global) or `ws://localhost:7860/ws/{project_id}` (project-scoped)
- **Monitor panel** (📡 button in header): Full execution monitor with event filters, search, and status tracking
- **Activity Center** (📋 button in header): Timeline of all events with icons, severity colors, and live status badges
- **Event Store**: Keeps up to 10,000 events in memory for browsing

Events include: type, message, status (running/completed/failed), severity, source, icon, duration, and rich metadata. The UI shows running events with animated indicators and auto-updates via WebSocket push.

### 🌐 Burp Suite Integration

Works with Burp Suite Professional (REST API) and Community Edition (import JSON exports). Automatically analyzes proxy history for SQL injection, XSS, path traversal, SSRF, and missing security headers.

### 🔗 Auto-Select Engine

Tell it what vulnerability indicators you've found (e.g., "sql_error", "auth_bypass"), and it recommends the best Phase 5 agent to deploy with relevant payloads.

| Endpoint | What it does |
|----------|-------------|
| `GET /api/auto-select/agents` | Returns all vulnerability-to-agent mappings with payloads and indicators |
| `POST /api/auto-select/recommend` | Give it a vulnerability type → get the best agent + secondary agents + OWASP mapping |
| `POST /api/auto-select/detect-and-recommend` | Give it indicators → it figures out the vuln type and recommends an agent |
| `POST /api/auto-select/run-recommended` | Prepares input data to run the recommended agent for a vulnerability

### 🧠 Multi-Provider LLM Support

| Provider | Best for |
|----------|---------|
| **Anthropic (Claude)** | Reasoning, analysis, report writing |
| **OpenAI (GPT-4o)** | General purpose, quick responses |
| **Ollama** | Free, runs entirely on your machine |
| **Groq** | Fast inference on open models |
| **OpenRouter** | Access to 100+ models |
| **LM Studio / vLLM** | Run custom models locally |
| **Gemini** | Google's latest models |
| **Mistral** | Efficient open-source models |

---

## 📦 Installation

### What you definitely need

| Thing | Why | Link |
|-------|-----|------|
| **Python 3.11+** | The whole platform runs on it | [python.org](https://python.org) |
| **An API key** | Powers the AI agents | See `.env.example` |

### What makes things work better

| Thing | What it adds | How to install |
|-------|-------------|----------------|
| **Go 1.21+** | Installs subfinder, httpx, nuclei, ffuf — deeper scanning | [go.dev](https://go.dev) |
| **30+ security tools** | Everything listed above | `bash scripts/install_tools.sh` |
| **Shodan / Censys keys** | Internet intelligence for the Passive Intel agent | Free accounts |

### Installing security tools

```bash
# One script installs everything:
bash scripts/install_tools.sh

# Or install individual tools via Go:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# For John the Ripper (Windows):
# Download from https://www.openwall.com/john/
# Place the run/ folder in ~/.sentinelx/tools/john/

# For SQLMap:
git clone --depth 1 https://github.com/sqlmapproject/sqlmap ~/.sentinelx/tools/sqlmap
```

Tools are auto-detected from `~/.sentinelx/tools/` and `~/go/bin/`. The platform just needs them on disk — no config needed.

### Install nuclei templates

```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates
```

---

## 🚀 Running the Server

```bash
# Development mode (auto-reloads when files change)
cd sentinel_x_ultra
uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860 --reload

# Production mode
uvicorn sentinel_x_ultra.server:app --host 0.0.0.0 --port 7860

# Just the Python module
python -m sentinel_x_ultra.server
```

### Using Make

```bash
make install          # Install Python deps + security tools
make dev              # Start server on :7860 with hot-reload
make dev-frontend     # Start frontend on :5173 with HMR
make build            # Build production frontend
make test             # Run unit tests
make test-coverage    # Run tests with coverage report
make clean            # Remove cache & artifacts
make ci               # Local CI (syntax check + tests)
make up               # Docker Compose (dev)
make prod             # Docker Compose (production)
make logs             # Tail Docker logs
make stop             # Stop Docker containers
```

### Docker

```bash
docker compose up -d
# Open http://localhost:7860
```

The Docker image is ~200 MB and includes the Python backend + built React frontend. Hacking tools stay on your machine to keep the image small.

---

## 🧪 Running Tests

```bash
cd sentinel_x_ultra
python -m pytest tests/ -v
python -m pytest tests/test_bug_bounty.py -v  # Just bug bounty tests
python -m pytest tests/ --cov=sentinel_x_ultra/bug_bounty  # With coverage
```

---

## 📁 Project Structure

```
sentinel-x-ultra/
├── sentinel_x_ultra/                   # Python backend
│   ├── server.py                       # FastAPI web server (all endpoints)
│   ├── config.py                       # Settings — host, port, storage paths
│   ├── cli.py / __main__.py            # Command-line interface
│   ├── models.py                       # Pydantic data models
│   ├── providers.py                    # LLM provider router (Anthropic, OpenAI, etc.)
│   ├── memory.py                       # Project storage + state management
│   ├── rag.py                          # RAG engine for context retrieval
│   ├── methodology.py                  # Methodology reference engine (Blank.md, Burp workflow)
│   ├── project_context.py              # Project context for AI agents
│   ├── research_memory.py              # Research findings persistence
│   ├── coverage.py                     # Coverage tracking across agents
│   ├── validation.py                   # Finding validation pipeline
│   ├── workspace.py                    # Project workspace management
│   ├── seed_templates.py               # Recon txt template seeding (10 files)
│   ├── report_template.py              # Report templates for findings
│   ├── terminal.py                     # Terminal utilities
│   ├── burp_proxy.py                   # Burp Suite proxy analyzer
│   ├── burp_input_endpoints.py         # Burp upload endpoints
│   ├── recon_api.py                    # Reconnaissance API endpoints
│   ├── recon_methodology.py            # Recon methodology definitions
│   ├── v3_endpoints.py / new_endpoints.py  # API endpoint extensions
│   ├── ollama_embedder.py              # Ollama embedding integration
│   ├── agent_models.py / agent_knowledge.py  # Agent config & knowledge
│   ├── agents.py                       # Agent base classes
│   ├── agent_tool_integration.py       # Agent ↔ Tool bridge
│   │
│   ├── agents/                         # Phase 3-5 AI agents
│   │   ├── phase3.py                   # Recon, Code Review, Threat Modeling, Debate
│   │   ├── phase4.py                   # Remediation, Compliance, Report Generation
│   │   ├── phase5.py                   # Threat Intel, SecOps, Adaptive Defense, etc.
│   │   └── __init__.py                 # Agent base classes
│   │
│   ├── analyzers/                      # Analysis engines
│   │   ├── code_analyzer.py            # SAST — static code analysis with data flow
│   │   ├── web_analyzer.py             # Web vulnerability analysis
│   │   └── __init__.py
│   │
│   ├── engines/                        # Knowledge engines
│   │   ├── knowledge_graph.py          # Entity relationship graph + attack paths
│   │   ├── permission_graph.py         # Permission model with gap analysis
│   │   ├── business_rules.py           # Business logic rule extraction
│   │   └── __init__.py
│   │
│   ├── bug_bounty/                     # 10-agent pipeline
│   │   ├── orchestrator.py             # Runs all 10 agents in sequence
│   │   ├── url_parser.py               # Agent 1 — Parse bug bounty programs
│   │   ├── policy_enforcer.py          # Agent 2 — Policy rules
│   │   ├── scope_guardian.py           # Agent 3 — Scope enforcement
│   │   ├── passive_intel.py            # Agent 4 — OSINT recon
│   │   ├── active_enum.py              # Agent 5 — Attack surface mapping
│   │   ├── vuln_scanner.py             # Agent 6 — Vulnerability scanning
│   │   ├── validation_engine.py        # Agent 7 — False positive elimination
│   │   ├── exploitation.py             # Agent 8 — Safe proof-of-concepts
│   │   ├── analysis.py                 # Agent 9 — CVSS/CWE scoring
│   │   ├── report_generation.py        # Agent 10 — Report writing
│   │   ├── security_guard.py           # Ethical rules + PII sanitizer
│   │   ├── execution_engine.py         # Rate limiter, cache, circuit breaker
│   │   ├── system_prompts.py           # Foundational Principles & agent prompts
│   │   ├── data_sources.py             # External API clients (Shodan, Censys, etc.)
│   │   ├── agent_memory.py             # Cross-agent shared knowledge store
│   │   ├── webhook.py / llm_provider.py # Notifications & LLM interface
│   │   └── __init__.py
│   │
│   ├── ffuf_tool.py / gobuster_tool.py / nmap_tool.py  # Web fuzzers & scanner
│   ├── john_tool.py / hydra_tool.py    # Password cracking
│   ├── sqlmap_tool.py                  # SQL injection
│   ├── xxe_tool.py                     # XXE payload generator + scanner
│   ├── deserialization_tool.py         # Deserialization payload generator
│   ├── recon_tools.py                  # SubFinder, Waybackurls, Gau, Dalfox, Httpx, Nuclei, etc.
│   ├── recon_tools_extended.py         # Extended tools: Amass, Sublist3r, Dirsearch, WPScan, etc.
│   └── tests/                          # 22+ tests across 8 test files
│
├── frontend/                           # React TypeScript web UI
│   ├── src/
│   │   ├── App.tsx                     # Main app with sidebar + notifications
│   │   ├── panel_components.tsx        # Input, Threat Hunt, Supply Chain panels
│   │   ├── main.tsx / index.css        # Entry point & global styles
│   │   ├── components/
│   │   │   ├── DashboardView.tsx       # Main dashboard with stat cards
│   │   │   ├── ProjectView.tsx         # Project page with dynamic tabs
│   │   │   ├── BugBountyPanel.tsx      # 10-agent pipeline UI
│   │   │   ├── AgentsPanel.tsx         # Phase 3 agent controls
│   │   │   ├── Phase5Panel.tsx         # Phase 5 agent controls
│   │   │   ├── AnalysisPanel.tsx       # Code/web analysis controls
│   │   │   ├── FindingsPanel.tsx       # Findings browser with filters
│   │   │   ├── AIReportPanel.tsx       # AI report generation
│   │   │   ├── ToolRunnerPanel.tsx     # Run hacking tools from the UI
│   │   │   ├── ProxyMonitor.tsx        # Burp-style proxy monitor
│   │   │   ├── ExecutionMonitor.tsx    # Real-time activity stream
│   │   │   ├── PipelineTracker.tsx     # Pipeline progress tracker
│   │   │   ├── OverviewChat.tsx        # AI chat for project overview
│   │   │   ├── ActivityCenter.tsx      # WebSocket activity feed
│   │   │   ├── SetupView.tsx           # Provider configuration
│   │   │   ├── ModelManagementUI.tsx   # Model management
│   │   │   ├── CreateProjectWizard.tsx # Project creation wizard
│   │   │   ├── ThreatHuntView.tsx      # Threat hunting UI
│   │   │   ├── LiveLogStream.tsx       # Live log viewer
│   │   │   ├── StatCard.tsx            # Reusable stat card
│   │   │   ├── NavItem.tsx / Button.tsx / Modal.tsx  # Reusable components
│   │   │   ├── StatusIndicator.tsx     # System status indicator
│   │   │   └── LoadingSpinner.tsx      # Loading state
│   │   └── hooks/useMediaQuery.ts      # Responsive design hooks
│   ├── dist/                           # Built static files
│   ├── vite.config.ts / tsconfig.json  # Build config
│   └── package.json                    # Frontend dependencies
│
├── scripts/
│   ├── install_tools.sh                # Install 30+ security tools
│   ├── recon_install.sh                # Alternative recon tool installer
│   └── entrypoint.sh                   # Docker entrypoint
├── .env.example                        # API key template (all providers)
├── Makefile                            # All commands in one place
├── Dockerfile + docker-compose*.yml    # Container setup (dev + prod + overrides)
├── SECURITY.md                         # Security disclosure policy
├── CHANGELOG.md                        # What changed in each version
├── SPEC.md                             # Technical specification
├── pyproject.toml                      # Python project config & linting rules
├── .husky/pre-commit                   # Auto-runs linting on git commit
├── .github/workflows/docker-build.yml  # GitHub Actions CI/CD
├── .github/dependabot.yml              # Automated dependency updates
└── README.md                           # This file (hi)
```

---

## ⚙️ Running Commands

| What you want | Command |
|--------------|---------|
| Start server | `cd sentinel_x_ultra && uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860 --reload` |
| Run frontend dev | `cd sentinel_x_ultra/frontend && npm install && npx vite --host 0.0.0.0 --port 5173` |
| Build frontend | `cd sentinel_x_ultra/frontend && npm install && npm run build` |
| Run all tests | `cd sentinel_x_ultra && python -m pytest tests/ -v` |
| Run tests with coverage | `cd sentinel_x_ultra && python -m pytest tests/ -v --cov=sentinel_x_ultra` |
| Docker Compose | `docker compose up -d` |
| Docker logs | `docker compose logs -f` |

---

## 🔐 API Keys

Copy `.env.example` to `.env` and fill in your keys. At minimum, you need one LLM provider:

| Provider | Sign up | Notes |
|----------|---------|-------|
| **OpenAI** | [platform.openai.com](https://platform.openai.com) | Needs billing |
| **Anthropic** | [console.anthropic.com](https://console.anthropic.com) | Needs billing |
| **Ollama** | [ollama.ai](https://ollama.ai) | **Free**, runs locally |
| **Groq** | [groq.com](https://groq.com) | Free tier available |
| **Shodan** | [account.shodan.io](https://account.shodan.io) | ~100 queries/month free |
| **Censys** | [search.censys.io](https://search.censys.io) | ~250 queries/month free |

### 🔧 Configuring Providers in the UI

1. Open the **Models** tab from the sidebar
2. Click **Add Provider**
3. Select your provider (Anthropic, OpenAI, Groq, etc.)
4. Enter the **Base URL** (e.g., `https://api.anthropic.com` for Anthropic, `https://api.openai.com/v1` for OpenAI)
5. Paste your **API key**
6. Click **Test** — it sends a test message and shows you the response + latency
7. If it works, save it. The key is persisted to `~/.sentinel-x/providers.json`

You can configure different **models per agent** from the same Models tab. For example, use Claude for reasoning agents and a cheaper model for scanning agents.

### 💡 No API key?

The agents still work — they just use deterministic logic instead of AI reasoning. Less smart, but still functional. Perfect for testing the pipeline logic without an API bill.

---

## 🧠 How It All Fits Together

1. **Create a project** → give it a name and optional target domain
2. **The Bug Bounty pipeline** → goes through all 10 agents, each one building on the last
3. **Phase 3 agents** → analyze code, model threats, debate findings
4. **Phase 5 agents** → deep-dive on specific areas (API security, threat hunting, etc.)
5. **Tools** → run nmap, ffuf, John the Ripper, or any integrated tool from the UI
6. **Findings tab** → browse validated results with CVSS scores and OWASP mappings
7. **AI Reports** → generate executive summaries and compliance reports

All of this runs through a **live activity stream** — every agent action, tool result, and error shows up in real-time via WebSocket.

---

## 🏗️ Architecture & Data Flow

```
                     ┌─────────────────────────────┐
                     │      React Web UI (:5173)    │
                     │  (or built dist on :7860)    │
                     └──────────┬──────────────────┘
                                │ HTTP / WebSocket
                                ▼
┌──────────────────────────────────────────────────────┐
│                FastAPI Server (:7860)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐ │
│  │ Activity │ │  Event   │ │   WebSocket Manager  │ │
│  │   Bus    │ │  Store   │ │   (/ws, /ws/{pid})   │ │
│  └────┬─────┘ └────┬─────┘ └──────────────────────┘ │
│       │            │         Broadcasts events      │
│       ▼            ▼           to all listeners     │
│  ┌──────────────────────────────────────────────┐   │
│  │              API Endpoints                    │   │
│  │  /api/projects/*  /api/agents/*  /api/tools/* │   │
│  │  /api/bug-bounty/*  /api/burp/*  /api/recon/*│   │
│  │  /api/analyze/*  /api/auto-select/*          │   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│  ┌──────────────────────▼───────────────────────┐   │
│  │           Multi-Provider LLM Router          │   │
│  │  Anthropic │ OpenAI │ Ollama │ Groq │ Gemini  │   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│  ┌──────────────────────▼───────────────────────┐   │
│  │  Bug Bounty Pipeline  │  Phase 3-5 Agents   │   │
│  │  ┌──→ Agent 1 ──→ 2 ──→ 3 ──→ ... ──→ 10 ─┐│   │
│  │  │     Shared AgentMemory + SecurityGuard   ││   │
│  │  └───────────────────────────────────────────┘│   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│  ┌──────────────────────▼───────────────────────┐   │
│  │  Tool Integrations (async subprocess exec)   │   │
│  │  nmap │ ffuf │ gobuster │ john │ hydra       │   │
│  │  sqlmap │ nuclei │ subfinder │ httpx │ dalfox│   │
│  │  waybackurls │ gau │ xxe │ deserialization  │   │
│  └──────────────────────┬───────────────────────┘   │
│                         │                            │
│  ┌──────────────────────▼───────────────────────┐   │
│  │  Engines & Analyzers                        │   │
│  │  KnowledgeGraph │ PermissionGraph │ RAG      │   │
│  │  CodeAnalyzer │ WebAnalyzer │ Methodology   │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

The data flow is straightforward:

1. **UI → API**: Browser sends HTTP requests to the FastAPI server
2. **API → Agents/Tools**: Endpoints dispatch to agents (AI-powered) or tools (subprocess)
3. **Agents → LLM Router**: Agents call the configured LLM for reasoning, or fall back to deterministic logic
4. **Everything → Activity Bus**: Every action emits an event to the Activity Bus
5. **Activity Bus → UI**: WebSocket pushes events to all connected browsers in real-time
6. **Tools → Results**: Tool output is parsed into structured results and returned to the calling endpoint

---

## 🤔 Troubleshooting

### Server won't start

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `Address already in use` | Port 7860 is taken | Kill the old process or change port in config |
| `ModuleNotFoundError: No module named '...'` | Missing dependency | `pip install -r sentinel_x_ultra/requirements.txt` |
| `SyntaxError` in server.py | Corrupted file from a bad edit | Check the file around the reported line — look for unterminated strings or broken multi-line literals |
| CORS errors in browser | Wrong port | Frontend dev mode uses :5173, backend is :7860 |

### Tools not detected

| Likely cause | Fix |
|-------------|-----|
| Tool not installed | Install it — see the Installation section above |
| Tool in wrong location | Tools are scanned from `~/.sentinelx/tools/` and `~/go/bin/` |
| Missing DLLs (Windows) | John the Ripper needs its `run/` folder with all DLLs present |
| Tool requires Go | Install Go 1.21+ and reinstall the tool via `go install` |

### LLM test fails

| Error | Fix |
|-------|-----|
| `401 Unauthorized` | API key is wrong — double-check it at the provider's dashboard |
| `404 Not Found` | Wrong model name — try a different model from the dropdown |
| `getaddrinfo failed` | Can't reach the URL — check internet, or if using Ollama make sure it's running on port 11434 |
| `Connection refused` | Service not running — start Ollama with `ollama serve` |

### Frontend shows blank page

1. Make sure the server is running — `curl http://localhost:7860/api/health` should return JSON
2. Check the browser console (F12) for errors
3. Rebuild the frontend: `cd sentinel_x_ultra/frontend && npm install && npm run build`
4. Restart the server

### Bug bounty pipeline fails

| Symptom | Fix |
|---------|-----|
| Agent 4 (Passive Intel) fails | Configure Shodan/Censys API keys in `.env` |
| Agent 5 (Active Enum) fails | Install the required tools (ffuf, gobuster, nmap) |
| All agents fail with "LLM not configured" | Configure a provider in the Models tab |
| Pipeline times out | Increase the timeout in the pipeline config, or run agents individually |

---

## 🌐 REST API Reference

All endpoints live under `http://localhost:7860`. Full docs are at `/docs` (Swagger UI).

### System

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check — returns status, version, available providers |
| `GET` | `/api/ws-status` | WebSocket connection status |

### Projects

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `POST` | `/api/projects` | Create project (name, folder, target, type) |
| `GET` | `/api/projects` | List all projects |
| `GET` | `/api/projects/{id}` | Get project details |
| `DELETE` | `/api/projects/{id}` | Delete a project |
| `POST` | `/api/projects/{id}/scope` | Update project scope |
| `GET` | `/api/projects/{id}/findings` | Get deduplicated findings |
| `GET` | `/api/projects/{id}/analysis-summary` | Combined analysis results |
| `POST` | `/api/projects/{id}/full-scan` | Run all agents + tools at once |

### Configuration

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET` | `/api/config/models` | Get model config |
| `POST` | `/api/config/save-key` | Save API key for a provider |
| `GET` | `/api/config/providers` | List configured providers |
| `GET` / `POST` | `/api/config/agent-models` | Get/set per-agent model configs |
| `POST` | `/api/config/test` | Test a provider connection with a sample message |

### Bug Bounty

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET` | `/api/bug-bounty/agents` | List all 10 agents |
| `GET` | `/api/bug-bounty/ethical-rules` | Get ethical rules hierarchy |
| `GET` | `/api/bug-bounty/system-prompt` | Get the full system prompt |
| `POST` | `/api/bug-bounty/pipeline` | Run the full 10-agent pipeline |
| `POST` | `/api/bug-bounty/url-parse` | Parse a HackerOne/BugCrowd URL |

### Agents (Phase 3)

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `POST` | `/api/projects/{id}/agents/recon` | Run reconnaissance agent |
| `POST` | `/api/projects/{id}/agents/code-review` | Run code review agent |
| `POST` | `/api/projects/{id}/agents/threat-modeling` | Run threat modeling agent |
| `POST` | `/api/projects/{id}/agents/dependency` | Run dependency scanner |
| `POST` | `/api/projects/{id}/agents/debate` | Run adversarial debate on findings |

### Agents (Phase 5)

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `POST` | `/api/projects/{id}/agents/threat-intelligence` | YARA, IOC enrichment |
| `POST` | `/api/projects/{id}/agents/security-operations` | SIEM, SOAR, incident mgmt |
| `POST` | `/api/projects/{id}/agents/adaptive-defense` | ML anomaly detection |
| `POST` | `/api/projects/{id}/agents/supply-chain` | SBOM, CVE scanning |
| `POST` | `/api/projects/{id}/agents/api-security` | API fuzzing, auth testing |
| `POST` | `/api/projects/{id}/agents/remediation` | Create fix plans |

### Tools

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET` | `/api/tools/list` | List all registered tools with availability |
| `GET` | `/api/tools/{name}/status` | Get tool version + capabilities |
| `POST` | `/api/tools/john/crack` | Crack hashes with John the Ripper |
| `POST` | `/api/tools/john/generate-hash` | Generate test hashes |
| `GET` | `/api/tools/john/formats` | List supported hash formats |
| `POST` | `/api/tools/hydra/scan` | Brute-force login with Hydra |
| `POST` | `/api/tools/sqlmap/scan` | SQL injection scan with SQLMap |
| `POST` | `/api/tools/xxe/scan` | Test for XXE vulnerabilities |
| `GET` | `/api/tools/xxe/payloads` | Get XXE payloads for manual testing |
| `POST` | `/api/tools/deserialization/scan` | Test for insecure deserialization |
| `GET` | `/api/tools/deserialization/payloads` | Generate deserialization payloads |
| `GET` | `/api/tools/install-guide` | Get installation instructions |

### Reconnaissance

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `GET` | `/api/recon/status` | Get tool status + methodology steps |
| `POST` | `/api/recon/scan` | Run recon on a target (full or phase-specific) |
| `POST` | `/api/recon/install` | Install specific tool or all tools |
| `GET` | `/api/recon/methodology` | Get the full reconnaissance methodology guide |

### Burp Suite

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `POST` | `/api/burp/connect` | Test connection to Burp REST API |
| `POST` | `/api/burp/history` | Fetch proxy history from Burp |
| `POST` | `/api/burp/scan` | Analyze Burp history for vulnerabilities |

### Analysis & Input

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `POST` | `/api/projects/{id}/analyze/code` | SAST code analysis |
| `POST` | `/api/projects/{id}/analyze/web/endpoint` | Web endpoint vuln analysis |
| `POST` | `/api/projects/{id}/rag/index` | Index content for RAG retrieval |
| `GET` | `/api/projects/{id}/rag/query` | Query RAG for relevant context |
| `POST` | `/api/input/urls` | Submit URLs for analysis |
| `POST` | `/api/input/code` | Submit code for analysis |
| `POST` | `/api/input/folder` | Scan a folder for source code |
| `POST` | `/api/input/prompt` | Submit a prompt for AI analysis |
| `POST` | `/api/input/burp-upload` | Upload Burp JSON export |

### Events & WebSocket

| Method | Endpoint | What it does |
|--------|----------|-------------|
| `WebSocket` | `/ws` | Global event stream (all projects) |
| `WebSocket` | `/ws/{project_id}` | Project-scoped event stream |
| `GET` | `/api/events` | Get event history with filters |
| `GET` | `/api/events/status` | Get system event summary |

---

## 📜 License

Proprietary — All rights reserved.


Proprietary — All rights reserved.
