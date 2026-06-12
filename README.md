# SENTINEL-X ULTRA 🛡️

**Autonomous Bug Bounty & Security Analysis Framework**

An AI-powered platform with 10 specialized agents that automate bug bounty hunting — from program parsing and OSINT recon to vulnerability scanning, safe exploitation, and professional report generation.

---

## ⚡ Quick Start

```bash
# 1. Install Python 3.11+, then:
pip install -r requirements.txt          # Python dependencies

# 2. Install 30+ security tools into ~/.sentinel/
bash scripts/install_tools.sh

# 3. Set at least one LLM API key
cp .env.example .env                    # Then edit .env with your keys

# 4. Start the web UI
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

Open **http://127.0.0.1:7860** in your browser.

---

## 📋 Requirements

| Requirement | Details | Optional? |
|-------------|---------|-----------|
| Python 3.11+ | Core runtime | ❌ Required |
| API Key (u can do some provider look down to see all the providers) | Powers AI analysis (CVSS, CWE, reports) | ❌ Required |
| Go 1.21+ | Installs subfinder, httpx, nuclei, etc. | ✅ Optional (skipped if missing) |
| Shodan / Censys / SecurityTrails keys | Live internet intelligence in Agent 4 | ✅ Optional |

---

## 🧠 The 10 Bug Bounty Agents

The pipeline runs all 10 agents in sequence. Each agent uses AI reasoning (via OpenAI/Claude/Ollama) to make smart decisions:

| # | Agent | What It Does |
|---|-------|-------------|
| 1 | **URL Parser** | Parses HackerOne/BugCrowd programs → extracts scope, policy, rewards |
| 2 | **Policy Enforcer** | 12-phase policy decisions: ALLOW / REVIEW / REJECT every finding |
| 3 | **Scope Guardian** | Multi-layer scope authorization — detects third-party domains |
| 4 | **Passive Intel** | OSINT recon + Shodan / Censys / SecurityTrails / URLScan |
| 5 | **Active Enumeration** | Dirsearch, Gobuster, FFUF, Nmap → maps attack surface |
| 6 | **Vuln Scanner** | Nuclei, SQLMap, Dalfox + AI hypothesis generation (OWASP Top 10) |
| 7 | **Validation Engine** | Adversarial false-positive elimination, skeptic scoring |
| 8 | **Exploitation** | Generates safe, reproducible proof-of-concept exploits |
| 9 | **Analysis** | Evidence-driven CVSS 3.1 scoring, CWE classification, OWASP mapping |
| 10 | **Report Generation** | Professional vulnerability reports (Blank.md format) |

### Infrastructure

| Module | What It Does |
|--------|-------------|
| **AgentMemory** | Shared knowledge across agents — assets, priorities, provenance chains |
| **DataSourceAggregator** | Cached API clients for Shodan, Censys, SecurityTrails, URLScan |
| **LLMProvider** | Unified interface for OpenAI / Claude / Ollama — 10 analysis methods |
| **ExecutionEngine** | Parallel executor, LRU cache, token-bucket rate limiter, circuit breaker |
| **SecurityGuard** | Scope validation, PII/secret redaction, ethical rule enforcement, resource caps |

---

## 🔧 Setup Guide

### Step 1: Python Environment

```bash
# Create and activate a virtual environment (recommended)
python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\activate
# Windows (Git Bash):
source .venv/Scripts/activate
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
```

### Step 2: Install Security Tools

```bash
bash scripts/install_tools.sh
```

This installs everything to `~/.sentinel/` (gitignored — stays on your machine):

| Category | Tools |
|----------|-------|
| **Go-based** | subfinder, waybackurls, httpx, nuclei, dalfox, gau, gobuster, ffuf |
| **Python** | sqlmap, nmap |
| **Cloned repos** | BigBountyRecon (Google Dorking), SubEnum, sqlifinder |
| **Templates** | 2500+ Nuclei vulnerability templates |
| **Wordlists** | Subdomain brute force + directory enumeration |

The script skips any tool where the prerequisite (Go, pip) is missing — no errors.

### Step 3: API Keys

```bash
cp .env.example .env
```

Edit `.env` and fill in **at least one** LLM provider key:

```ini
# Required (pick one):
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Optional — enables live internet intelligence:
SHODAN_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
SECURITYTRAILS_API_KEY=...
```

The framework auto-detects which provider to use. Order of preference: OpenAI → Claude → Ollama.

### Step 4: Run

```bash
python -m uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860
```

---

## 🐳 Docker Deployment

### Quick Start with Docker Compose

```bash
# Start the server (builds the image on first run)
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

Open **http://localhost:7860** in your browser.

### Manual Docker Build

```bash
docker build -t sentinel-x-ultra .
docker run -d \
  --name sentinel-x-ultra \
  -p 7860:7860 \
  --env-file .env \
  -v sentinelx_data:/root/.sentinel-x \
  sentinel-x-ultra
```

### What's Included in the Docker Image

| Component | Included? | Notes |
|-----------|-----------|-------|
| Python backend (FastAPI) | ✅ | Core server on port 7860 |
| React frontend (Vite) | ✅ | Built as static assets, served by backend |
| All Python dependencies | ✅ | From `requirements.txt` |
| LLM API integration | ✅ | OpenAI, Anthropic, Ollama (requires `.env`) |
| Security tools (nuclei, ffuf, etc.) | ❌ | Install locally via `bash scripts/install_tools.sh` |

> **Security tools are excluded** from the Docker image to keep it lightweight (~200 MB).
> For full functionality including nuclei, ffuf, nmap, etc., install them locally
> with `bash scripts/install_tools.sh` — the server auto-detects them from `~/.sentinel/`.

### Data Persistence

- **Projects & config** → stored in a named Docker volume (`sentinelx_data`)
- **Environment** → passed via `.env` file (mounted by docker-compose)
- **Files to scan** → mount a local directory with `-v ./workspace:/workspace:ro`

---

## 🔬 How Agents Use AI

Every agent has access to an LLM provider. When API keys are configured, agents use AI reasoning for smart decisions:

- **Agent 4 (Passive Intel):** LLM prioritizes discovered assets by business value
- **Agent 6 (Vuln Scanner):** LLM generates vulnerability hypotheses and rates them by likelihood
- **Agent 7 (Validation):** LLM performs adversarial review to eliminate false positives
- **Agent 9 (Analysis):** LLM derives CVSS 3.1 metrics and CWE classifications from evidence
- **Agents 2, 3, 5, 8, 10:** LLM enhances policy decisions, risk assessment, and report quality

When no API key is configured, all agents fall back to deterministic logic — still functional, just less intelligent.

---

## 📡 Key API Endpoints

```bash
# Bug Bounty Pipeline
POST /api/bug-bounty/pipeline          # Run all 10 agents
GET  /api/bug-bounty/agents            # List agent descriptions
GET  /api/bug-bounty/system-prompt     # Foundational principles
POST /api/bug-bounty/url-parse         # Parse a HackerOne/BugCrowd URL

# Security Analysis
POST /api/projects/{id}/agents/recon          # Reconnaissance
POST /api/projects/{id}/agents/code-review    # Code review
POST /api/projects/{id}/agents/debate         # Validate findings
POST /api/projects/{id}/analyze/code          # SAST analysis
POST /api/projects/{id}/analyze/web/endpoint  # Web vuln scan
```

---

## 🧪 Tests

```bash
cd sentinel_x_ultra
python -m pytest sentinel_x_ultra/tests/test_bug_bounty.py -v
```

22 tests covering: agent creation, shared memory, data source caching, LLM fallback, CVSS/CWE derivation, imports.

---

## 🏗️ Project Structure

```
sentinel-x-ultra/
├── scripts/install_tools.sh     ← One-command tool installer
├── .env.example                 ← API key template
├── sentinel_x_ultra/
│   ├── server.py                ← Web server
│   ├── config.py                ← Settings
│   └── bug_bounty/              ← 10-agent pipeline
│       ├── orchestrator.py      ← Pipeline runner
│       ├── agent_memory.py      ← Shared knowledge store
│       ├── data_sources.py      ← Shodan/Censys/Trails clients
│       ├── llm_provider.py      ← OpenAI/Claude/Ollama
│       ├── execution_engine.py  ← Rate limiter, cache, circuit breaker
│       ├── security_guard.py    ← Ethics, scope, PII sanitizer
│       ├── url_parser.py .. report_generation.py  ← Agents 1-10
├── frontend/                    ← React web UI
├── .gitignore                   ← Ignores .sentinel/, .env, __pycache__
├── requirements.txt
└── pyproject.toml
```

---

## 🔐 LLM Provider URLs

| Provider | Base URL |
|----------|----------|
| OpenAI | `https://api.openai.com/v1` |
| Anthropic | `https://api.anthropic.com` |
| Ollama (local) | `http://localhost:11434` |
| Google | `https://generativelanguage.googleapis.com/v1beta` |
| Groq | `https://api.groq.com/openai/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |

---

## 📄 License

Proprietary — All rights reserved
