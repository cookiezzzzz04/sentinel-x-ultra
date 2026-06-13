# Contributing to Sentinel-X Ultra

First off, thanks for taking the time to contribute! 🛡️

This document outlines the development workflow, code standards, and processes for contributing to the project.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Writing Tests](#writing-tests)
- [Adding a New Bug Bounty Agent](#adding-a-new-bug-bounty-agent)
- [Code Style & Conventions](#code-style--conventions)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Development Setup

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.11+ | Core runtime |
| Node.js | 20+ | Frontend development only |
| Go | 1.21+ | Optional — for security tools |
| Docker | 24+ | Optional — containerized development |

### 1. Clone and Set Up Python

```bash
git clone https://github.com/your-org/Sentinel-X-Ultra.git
cd Sentinel-X-Ultra

# Create a virtual environment
python -m venv .venv

# Activate it
# Windows (PowerShell):   .venv\Scripts\activate
# Windows (Git Bash):     source .venv/Scripts/activate
# Linux/Mac:              source .venv/bin/activate

# Install dependencies
pip install -r sentinel_x_ultra/requirements.txt
```

### 2. Configure API Keys (Optional but Recommended)

```bash
cp .env.example .env
```

Edit `.env` with at least one LLM provider key (OpenAI or Anthropic). See [.env.example](.env.example) for all available options.

### 3. Install Security Tools (Optional)

```bash
bash scripts/install_tools.sh
```

Installs 10+ reconnaissance and scanning tools into `~/.sentinel/`. This step is optional — agents fall back to deterministic logic when tools aren't available.

### 4. Verify Everything Works

```bash
# Run the test suite
cd sentinel_x_ultra
python -m pytest sentinel_x_ultra/tests/ -v --tb=short
```

All 22 tests should pass.

---

## Project Structure

```
sentinel-x-ultra/
├── scripts/
│   ├── install_tools.sh          # Security tool installer
│   ├── entrypoint.sh             # Docker entrypoint
│   ├── recon_install.sh          # Alternative recon tool installer
│   └── test_docker_integration.sh # Integration test
├── sentinel_x_ultra/
│   ├── server.py                 # FastAPI web server (main entry point)
│   ├── config.py                 # Settings & environment configuration
│   ├── __main__.py               # CLI entry point
│   ├── cli.py                    # CLI interface
│   ├── models.py                 # Pydantic models
│   ├── providers.py              # LLM provider abstraction
│   ├── validation.py             # Input validation
│   ├── workspace.py              # Project workspace management
│   ├── memory.py                 # Agent memory system
│   ├── coverage.py               # Coverage analysis
│   ├── rag.py                    # RAG (Retrieval-Augmented Generation)
│   ├── recon_tools.py            # Reconnaissance tool wrappers
│   ├── recon_api.py              # Recon API endpoints
│   ├── recon_methodology.py      # Recon methodology engine
│   ├── burp_proxy.py             # Burp Suite integration
│   ├── burp_input_endpoints.py   # Burp input endpoints
│   ├── new_endpoints.py          # Endpoint discovery tools
│   ├── v3_endpoints.py           # V3 API endpoints
│   ├── _fix_endpoints.py         # Temporary endpoint fixes
│   ├── project_context.py        # Project context management
│   ├── research_memory.py        # Research memory persistence
│   ├── seed_templates.py         # Report seed templates
│   ├── report_template.py        # Report generation templates
│   ├── terminal.py               # Terminal utilities
│   ├── ollama_embedder.py        # Ollama embedding integration
│   ├── nmap_tool.py              # Nmap wrapper
│   ├── ffuf_tool.py              # FFUF wrapper
│   ├── gobuster_tool.py          # Gobuster wrapper
│   ├── bug_bounty/               # <-- 10-agent pipeline (core feature)
│   │   ├── orchestrator.py       # Pipeline runner & rate limiter
│   │   ├── agent_memory.py       # Shared knowledge store
│   │   ├── data_sources.py       # Shodan/Censys/SecurityTrails clients
│   │   ├── llm_provider.py       # OpenAI/Claude/Ollama interface
│   │   ├── execution_engine.py   # Rate limiter, cache, circuit breaker
│   │   ├── security_guard.py     # Ethics, scope, PII sanitizer
│   │   ├── system_prompts.py     # Foundational Principles & prompts
│   │   ├── webhook.py            # Webhook notifications
│   │   ├── url_parser.py         # Agent 1
│   │   ├── policy_enforcer.py    # Agent 2
│   │   ├── scope_guardian.py     # Agent 3
│   │   ├── passive_intel.py      # Agent 4
│   │   ├── active_enum.py        # Agent 5
│   │   ├── vuln_scanner.py       # Agent 6
│   │   ├── validation_engine.py  # Agent 7
│   │   ├── exploitation.py       # Agent 8
│   │   ├── analysis.py           # Agent 9
│   │   └── report_generation.py  # Agent 10
│   ├── agents/                   # Additional agent modules
│   │   ├── phase3.py
│   │   ├── phase4.py
│   │   └── phase5.py
│   ├── analyzers/
│   │   ├── code_analyzer.py      # SAST code analysis
│   │   └── web_analyzer.py       # Web vulnerability analysis
│   ├── engines/
│   │   ├── business_rules.py     # Business logic rules engine
│   │   ├── knowledge_graph.py    # Knowledge graph engine
│   │   └── permission_graph.py   # Permission analysis engine
│   └── tests/
│       ├── test_bug_bounty.py    # 22 tests for the 10-agent pipeline
│       ├── test_burp_proxy.py
│       ├── test_v3.py
│       └── ... (more test files)
├── frontend/
│   ├── src/
│   │   ├── App.tsx               # Main React application
│   │   ├── panel_components.tsx  # Dashboard panels
│   │   ├── main.tsx              # React entry point
│   │   └── index.css             # Global styles
│   ├── dist/                     # Built frontend (gitignored)
│   ├── index.html
│   ├── vite.config.ts
│   ├── package.json
│   └── tsconfig.json
├── Makefile                      # Common commands
├── Dockerfile                    # Multi-stage Docker image
├── docker-compose.yml            # Docker Compose (dev)
├── docker-compose.prod.yml       # Docker Compose (production)
├── docker-compose.override.yml   # Dev overrides (auto-merged)
├── .env.example                  # API key template
├── SPEC.md                       # Technical specification
├── SECURITY.md                   # Security & disclosure policy
├── requirements.txt
└── pyproject.toml
```

### Key Architecture Decisions

- **10-agent pipeline** — Agents run sequentially, each with a focused responsibility. They share context via `AgentMemory` and coordinate through the `BugBountyOrchestrator`.
- **`AgentMemory`** — A shared knowledge store that passes discovered assets, priority targets, and findings between agents. Uses deduplication and provenance tracking.
- **`ExecutionEngine`** — Every external API call goes through this layer, which provides: token-bucket rate limiting, LRU caching, and circuit breaker protection.
- **`SecurityGuard`** — All agents route scope checks, ethical rule enforcement, and output sanitization through this module. The decision hierarchy (Legal → Policy → Validation → Quality → Efficiency) is non-negotiable.
- **`LLMProvider`** — Abstract interface over OpenAI, Anthropic, and Ollama. Falls back to deterministic logic when no API key is configured.

---

## Development Workflow

### Using the Makefile

```bash
make install          # Install Python deps + security tools
make dev              # Start server with hot-reload on :7860
make build            # Build production frontend
make test             # Run unit tests
make test-coverage    # Run tests with coverage report
make clean            # Remove cache & artifacts
make ci               # Local CI (syntax check + tests)
```

### Running the Server Manually

```bash
# Python backend (hot-reload enabled)
cd sentinel_x_ultra
uvicorn sentinel_x_ultra.server:app --host 127.0.0.1 --port 7860 --reload --log-level debug

# Or using the module directly:
python -m sentinel_x_ultra.server

# Frontend (separate terminal, Vite HMR on :5173)
cd sentinel_x_ultra/frontend
npm install && npm run dev -- --host 0.0.0.0 --port 5173
```

### Docker Development

```bash
make up              # Start in dev mode (with hot-reload via override)
make up-frontend     # Start with frontend HMR server
make prod            # Start in production mode
make logs            # Tail container logs
make stop            # Stop containers
make test-docker     # Run full integration test
```

The `docker-compose.override.yml` auto-merges with `docker-compose.yml` — no need to pass `-f` flags. It mounts your source code live and enables `--reload` for instant feedback.

### Git Workflow

1. Create a branch from `main`: `git checkout -b feat/your-feature-name`
2. Make your changes with clear, descriptive commits
3. Run tests before pushing: `make test` or `make ci`
4. Open a pull request against `main`
5. Ensure CI passes (GitHub Actions runs tests + Docker build)

**Commit style:** Use conventional commits:

```
feat: add new bug bounty agent for API fuzzing
fix: correct rate limiter acquiring wait time
docs: update README with Docker deployment steps
refactor: extract scope validation into reusable module
test: add tests for Agent 9 CVSS fallback logic
```

---

## Writing Tests

### Test Framework

We use **pytest** with `pytest-asyncio` for async tests. All tests live in `sentinel_x_ultra/tests/`.

### Running Tests

```bash
# Run all tests
cd sentinel_x_ultra
python -m pytest sentinel_x_ultra/tests/ -v --tb=short

# Run with coverage
python -m pytest sentinel_x_ultra/tests/ -v --tb=short --cov=sentinel_x_ultra/bug_bounty

# Run a specific test file
python -m pytest sentinel_x_ultra/tests/test_bug_bounty.py -v --tb=short

# Run a specific test class or method
python -m pytest sentinel_x_ultra/tests/test_bug_bounty.py::TestBugBountyOrchestrator -v
```

### What to Test

| Scenario | Example |
|----------|---------|
| **Agent creation** | All 10 agents instantiate without errors, accept `llm_provider` and `memory` params |
| **Data flow** | `AgentMemory` correctly records and retrieves assets across agents |
| **Fallback logic** | `LLMProvider` returns fallback responses when no API key is configured |
| **Deterministic behavior** | Agent 9's CVSS/CWE classification produces correct results without an LLM |
| **Deduplication** | Duplicate assets in `AgentMemory` are merged with higher confidence kept |
| **Imports** | All agent modules import cleanly without circular dependency errors |
| **Edge cases** | Empty evidence, missing parameters, degraded states |

### Test Conventions

- Use descriptive test method names: `test_memory_record_and_read_asset` not `test_memory_1`
- Group related tests in classes: `class TestAgentMemory`
- Add a docstring to every test explaining what it verifies
- Mark async tests with `@pytest.mark.asyncio`
- Use `from sentinel_x_ultra.bug_bounty.xxx import ...` (full module path)
- Add test fixtures to `conftest.py` when shared across test files

```python
# Example: Good test structure
class TestAgentMemory:
    """Test the cross-agent shared memory store."""

    def test_memory_record_and_read_asset(self):
        """Verify assets can be recorded and retrieved."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory

        memory = AgentMemory()
        memory.record_asset("agent_4", "example.com", "DOMAIN", 0.95)

        assets = memory.get_assets()
        assert len(assets) == 1
        assert assets[0]["name"] == "example.com"
        assert assets[0]["confidence"] == 0.95
```

---

## Adding a New Bug Bounty Agent

Each agent follows a consistent pattern. Here's the checklist:

### 1. Create the Agent File

Create `sentinel_x_ultra/sentinel_x_ultra/bug_bounty/your_agent.py`:

```python
"""Agent X: Your Agent Name — one-line description."""

from typing import Optional, Any
from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory
from sentinel_x_ultra.bug_bounty.llm_provider import LLMProvider


class YourAgent:
    """One-paragraph description of what this agent does and when it runs."""

    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        memory: Optional[AgentMemory] = None,
    ):
        self.llm_provider = llm_provider
        self.memory = memory
        self.name = "Your Agent Name"
        self.description = "What this agent does"

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute this agent's work and return results."""
        # Your logic here
        return {"status": "completed", "findings": []}
```

### 2. Register in the Orchestrator

In `sentinel_x_ultra/sentinel_x_ultra/bug_bounty/orchestrator.py`:

```python
from .your_agent import YourAgent

# In __init__:
self.agent_X = YourAgent(
    llm_provider=self.llm_provider,
    memory=self.memory,
)

# In run_pipeline:
context = await self._run_agent_X(context)
```

### 3. Add System Prompt Reference

In `sentinel_x_ultra/sentinel_x_ultra/bug_bounty/system_prompts.py`, add your agent's section to `AGENT_ARCHITECTURE`.

### 4. Update the API

In `sentinel_x_ultra/server.py`, add the new agent to the `/api/bug-bounty/agents` response array. Also update the UI in `frontend/src/App.tsx` to add the new agent card and optional panel tab.

If any integration tests hardcode an agent count check (e.g. `assert total_agents == 10`), update them to match the new count.

### 5. Write Tests

Add tests to `sentinel_x_ultra/tests/test_bug_bounty.py`:

```python
class TestYourAgent:
    """Test Your Agent."""

    def test_agent_creates(self):
        """Verify agent creates successfully."""
        from sentinel_x_ultra.bug_bounty.your_agent import YourAgent
        agent = YourAgent()
        assert agent is not None
        assert agent.name == "Your Agent Name"

    def test_agent_accepts_llm_provider(self):
        """Verify agent accepts llm_provider parameter."""
        from sentinel_x_ultra.bug_bounty.your_agent import YourAgent
        agent = YourAgent(llm_provider=None)
        assert agent.llm_provider is None
```

### 6. Update APIs & Frontend

Update these files to expose the new agent:

| File | What to update |
|------|---------------|
| `sentinel_x_ultra/server.py` | Add `/api/bug-bounty/agents` entry in the response |
| `frontend/src/App.tsx` | Add agent to the `agents` state + optional panel tab |

### Agent Responsibilities & Patterns

| Aspect | Pattern |
|--------|---------|
| **Input** | Accepts `context` dict from previous agent |
| **Output** | Returns dict with `status`, `findings`, data to pass forward |
| **Memory** | Reads/writes shared assets via `self.memory.record_asset()` |
| **Rate Limiting** | Uses `self.rate_limiter.acquire(tokens=N)` for external calls |
| **Scope Checking** | Uses `ScopeGuardian` or direct `execution_engine.security_guard` |
| **LLM Usage** | Checks `self.llm_provider is not None` before calling, always has fallback |

---

## Code Style & Conventions

### Python

- **Formatter**: Follow PEP 8. Use `black` or `autopep8` if you like — no strict requirement.
- **Imports**: Standard library → third-party → local. One import per line.
- **Type hints**: Required for all function signatures. Use `Optional[Type]` instead of `Type | None` for Python 3.9 compat.
- **Docstrings**: Required for all classes and public methods. Use triple quotes with a one-line summary.
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_CASE` for constants.
- **Async**: Use `async def` and `await` for all I/O operations. Wrap synchronous calls in `asyncio.to_thread()` if needed.

```python
# Good
from typing import Optional

class AgentMemory:
    """Cross-agent shared knowledge store with deduplication."""

    def record_asset(
        self,
        discovered_by: str,
        name: str,
        asset_type: str,
        confidence: float,
        metadata: Optional[dict] = None,
    ) -> None:
        """Record a discovered asset into shared memory."""
        ...
```

### TypeScript / React

- **Formatter**: Prettier (via Vite config)
- **Naming**: `camelCase` for variables/functions, `PascalCase` for components
- **Styles**: CSS-in-JS via template literals (project convention)
- **State**: Use `useState` / `useEffect` hooks — no Redux or external state management

### Markdown (Documentation)

- Wrap code blocks with language identifier: ` ```python `
- Use tables for structured data
- Keep line lengths under 100 characters
- Use `---` horizontal rules sparingly for section breaks

---

## Pull Request Process

1. **Ensure tests pass**: Run `make test` or `make ci` before opening a PR
2. **Keep PRs focused**: One feature/fix per PR. Large changes should be broken into smaller, reviewable units
3. **Write a clear description**: What does this change do? Why is it needed? How was it tested?
4. **Reference issues**: Link to any related GitHub issues: `Closes #123`
5. **Update documentation**: If you add a feature, update the README, SECURITY.md, or this CONTRIBUTING.md as needed
6. **Add tests**: New features require tests. Bug fixes require a test that would have caught the bug
7. **Await review**: A maintainer will review your PR. Address feedback with additional commits (no force-pushing)

### PR Checklist

Before submitting, ensure:

- [ ] Tests pass locally: `make test`
- [ ] New tests cover the change
- [ ] Type hints are correct
- [ ] No print/console.log statements left in (use proper logging)
- [ ] `.env` secrets are not committed
- [ ] API changes are reflected in the frontend
- [ ] README/docs are updated if user-facing

---

## Reporting Bugs

Open a [GitHub issue](https://github.com/your-org/Sentinel-X-Ultra/issues/new) with:

- **Title**: Clear, descriptive summary
- **Environment**: Python version, OS, API provider (if applicable)
- **Steps to reproduce**: Minimal, complete, verifiable steps
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened (logs, error messages, screenshots)
- **Additional context**: Any relevant configuration, file contents, or recent changes

**Do not** report security vulnerabilities in public issues. See [SECURITY.md](SECURITY.md) for the disclosure process.

---

## Feature Requests

Open a [GitHub issue](https://github.com/your-org/Sentinel-X-Ultra/issues/new) with:

- **Problem**: What problem are you trying to solve?
- **Proposed solution**: Your idea for how to solve it
- **Alternatives**: Any alternative solutions you've considered
- **Context**: How this fits into your workflow or use case

Feature requests that align with the project's scope (autonomous bug bounty automation, security analysis, AI-powered vulnerability detection) are most likely to be accepted.

---

## Additional Resources

- [README.md](README.md) — Project overview, quick start, architecture diagram, REST API docs, troubleshooting
- [SECURITY.md](SECURITY.md) — Security disclosure policy & ethical guidelines
- [.env.example](.env.example) — All supported configuration options
- [Makefile](Makefile) — Common development commands
- [Dockerfile](Dockerfile) — Production deployment configuration
- `scripts/recon_install.sh` — Alternative recon tool installer

### Troubleshooting

See the **[Troubleshooting section](README.md#-troubleshooting)** in the README for common issues:

- Server won't start (port conflicts, missing deps, syntax errors)
- Tools not detected (wrong locations, missing DLLs)
- LLM test fails (wrong keys, wrong model names, connection issues)
- Frontend shows blank page (need to rebuild, check console errors)
- Bug bounty pipeline fails (LLM not configured, tools not installed, timeouts)

---

*Sentinel-X Ultra is a security research tool. Always operate within authorized scopes and comply with applicable laws.*
