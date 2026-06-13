# Changelog

All notable changes to Sentinel-X Ultra are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Bug Bounty Multi-Agent Framework v7.0** — 10 specialized agents with ethical rules, scope validation, and report generation
- **Docker support** — Multi-stage Dockerfile, docker-compose.yml (dev), docker-compose.prod.yml (production), docker-compose.override.yml (hot-reload)
- **Makefile** — 16 commands for install, dev, build, test, Docker, and cleanup
- **GitHub Actions workflow** — Automatic Docker image build and push to GHCR (with Docker Hub support)
- **CODEOWNERS** — Auto-assignment for maintainers
- **Contributing guide** — `CONTRIBUTING.md` with development setup, code style, PR process, and agent creation guide
- **Security policy** — `SECURITY.md` with disclosure process, ethical framework, and responsible research guidelines
- **Docker integration test** — `scripts/test_docker_integration.sh` for CI pipeline verification
- **Docker entrypoint** — `scripts/entrypoint.sh` with environment validation and optional tool installation
- **Rate limiting** — Token-bucket `RateLimiter` wired into agents 4, 5, 6 with adaptive throttling
- **Docker build caching** — Layer caching for faster rebuilds in CI

### Fixed

- **Rate limiter bug** — `acquire()` return value (wait time) was ignored, making rate limiting a no-op. Now sleeps properly when tokens are depleted.
- **Docker build** — `npm ci --omit=dev` removed (would've skipped Vite/TypeScript, breaking frontend build)
- **Override file network** — Removed reference to undefined `sentinelx_net` network
- **Entrypoint install path** — `install_tools.sh` wasn't copied into Docker image; added to Dockerfile

### Changed

- **README** — Full rewrite: Docker section, Makefile reference, cleaner install flow, 10-agent table, API docs
- **.gitignore** — Added `.sentinel/`, `tools/`, test/dev file patterns, OS files
- **.env.example** — Documented all supported API keys with provider links and free tier limits
- **Bug bounty API** — Added `/api/bug-bounty/*` endpoints for system prompt, agents list, ethical rules

---

## [0.1.0] — 2025-01-15

### Added

- Initial project scaffold
- FastAPI web server with WebSocket activity bus
- Phase 1: Core infrastructure (MemoryEngine, ProviderRegistry, MessageBus, AgentRegistry)
- Phase 2: Analysis engines (CodeAnalyzer, WebAnalyzer, KnowledgeGraphEngine, PermissionGraphEngine, BusinessRuleEngine, RAGEngine)
- Phase 3: Security agents (ReconAgent, CodeReviewAgent, ThreatModelingAgent, DependencyAgent, DebateAgent)
- Phase 4: Remediation & compliance (RemediationAgent, ReportGenerator, ComplianceEngine)
- Phase 5: Advanced security operations (ThreatIntelligenceAgent, SecurityOperationsAgent, AdaptiveDefenseAgent, SupplyChainAgent, APISecurityAgent)
- React frontend with Vite (dashboard, project management, agent controls, findings viewer)
- Burp Suite integration (connect, fetch history, scan proxy data)
- Auto-select agent recommendation system (vulnerability type → best agent)
- Multi-provider LLM support (OpenAI, Anthropic, Groq, OpenRouter, Ollama, LM Studio, vLLM, Gemini, Mistral)
- Bug bounty URL parser for HackerOne/BugCrowd programs
- 22 unit tests across all major modules
- GitHub issues templates (bug report, feature request)
- `pyproject.toml` with ruff and mypy configuration

---

## Template

When cutting a new release, copy the section below and fill in the details:

```markdown
## [X.Y.Z] — YYYY-MM-DD

### Added
- 

### Fixed
- 

### Changed
- 
```
