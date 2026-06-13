# =============================================================================
# SENTINEL-X ULTRA — Makefile
# =============================================================================
# Common commands for development, testing, and deployment.
#
# Quick reference:
#   make install       Install Python dependencies + optional tools
#   make dev           Start dev server with hot-reload
#   make build         Build production frontend
#   make docker-build  Build Docker image
#   make up            Start Docker Compose (dev mode)
#   make prod          Start Docker Compose (production mode)
#   make test          Run Python test suite
#   make test-docker   Run Docker integration test
#   make clean         Remove cache, build artifacts, and temp files
# =============================================================================

.SILENT:
.DEFAULT_GOAL := help

# ─── Colors ──────────────────────────────────────────────────────────────────
CYAN  := $(shell tput setaf 6 2>/dev/null || echo "")
GREEN := $(shell tput setaf 2 2>/dev/null || echo "")
YELLOW := $(shell tput setaf 3 2>/dev/null || echo "")
RESET := $(shell tput sgr0 2>/dev/null || echo "")

help: ## Show this help
	@echo ""
	@echo "$(CYAN)SENTINEL-X ULTRA — Commands$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-18s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ─── Environment ─────────────────────────────────────────────────────────────

.PHONY: check-env
check-env:
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)⚠  No .env file found. Copy from .env.example:$(RESET)"; \
		echo "  cp .env.example .env"; \
	fi

# ─── Python ──────────────────────────────────────────────────────────────────

install: check-env ## Install Python dependencies and optional security tools
	@echo "$(CYAN)→ Installing Python dependencies...$(RESET)"
	pip install -r sentinel_x_ultra/requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(RESET)"
	@echo ""
	@echo "$(CYAN)→ Installing security tools into ~/.sentinel/...$(RESET)"
	@if [ -f scripts/install_tools.sh ]; then \
		bash scripts/install_tools.sh; \
	else \
		echo "$(YELLOW)  ⚠  scripts/install_tools.sh not found, skipping$(RESET)"; \
	fi

dev: check-env ## Start dev server with hot-reload (Python backend only)
	@echo "$(CYAN)→ Starting dev server on http://127.0.0.1:7860$(RESET)"
	cd sentinel_x_ultra && uvicorn sentinel_x_ultra.server:app \
		--host 127.0.0.1 \
		--port 7860 \
		--reload \
		--log-level debug

dev-frontend: ## Start frontend dev server with Vite HMR (port 5173)
	@echo "$(CYAN)→ Starting frontend dev server on http://127.0.0.1:5173$(RESET)"
	cd sentinel_x_ultra/frontend && npm install && npm run dev -- --host 0.0.0.0 --port 5173

build: ## Build production frontend
	@echo "$(CYAN)→ Building React frontend...$(RESET)"
	cd sentinel_x_ultra/frontend && npm install && npm run build
	@echo "$(GREEN)✓ Frontend built to sentinel_x_ultra/frontend/dist/$(RESET)"

# ─── Docker ──────────────────────────────────────────────────────────────────

docker-build: ## Build Docker image
	@echo "$(CYAN)→ Building Docker image...$(RESET)"
	docker build -t sentinel-x-ultra .
	@echo "$(GREEN)✓ Docker image built: sentinel-x-ultra:latest$(RESET)"

up: ## Start Docker Compose (dev mode with hot-reload)
	@echo "$(CYAN)→ Starting Docker Compose (dev mode)...$(RESET)"
	docker compose up -d
	@echo "$(GREEN)✓ Server running at http://localhost:7860$(RESET)"

up-frontend: ## Start Docker Compose with frontend dev server
	@echo "$(CYAN)→ Starting Docker Compose with frontend HMR...$(RESET)"
	docker compose --profile dev up -d
	@echo "$(GREEN)✓ Backend at http://localhost:7860  |  Frontend at http://localhost:5173$(RESET)"

prod: ## Start Docker Compose (production mode)
	@echo "$(CYAN)→ Starting production stack...$(RESET)"
	docker compose -f docker-compose.prod.yml up -d
	@echo "$(GREEN)✓ Production stack started$(RESET)"

logs: ## Tail container logs
	docker compose logs -f

stop: ## Stop all Docker containers
	@echo "$(CYAN)→ Stopping...$(RESET)"
	docker compose down
	@echo "$(GREEN)✓ Stopped$(RESET)"

# ─── Testing ─────────────────────────────────────────────────────────────────

test: ## Run Python test suite (unit tests)
	@echo "$(CYAN)→ Running tests...$(RESET)"
	cd sentinel_x_ultra && python -m pytest sentinel_x_ultra/tests/ -v --tb=short
	@echo "$(GREEN)✓ Tests complete$(RESET)"

test-coverage: ## Run tests with coverage report
	@echo "$(CYAN)→ Running tests with coverage...$(RESET)"
	cd sentinel_x_ultra && python -m pytest sentinel_x_ultra/tests/ -v --tb=short --cov=sentinel_x_ultra/bug_bounty
	@echo "$(GREEN)✓ Coverage report complete$(RESET)"

test-docker: ## Run Docker integration test (requires Docker)
	@echo "$(CYAN)→ Running Docker integration test...$(RESET)"
	bash scripts/test_docker_integration.sh

# ─── Utilities ───────────────────────────────────────────────────────────────

clean: ## Remove cache, build artifacts, and temp files
	@echo "$(CYAN)→ Cleaning...$(RESET)"
	# Python cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	# Build artifacts
	rm -rf sentinel_x_ultra/frontend/dist/ 2>/dev/null || true
	rm -rf .pytest_cache/ 2>/dev/null || true
	rm -rf *.egg-info/ 2>/dev/null || true
	# Logs
	rm -f *.log 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned$(RESET)"

clean-all: clean ## Remove virtual environment, node_modules, and Docker images
	@echo "$(CYAN)→ Deep cleaning...$(RESET)"
	rm -rf .venv/ 2>/dev/null || true
	rm -rf sentinel_x_ultra/frontend/node_modules/ 2>/dev/null || true
	-docker rmi sentinel-x-ultra:latest 2>/dev/null || true
	@echo "$(GREEN)✓ Deep clean complete$(RESET)"

# ─── GitHub Actions ──────────────────────────────────────────────────────────

ci: ## Run local CI check (syntax + tests)
	@echo "$(CYAN)→ Running CI checks...$(RESET)"
	cd sentinel_x_ultra && python -c "import ast, os; \
		files = [] ;\
		for root, dirs, fnames in os.walk('sentinel_x_ultra/bug_bounty'): \
			files.extend([os.path.join(root, f) for f in fnames if f.endswith('.py')]); \
		ok = all(ast.parse(open(f, encoding='utf-8').read()) or print(f'OK: {f}') or True for f in files); \
		print('All OK!' if ok else 'SYNTAX ERRORS FOUND')"
	cd sentinel_x_ultra && python -m pytest sentinel_x_ultra/tests/ -v --tb=short
	@echo "$(GREEN)✓ CI checks passed$(RESET)"
