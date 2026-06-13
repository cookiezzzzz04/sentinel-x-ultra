# =============================================================================
# SENTINEL-X ULTRA — Multi-Stage Dockerfile
# =============================================================================
# Stage 1: Build the React frontend
# Stage 2: Python runtime with backend
#
# Build: docker build -t sentinel-x-ultra .
# Run:   docker run -p 7860:7860 --env-file .env sentinel-x-ultra
# =============================================================================

# ─── Stage 1: Frontend Build ─────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /build/frontend

# Copy package files and install
COPY sentinel_x_ultra/frontend/package.json sentinel_x_ultra/frontend/package-lock.json* ./
RUN npm ci 2>/dev/null || npm install

# Copy source and build
COPY sentinel_x_ultra/frontend/ .
RUN npm run build

# ─── Stage 2: Python Runtime ─────────────────────────────────────────────────
FROM python:3.11-slim

LABEL name="Sentinel-X Ultra"
LABEL description="Autonomous Security Analysis Intelligence Framework"
LABEL version="0.1.0"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies for Python packages and optional tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies first (cached if requirements don't change)
COPY sentinel_x_ultra/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python package
COPY sentinel_x_ultra/sentinel_x_ultra/ sentinel_x_ultra/
COPY sentinel_x_ultra/pyproject.toml sentinel_x_ultra/README.md ./

# Copy the built frontend from Stage 1
COPY --from=frontend-builder /build/frontend/dist/ frontend/dist/

# Copy entrypoint and tool installer
COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/install_tools.sh /install_tools.sh
RUN chmod +x /entrypoint.sh /install_tools.sh

# Create data directory
RUN mkdir -p /root/.sentinel-x

# Expose the web server port
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/api/health')" || exit 1

# Default: start the web server via entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "sentinel_x_ultra.server:app", "--host", "0.0.0.0", "--port", "7860"]
