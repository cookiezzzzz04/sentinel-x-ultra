#!/bin/bash
# =============================================================================
# SENTINEL-X ULTRA — Docker Entrypoint
# =============================================================================
# Validates the environment, installs optional tools if requested, and starts
# the web server.
#
# Environment variables:
#   INSTALL_TOOLS=false     Set to "true" to install security tools at startup
#   SKIP_VALIDATION=false   Set to "true" to skip env validation
# =============================================================================

set -e

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              SENTINEL-X ULTRA — Docker Image               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Environment Validation ──────────────────────────────────────────────────
if [ "${SKIP_VALIDATION}" != "true" ]; then
    echo "┌────────────────────────────────────────────────────────────────┐"
    echo "│ Validating environment...                                     │"
    echo "└────────────────────────────────────────────────────────────────┘"

    # Check for at least one LLM provider API key
    HAS_OPENAI=false
    HAS_ANTHROPIC=false
    HAS_OLLAMA=false

    if [ -n "${OPENAI_API_KEY}" ] && [ "${OPENAI_API_KEY}" != "sk-..." ]; then
        HAS_OPENAI=true
        echo "  ✓ OpenAI API key found"
    fi
    if [ -n "${ANTHROPIC_API_KEY}" ] && [ "${ANTHROPIC_API_KEY}" != "sk-ant-..." ]; then
        HAS_ANTHROPIC=true
        echo "  ✓ Anthropic API key found"
    fi
    if [ -n "${OLLAMA_API_BASE}" ]; then
        HAS_OLLAMA=true
        echo "  ✓ Ollama configured (${OLLAMA_API_BASE})"
    fi

    if [ "${HAS_OPENAI}" = false ] && [ "${HAS_ANTHROPIC}" = false ] && [ "${HAS_OLLAMA}" = false ]; then
        echo ""
        echo "  ⚠  No LLM provider configured!"
        echo "     The server will start, but AI analysis requires at least one of:"
        echo "       - OPENAI_API_KEY"
        echo "       - ANTHROPIC_API_KEY"
        echo "       - OLLAMA_API_BASE (local)"
        echo ""
        echo "     Create a .env file with your API keys and restart."
        echo "     See .env.example for all options."
        echo ""
    else
        echo "  ✅ At least one LLM provider available"
    fi

    # Check for optional data source keys
    if [ -n "${SHODAN_API_KEY}" ]; then
        echo "  ✓ Shodan API key found"
    fi
    if [ -n "${CENSYS_API_ID}" ] && [ -n "${CENSYS_API_SECRET}" ]; then
        echo "  ✓ Censys API credentials found"
    fi
    if [ -n "${SECURITYTRAILS_API_KEY}" ]; then
        echo "  ✓ SecurityTrails API key found"
    fi

    echo ""
fi

# ─── Optional Tool Installation ──────────────────────────────────────────────
if [ "${INSTALL_TOOLS}" = "true" ]; then
    echo "┌────────────────────────────────────────────────────────────────┐"
    echo "│ Installing security tools...                                  │"
    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""

    # Install Go for tool compilation
    if ! command -v go &>/dev/null; then
        echo "  Installing Go..."
        curl -sL "https://go.dev/dl/go1.22.5.linux-amd64.tar.gz" -o /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH="/usr/local/go/bin:$PATH"
        echo "  ✓ Go installed"
    fi

    # Run the tools installer
    INSTALL_TOOLS_DIR="$(dirname "$0")"
    if [ -f "${INSTALL_TOOLS_DIR}/install_tools.sh" ]; then
        bash "${INSTALL_TOOLS_DIR}/install_tools.sh" || true
    else
        echo "  ⚠  install_tools.sh not found, skipping"
    fi

    echo ""
    echo "  Tool installation complete."
    echo ""
fi

# ─── Data Directory ──────────────────────────────────────────────────────────
mkdir -p /root/.sentinel-x

# ─── Start Server ────────────────────────────────────────────────────────────
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ Starting SENTINEL-X ULTRA web server...                        │"
echo "└────────────────────────────────────────────────────────────────┘"
echo ""

# If arguments are passed to the container, use those as the command.
# Otherwise, default to uvicorn.
if [ $# -gt 0 ]; then
    exec "$@"
else
    exec uvicorn sentinel_x_ultra.server:app \
        --host "${SENTINELX_SERVER__HOST:-0.0.0.0}" \
        --port "${SENTINELX_SERVER__PORT:-7860}" \
        --log-level "${SENTINELX_SERVER__LOG_LEVEL:-info}"
fi
