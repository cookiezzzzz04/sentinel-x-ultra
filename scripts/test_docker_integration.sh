#!/bin/bash
# =============================================================================
# SENTINEL-X ULTRA — Docker Integration Test
# =============================================================================
# Builds the Docker image, starts the container, tests the /api/health
# endpoint, and cleans up.
#
# Usage:
#   bash scripts/test_docker_integration.sh
#
# Prerequisites:
#   - Docker and Docker Compose installed
#   - Port 7860 must be free
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTAINER_NAME="sentinel-x-ultra-integration-test"
IMAGE_NAME="sentinel-x-ultra:integration-test"
TEST_PASSED=true
PASS_COUNT=0
FAIL_COUNT=0

# ─── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((PASS_COUNT++))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    TEST_PASSED=false
    ((FAIL_COUNT++))
}

# ─── Sanity Checks ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║    SENTINEL-X ULTRA — Docker Integration Test              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [1/6] Checking prerequisites                                 │"
echo "└────────────────────────────────────────────────────────────────┘"

if command -v docker &>/dev/null; then
    pass "Docker installed ($(docker --version))"
else
    fail "Docker is not installed. Install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

if docker compose version &>/dev/null; then
    pass "Docker Compose installed ($(docker compose version --short 2>/dev/null || echo 'available'))"
else
    fail "Docker Compose not found"
    exit 1
fi

# Clean up any leftover containers from a previous failed run
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

# ─── Build ────────────────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [2/6] Building Docker image                                   │"
echo "└────────────────────────────────────────────────────────────────┘"

BUILD_START=$(date +%s%N)
if docker build -t "${IMAGE_NAME}" -f "${PROJECT_DIR}/Dockerfile" "${PROJECT_DIR}" 2>&1 | tail -5; then
    BUILD_END=$(date +%s%N)
    BUILD_MS=$(( (BUILD_END - BUILD_START) / 1000000 ))
    pass "Image built in ${BUILD_MS}ms"
else
    fail "Docker build failed"
    exit 1
fi

# ─── Start Container ─────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [3/6] Starting container                                      │"
echo "└────────────────────────────────────────────────────────────────┘"

# Create a minimal .env for testing if none exists
TEST_ENV_FILE="${PROJECT_DIR}/.env.test"
if [ ! -f "${TEST_ENV_FILE}" ]; then
    cat > "${TEST_ENV_FILE}" << 'EOF'
# Test environment — no real API keys needed for health check
SENTINELX_SERVER__HOST=0.0.0.0
SENTINELX_SERVER__PORT=7860
SENTINELX_SERVER__LOG_LEVEL=INFO
EOF
    pass "Created temporary .env.test"
fi

CONTAINER_ID=$(docker run -d \
    --name "${CONTAINER_NAME}" \
    -p 7860:7860 \
    --env-file "${TEST_ENV_FILE}" \
    --health-cmd "python -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:7860/api/health\")'" \
    --health-interval 3s \
    --health-retries 10 \
    --health-start-period 15s \
    --health-timeout 5s \
    "${IMAGE_NAME}" 2>&1)

if [ -n "${CONTAINER_ID}" ]; then
    pass "Container started (${CONTAINER_ID:0:12})"
else
    fail "Failed to start container"
    exit 1
fi

# ─── Wait for Healthy ────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [4/6] Waiting for container to become healthy                  │"
echo "└────────────────────────────────────────────────────────────────┘"

MAX_WAIT=60
WAIT=0
HEALTHY=false

while [ ${WAIT} -lt ${MAX_WAIT} ]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "starting")
    if [ "${STATUS}" = "healthy" ]; then
        HEALTHY=true
        pass "Container healthy after ${WAIT}s"
        break
    elif [ "${STATUS}" = "unhealthy" ]; then
        fail "Container became unhealthy"
        docker logs "${CONTAINER_NAME}" --tail 20
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
    echo -n "."
done
echo ""

if [ "${HEALTHY}" = false ]; then
    fail "Container did not become healthy within ${MAX_WAIT}s"
    echo ""
    echo "  Container logs:"
    docker logs "${CONTAINER_NAME}" --tail 30
fi

# ─── Test API Endpoints ──────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [5/6] Testing API endpoints                                  │"
echo "└────────────────────────────────────────────────────────────────┘"

if [ "${HEALTHY}" = true ]; then
    # Test /api/health
    HEALTH_RESPONSE=$(curl -s http://localhost:7860/api/health 2>/dev/null || echo "")
    if echo "${HEALTH_RESPONSE}" | python -c "import sys,json; d=json.load(sys.stdin); assert d.get('status') == 'ok'" 2>/dev/null; then
        pass "/api/health returned status=ok"
    else
        fail "/api/health did not return expected response"
        echo "    Got: ${HEALTH_RESPONSE}"
    fi

    # Test root serves frontend
    ROOT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:7860/ 2>/dev/null || echo "000")
    if [ "${ROOT_STATUS}" = "200" ]; then
        pass "Frontend served at / (HTTP ${ROOT_STATUS})"
    else
        fail "Frontend not served at / (HTTP ${ROOT_STATUS})"
    fi

    # Test /api/bug-bounty/agents endpoint
    AGENTS_RESPONSE=$(curl -s http://localhost:7860/api/bug-bounty/agents 2>/dev/null || echo "")
    AGENT_COUNT=$(echo "${AGENTS_RESPONSE}" | python -c "import sys,json; print(json.load(sys.stdin).get('total_agents', 0))" 2>/dev/null || echo "0")
    if [ "${AGENT_COUNT}" -eq 10 ]; then
        pass "/api/bug-bounty/agents returned 10 agents"
    else
        fail "/api/bug-bounty/agents returned ${AGENT_COUNT} agents (expected 10)"
        echo "    Response: ${AGENTS_RESPONSE}"
    fi
fi

# ─── Cleanup ─────────────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [6/6] Cleaning up                                             │"
echo "└────────────────────────────────────────────────────────────────┘"

docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 && pass "Container stopped"
docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 && pass "Container removed"
docker image rm "${IMAGE_NAME}" >/dev/null 2>&1 || true

# Remove test .env if it was created by us
if [ -f "${TEST_ENV_FILE}" ] && grep -q "Test environment" "${TEST_ENV_FILE}"; then
    rm -f "${TEST_ENV_FILE}"
fi

# ─── Results ─────────────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ Test Results                                                  │"
echo "└────────────────────────────────────────────────────────────────┘"
echo ""
echo "  ${GREEN}Passed: ${PASS_COUNT}${NC}"
echo "  ${RED}Failed: ${FAIL_COUNT}${NC}"
echo ""

if [ "${TEST_PASSED}" = true ]; then
    echo -e "  ${GREEN}✅ All integration tests passed${NC}"
    exit 0
else
    echo -e "  ${RED}❌ Some integration tests failed${NC}"
    exit 1
fi
