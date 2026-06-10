#!/bin/bash
# Sentinel-X Reconnaissance Tools Installation Script
# Installs all tools to ~/.sentinelx/tools/

set -e

TOOLS_DIR="$HOME/.sentinelx/tools"
mkdir -p "$TOOLS_DIR"

echo "[SENTINEL-X] Installing reconnaissance tools to $TOOLS_DIR"

# Function to check if tool is installed
check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# ============ GO-BASED TOOLS ============
echo "[1/6] Installing Go-based tools..."

if check_tool go; then
    # SubFinder - Passive subdomain enumeration
    if ! check_tool subfinder; then
        echo "  Installing subfinder..."
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    else
        echo "  subfinder already installed"
    fi

    # Waybackurls - Historical URL collection
    if ! check_tool waybackurls; then
        echo "  Installing waybackurls..."
        go install -v github.com/tomnomnom/waybackurls@latest
    else
        echo "  waybackurls already installed"
    fi

    # Httpx - HTTP probing
    if ! check_tool httpx; then
        echo "  Installing httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    else
        echo "  httpx already installed"
    fi

    # Nuclei - Vulnerability scanner
    if ! check_tool nuclei; then
        echo "  Installing nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    else
        echo "  nuclei already installed"
    fi

    # Dalfox - XSS scanner (Go-based)
    if ! check_tool dalfox; then
        echo "  Installing dalfox..."
        go install -v github.com/hahwul/dalfox/v2/cmd/dalfox@latest
    else
        echo "  dalfox already installed"
    fi
else
    echo "  Go not found - skipping Go-based tools"
fi

# ============ GIT-BASED TOOLS ============
echo "[2/6] Installing Git-based tools..."

# BigBountyRecon - Google Dorking (58 techniques)
if [ ! -d "$TOOLS_DIR/BigBountyRecon" ]; then
    echo "  Cloning BigBountyRecon..."
    git clone --depth 1 https://github.com/Viralmaniar/BigBountyRecon.git "$TOOLS_DIR/BigBountyRecon"
else
    echo "  BigBountyRecon already installed"
fi

# SubEnum - Multi-source subdomain enumeration
if [ ! -d "$TOOLS_DIR/SubEnum" ]; then
    echo "  Cloning SubEnum..."
    git clone --depth 1 https://github.com/bing0o/SubEnum.git "$TOOLS_DIR/SubEnum"
else
    echo "  SubEnum already installed"
fi

# Sqlifinder - SQL injection discovery
if [ ! -d "$TOOLS_DIR/sqlifinder" ]; then
    echo "  Cloning sqlifinder..."
    git clone --depth 1 https://github.com/americo/sqlifinder.git "$TOOLS_DIR/sqlifinder"
else
    echo "  sqlifinder already installed"
fi

# Gau - Alternative URL collector (Go-based)
if ! check_tool gau; then
    echo "  Installing gau..."
    go install -v github.com/lc/gau/v2/cmd/gau@latest
else
    echo "  gau already installed"
fi

# ============ NUCLEI TEMPLATES ============
echo "[3/6] Setting up Nuclei templates..."

NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"
if [ ! -d "$NUCLEI_TEMPLATES_DIR" ]; then
    echo "  Cloning nuclei-templates..."
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_TEMPLATES_DIR"
else
    echo "  nuclei-templates already installed"
fi

# ============ WORDLISTS ============
echo "[4/6] Setting up wordlists..."

WORDLISTS_DIR="$TOOLS_DIR/wordlists"
mkdir -p "$WORDLISTS_DIR"

# Download common wordlists if not exist
if [ ! -f "$WORDLISTS_DIR/directory-wordlist.txt" ]; then
    echo "  Downloading directory wordlist..."
    curl -sL "https://raw.githubusercontent.com/v0pr/Wordlist/main/directory-wordlist.txt" -o "$WORDLISTS_DIR/directory-wordlist.txt" 2>/dev/null || true
fi

if [ ! -f "$WORDLISTS_DIR/subdomains.txt" ]; then
    echo "  Downloading subdomains wordlist..."
    curl -sL "https://raw.githubusercontent.com/rbsec/dns-bruteforce/master/subdomains.txt" -o "$WORDLISTS_DIR/subdomains.txt" 2>/dev/null || true
fi

# ============ VERIFICATION ============
echo "[5/6] Verifying installations..."

INSTALLED_TOOLS=("subfinder" "waybackurls" "httpx" "nuclei" "dalfox" "gau")
MISSING=""

for tool in "${INSTALLED_TOOLS[@]}"; do
    if check_tool "$tool"; then
        VERSION=$($tool -version 2>&1 | head -1 || echo "unknown")
        echo "  ✓ $tool: $VERSION"
    else
        echo "  ✗ $tool: NOT FOUND"
        MISSING="$MISSING $tool"
    fi
done

# Check Git-based tools
[ -d "$TOOLS_DIR/BigBountyRecon" ] && echo "  ✓ BigBountyRecon" || echo "  ✗ BigBountyRecon: NOT FOUND"
[ -d "$TOOLS_DIR/SubEnum" ] && echo "  ✓ SubEnum" || echo "  ✗ SubEnum: NOT FOUND"
[ -d "$TOOLS_DIR/sqlifinder" ] && echo "  ✓ sqlifinder" || echo "  ✗ sqlifinder: NOT FOUND"

echo "[6/6] Installation complete!"
echo ""
echo "Tools installed to: $TOOLS_DIR"
echo "Nuclei templates: $NUCLEI_TEMPLATES_DIR"
echo ""
echo "To use in reconnaissance:"
echo "  export PATH=\"\\$PATH:\\$HOME/go/bin:\\$HOME/.sentinelx/tools\""
echo ""
if [ -n "$MISSING" ]; then
    echo "WARNING: Some tools failed to install:$MISSING"
    echo "You may need to install Go or add to PATH manually."
fi