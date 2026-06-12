#!/bin/bash
# =============================================================================
# SENTINEL-X ULTRA — Security Tools Installer
# Installs all reconnaissance & scanning tools into ~/.sentinel/
# =============================================================================
# Usage: bash scripts/install_tools.sh
# =============================================================================

set -e
SENTINEL_DIR="$HOME/.sentinel"
TOOLS_DIR="$SENTINEL_DIR/tools"
WORDLISTS_DIR="$TOOLS_DIR/wordlists"
NUCLEI_DIR="$SENTINEL_DIR/nuclei-templates"

mkdir -p "$TOOLS_DIR" "$WORDLISTS_DIR" "$NUCLEI_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       SENTINEL-X ULTRA — Security Tools Installer          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Installing to: $SENTINEL_DIR"
echo ""

# ─── Helper ─────────────────────────────────────────────────────────────────
check_tool() { command -v "$1" >/dev/null 2>&1; }
check_dir()  { [ -d "$1" ]; }

# ─── 1. Go-based Tools ──────────────────────────────────────────────────────
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [1/6] Go-based Recon & Scanning Tools                        │"
echo "└────────────────────────────────────────────────────────────────┘"

if check_tool go; then
    GOPATH=$(go env GOPATH 2>/dev/null || echo "$HOME/go")
    export PATH="$GOPATH/bin:$PATH"

    for tool_info in \
        "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
        "waybackurls:github.com/tomnomnom/waybackurls@latest" \
        "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest" \
        "nuclei:github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" \
        "dalfox:github.com/hahwul/dalfox/v2/cmd/dalfox@latest" \
        "gau:github.com/lc/gau/v2/cmd/gau@latest" \
        "gobuster:github.com/OJ/gobuster/v3@latest" \
        "ffuf:github.com/ffuf/ffuf/v2@latest"
    do
        IFS=":" read -r name pkg <<< "$tool_info"
        if check_tool "$name"; then
            echo "  ✓ $name (already installed)"
        else
            echo "  Installing $name..."
            go install -v "$pkg" 2>/dev/null || echo "  ⚠  $name install failed (continuing)"
        fi
    done
else
    echo "  ⚠  Go not found — install Go first: https://go.dev/dl/"
    echo "     Skipping: subfinder, waybackurls, httpx, nuclei, dalfox, gau, gobuster, ffuf"
fi

# ─── 2. Python Tools ─────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [2/6] Python Security Tools                                 │"
echo "└────────────────────────────────────────────────────────────────┘"

for tool in sqlmap nmap; do
    if check_tool "$tool"; then
        echo "  ✓ $tool (already installed)"
    else
        echo "  Installing $tool..."
        pip install "$tool" 2>/dev/null || echo "  ⚠  $tool install failed (try: pip install $tool)"
    fi
done

# ─── 3. Git-based Tool Repos ─────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [3/6] Cloned Tool Repositories                               │"
echo "└────────────────────────────────────────────────────────────────┘"

for repo_info in \
    "BigBountyRecon:https://github.com/Viralmaniar/BigBountyRecon.git" \
    "SubEnum:https://github.com/bing0o/SubEnum.git" \
    "sqlifinder:https://github.com/americo/sqlifinder.git"
do
    IFS=":" read -r name url <<< "$repo_info"
    if check_dir "$TOOLS_DIR/$name"; then
        echo "  ✓ $name (already cloned)"
    else
        echo "  Cloning $name..."
        git clone --depth 1 "$url" "$TOOLS_DIR/$name" 2>/dev/null || echo "  ⚠  $name clone failed"
    fi
done

# ─── 4. Nuclei Templates ─────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [4/6] Nuclei Vulnerability Templates                        │"
echo "└────────────────────────────────────────────────────────────────┘"

if [ -d "$NUCLEI_DIR/.git" ]; then
    echo "  ✓ nuclei-templates (already cloned)"
else
    echo "  Downloading nuclei-templates..."
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$NUCLEI_DIR" 2>/dev/null || \
        echo "  ⚠  nuclei-templates download failed"
fi

# ─── 5. Wordlists ────────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [5/6] Wordlists                                             │"
echo "└────────────────────────────────────────────────────────────────┘"

if [ ! -f "$WORDLISTS_DIR/subdomains.txt" ]; then
    echo "  Downloading subdomain wordlist..."
    curl -sL "https://raw.githubusercontent.com/rbsec/dns-bruteforce/master/subdomains.txt" \
        -o "$WORDLISTS_DIR/subdomains.txt" 2>/dev/null && echo "  ✓ subdomains.txt" || echo "  ⚠  download failed"
else
    echo "  ✓ subdomains.txt (already exists)"
fi

if [ ! -f "$WORDLISTS_DIR/directories.txt" ]; then
    echo "  Downloading directory wordlist..."
    curl -sL "https://raw.githubusercontent.com/v0pr/Wordlist/main/directory-wordlist.txt" \
        -o "$WORDLISTS_DIR/directories.txt" 2>/dev/null && echo "  ✓ directories.txt" || echo "  ⚠  download failed"
else
    echo "  ✓ directories.txt (already exists)"
fi

# ─── 6. Summary ──────────────────────────────────────────────────────────────
echo ""
echo "┌────────────────────────────────────────────────────────────────┐"
echo "│ [6/6] Installation Summary                                  │"
echo "└────────────────────────────────────────────────────────────────┘"

TOOLS_LIST=("subfinder" "waybackurls" "httpx" "nuclei" "dalfox" "gau" "gobuster" "ffuf" "sqlmap" "nmap")
for tool in "${TOOLS_LIST[@]}"; do
    if check_tool "$tool"; then
        echo "  ✓ $tool"
    else
        echo "  ✗ $tool (not installed)"
    fi
done

echo ""
echo "  Tool repos in:  $TOOLS_DIR"
echo "  Templates in:   $NUCLEI_DIR"
echo "  Wordlists in:   $WORDLISTS_DIR"
echo ""
echo "  Add to your PATH:"
echo "    export PATH=\"\$PATH:\$HOME/go/bin:\$HOME/.sentinel/tools\""
echo ""
echo "✅ Done!"
