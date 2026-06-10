
## v0.5.0 - Phase 5 Features

### UI Improvements
- **Analysis Panel** - SAST code analysis with pattern detection, now fully connected to project tabs
- **Agents Panel** - Phase 3 AI agent controls with real-time output, now fully connected to project tabs
- **Descriptions/Bios** - Added explanatory descriptions under all major panel titles (Input Sources, Threat Hunt, Supply Chain, Bug Bounty, OWASP)

### Burp Suite Integration (Community Edition)
- **Real-Time Proxy Mode** - Configure SENTINEL-X to route traffic through Burp Suite for live analysis
- **JSON Export Import** - Upload Burp Suite JSON exports for analysis (Proxy > HTTP History > Export > JSON)
- **Request Routing** - `/api/burp/proxy-request` endpoint forwards requests through upstream Burp proxy
- **Analysis Endpoints**:
  - `POST /api/burp/proxy-analyze` - Analyze request/response through Burp Suite
  - `GET /api/burp/proxy-summary` - Get accumulated analysis summary

### Bug Fixes
- Fixed `BurpProxyAnalyzer` cache to persist request data across API calls
- Fixed Analysis/Agents panel rendering in project view tabs
- Fixed syntax error in `get_owasp_context` function

### Cache Management
- Added `clear_all_burp_caches()` function to prevent memory leaks
- Added `get_cached_proxy_count()` to monitor cache size

## v0.4.0 - Phase 4 Features

- Agent model selection per agent type
- OWASP Top 10 knowledge integrated into agent system prompts
- Bug bounty program context support
- Agent memory persistence across runs

# Sentinel-X Ultra

Security analysis platform with AI-powered agents.

## Features

- Phase 3 AI Agents for security analysis
- Phase 5 advanced threat hunting and operations
- Bug Bounty methodology integration
- Burp Suite Community Edition support

