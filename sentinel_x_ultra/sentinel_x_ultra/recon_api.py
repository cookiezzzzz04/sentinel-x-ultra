"""
Reconnaissance Tools API Integration

This module adds API endpoints for the reconnaissance tools following
the bug bounty methodology guide. It integrates with the FastAPI server.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import asyncio

# Import reconnaissance tools
from .recon_tools import (
    get_recon_workflow,
    install_all_tools,
    SubFinderTool,
    SubEnumTool,
    WaybackUrlsTool,
    GauTool,
    HttpxTool,
    DalfoxTool,
    SqlifinderTool,
    NucleiTool,
    ReconResult,
    SENTINELX_TOOLS_DIR,
)

# Advanced tools
from .hydra_tool import HydraTool, HydraResult, get_hydra_tool
from .sqlmap_tool import SQLMapTool, SQLMapResult, get_sqlmap_tool
from .xxe_tool import XXETool, XXEResult, get_xxe_tool
from .deserialization_tool import DeserializationTool, DeserializationResult, get_deserialization_tool


# ============================================================================
# Pydantic Models for API
# ============================================================================

class ReconRequest(BaseModel):
    target: str
    phase: Optional[str] = "full"  # "full", "dorking", "subdomains", "urls", "xss", "sqli", "vulnerabilities"
    options: Optional[Dict[str, Any]] = None


class ToolInstallRequest(BaseModel):
    tool: Optional[str] = None  # None means all tools


class ToolStatusRequest(BaseModel):
    pass


# ============================================================================
# API Router
# ============================================================================

recon_router = APIRouter(prefix="/api/recon", tags=["reconnaissance"])


@recon_router.get("/status")
async def get_recon_status():
    """Get status of all reconnaissance tools."""
    workflow = get_recon_workflow()
    available = workflow.get_available_tools()
    
    return {
        "status": "ok",
        "tools_available": available,
        "tools_dir": SENTINELX_TOOLS_DIR,
        "methodology": {
            "name": "Bug Bounty Reconnaissance Guide",
            "steps": [
                "2. Subdomain Enumeration (SubFinder + SubEnum) - Passive subdomain discovery",
                "3. HTTP Probing (httpx) - Find alive/responsive hosts",
                "4. URL Collection (waybackurls/gau) - Historical URL enumeration",
                "5. Parameter Extraction - Identify URL parameters for testing",
                "6. XSS Scanning (Dalfox) - XSS vulnerability detection",
                "7. SQL Injection Testing (Sqlifinder) - SQLi vulnerability discovery",
                "8. Nuclei Scanning - Template-based vulnerability scanning"
            ],
            "sources": [
                "https://github.com/projectdiscovery/subfinder",
                "https://github.com/bing0o/SubEnum",
                "https://github.com/tomnomnom/waybackurls",
                "https://github.com/hahwul/dalfox",
                "https://github.com/americo/sqlifinder"
            ]
        }
    }


@recon_router.post("/install")
async def install_recon_tools(req: ToolInstallRequest):
    """Install reconnaissance tools automatically."""
    try:
        if req.tool:
            # Install specific tool
            tool_name = req.tool.lower()
            if tool_name == "subfinder":
                from .recon_tools import install_subfinder
                result = await install_subfinder()
            elif tool_name == "waybackurls":
                from .recon_tools import install_waybackurls
                result = await install_waybackurls()
            elif tool_name == "dalfox":
                from .recon_tools import install_dalfox
                result = await install_dalfox()
            elif tool_name == "httpx":
                from .recon_tools import install_httpx
                result = await install_httpx()
            elif tool_name == "nuclei":
                from .recon_tools import install_nuclei
                result = await install_nuclei()
            elif tool_name == "gau":
                from .recon_tools import install_gau
                result = await install_gau()
            else:
                return {"status": "error", "error": f"Unknown tool: {req.tool}"}
            return {"status": "ok", "tool": req.tool, "result": result}
        else:
            # Install all tools
            results = await install_all_tools()
            return {"status": "ok", "results": results}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@recon_router.post("/scan")
async def run_recon_scan(req: ReconRequest):
    """Run reconnaissance scan on a target."""
    try:
        workflow = get_recon_workflow()
        
        if req.phase == "full":
            # Run full reconnaissance workflow
            results = await workflow.run_full_recon(req.target)
            return {
                "status": "completed",
                "target": req.target,
                "phase": "full",
                "results": {
                    tool: {
                        "findings_count": len(r.findings) if r else 0,
                        "errors": r.errors if r else [],
                        "execution_time": r.execution_time if r else 0
                    }
                    for tool, r in results.items()
                }
            }
        elif req.phase == "dorking":
            tools = {
                "subfinder": {
                    "name": "SubFinder",
                    "description": "Passive subdomain enumeration",
                    "methods": ["scan(target, recursive, all_sources)"],
                    "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                    "methodology": "subfinder -d {target} -recursive -all"
                },
                "waybackurls": {
                    "name": "Waybackurls",
                    "description": "Pull URLs from Wayback Machine",
                    "methods": ["scan(target)"],
                    "install": "go install github.com/tomnomnom/waybackurls@latest",
                    "methodology": "echo {target} | waybackurls"
                },
                "gau": {
                    "name": "Gau",
                    "description": "Fetch known URLs from AlienVault, Wayback, Common Crawl",
                    "methods": ["scan(target)"],
                    "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
                    "methodology": "gau {target}"
                },
                "httpx": {
                    "name": "Httpx",
                    "description": "HTTP probing and technology detection",
                    "methods": ["scan(urls)"],
                    "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
                    "methodology": "httpx -l urls.txt"
                }
            }
            return tools
    except Exception as e:
        return {"status": "error", "error": str(e)}


@recon_router.get("/methodology")
async def get_methodology():
    """Get the complete bug bounty reconnaissance methodology."""
    return {
        "name": "Complete Bug Bounty Reconnaissance Methodology",
        "description": "A comprehensive guide for initial reconnaissance in bug bounty hunting",
        "phases": [
            {
                "phase": 1,
                "name": "Google Dorking",
                "commands": [
                    "site:*.domain.com inurl:*admin | login",
                    "site:*.domain.com intext:sql syntax near",
                    "site:*.domain.com inurl:/geoserver/ows?service=wfs"
                ],
                "purpose": "Initial reconnaissance to discover endpoints, login pages, SQL errors, geoserver instances"
            },
            {
                "phase": 2,
                "name": "Subdomain Enumeration",
                "tools": ["SubFinder", "SubEnum"],
                "commands": [
                    "subfinder -d target.com -all -recursive -o subs.txt",
                    "subenum -l targets.txt -u wayback,crt,abuseipdb,bufferover -o subs2.txt"
                ],
                "purpose": "Discover subdomains using passive sources"
            },
            {
                "phase": 3,
                "name": "HTTP Probing",
                "tool": "httpx",
                "commands": ["cat all_subs.txt | httpx -o alive_hosts.txt"],
                "purpose": "Find alive/responsive hosts from discovered subdomains"
            },
            {
                "phase": 4,
                "name": "URL Collection",
                "tools": ["waybackurls", "gau"],
                "commands": [
                    "cat alive.txt | waybackurls | tee urls.txt",
                    "gau domain1.com gau domain2.com > urls2.txt"
                ],
                "purpose": "Collect historical URLs for parameter testing"
            },
            {
                "phase": 5,
                "name": "Parameter Extraction",
                "tool": "grep",
                "commands": [
                    "cat urls.txt | grep '=' | tee params.txt",
                    "cat urls.txt | grep -iE '.js$' | grep -ivE '.json' | tee js_files.txt"
                ],
                "purpose": "Extract URLs with parameters and JS files for testing"
            },
            {
                "phase": 6,
                "name": "XSS Scanning",
                "tool": "Dalfox",
                "commands": [
                    "cat params.txt | uro | gf xss > xss_targets.txt",
                    "dalfox file xss_targets.txt"
                ],
                "purpose": "Detect XSS vulnerabilities"
            },
            {
                "phase": 7,
                "name": "SQL Injection Testing",
                "tools": ["sqlifinder", "sqlmap"],
                "commands": [
                    "python3 sqlifinder.py -d target.com",
                    "sqlmap -m params.txt --batch --random-agent"
                ],
                "purpose": "Discover SQL injection vulnerabilities"
            },
            {
                "phase": 8,
                "name": "Nuclei Vulnerability Scanning",
                "tool": "Nuclei",
                "commands": [
                    "nuclei -list urls.txt -t /fuzzing-templates",
                    "nuclei -list alive.txt -t /nuclei-templates/vulnerabilities -t /nuclei-templates/cves"
                ],
                "purpose": "Scan for various vulnerabilities using templates"
            }
        ],
        "tools_integrated": [
{"name": "SubFinder", "source": "https://github.com/projectdiscovery/subfinder"},
            {"name": "SubEnum", "source": "https://github.com/bing0o/SubEnum"},
            {"name": "waybackurls", "source": "https://github.com/tomnomnom/waybackurls"},
            {"name": "Dalfox", "source": "https://github.com/hahwul/dalfox"},
            {"name": "Sqlifinder", "source": "https://github.com/americo/sqlifinder"}
        ]
    }


def _format_recon_result(result: ReconResult, target: str, phase: str) -> Dict[str, Any]:
    """Format a ReconResult for JSON response."""
    return {
        "status": "completed",
        "target": target,
        "phase": phase,
        "tool": result.tool,
        "findings_count": len(result.findings),
        "findings": result.findings[:50],  # Limit to 50 for response
        "errors": result.errors,
        "execution_time": round(result.execution_time, 2),
        "raw_output_preview": result.raw_output[:500] if result.raw_output else ""
    }


def _combine_results(results: List[ReconResult]) -> ReconResult:
    """Combine multiple ReconResult objects."""
    combined_findings = []
    combined_errors = []
    total_time = 0
    
    for r in results:
        if r:
            combined_findings.extend(r.findings)
            combined_errors.extend(r.errors)
            total_time += r.execution_time
    
    return ReconResult(
        tool="combined",
        target="multiple",
        findings=combined_findings,
        errors=combined_errors,
        execution_time=total_time
    )


# ============================================================================
# Pydantic Models for New Tools
# ============================================================================

class HydraScanRequest(BaseModel):
    target: str
    service: str = "ssh"
    username: Optional[str] = None
    username_file: Optional[str] = None
    password_file: Optional[str] = None
    port: Optional[int] = None
    threads: int = 4
    timeout_sec: int = 600


class SQLMapScanRequest(BaseModel):
    target: str
    data: Optional[str] = None
    cookie: Optional[str] = None
    technique: str = "BEUST"
    level: int = 1
    risk: int = 1
    threads: int = 1
    dbms: Optional[str] = None
    batch: bool = True
    timeout_sec: int = 600
    enumerate_dbs: bool = False


class XXEScanRequest(BaseModel):
    target: str
    test_type: str = "all"
    method: str = "POST"
    content_type: str = "application/xml"
    timeout_sec: int = 30
    collaborator_url: Optional[str] = None


class DeserializationScanRequest(BaseModel):
    target: str
    language: str = "all"
    command: str = "id"
    method: str = "POST"
    timeout_sec: int = 30


class ToolInfoRequest(BaseModel):
    tool: str = "all"


# ============================================================================
# Advanced Tool Endpoints
# ============================================================================

tool_router = APIRouter(prefix="/api/tools", tags=["tools"])


@tool_router.get("/list")
async def list_all_tools():
    """List all registered tools with availability status."""
    from . import get_all_tool_status
    status = get_all_tool_status()
    return {
        "status": "ok",
        "tools": status,
        "tools_dir": SENTINELX_TOOLS_DIR,
    }


@tool_router.get("/{tool_name}/status")
async def get_tool_status(tool_name: str):
    """Get status of a specific tool."""
    tool_map = {}
    from . import TOOL_REGISTRY as _tool_reg
    import importlib as _il
    for _name, (_mod, _getter, _cls) in _tool_reg.items():
        try:
            _m = _il.import_module(f".{_mod}", __package__)
            tool_map[_name] = lambda m=_m, g=_getter: getattr(m, g)()
        except Exception:
            pass
    
    getter = tool_map.get(tool_name.lower())
    if not getter:
        return {"status": "error", "error": f"Unknown tool: {tool_name}. Available: {', '.join(tool_map.keys())}"}
    
    try:
        tool = getter()
        return {
            "status": "ok",
            "tool": tool_name,
            "available": tool.is_available(),
            "version": tool.get_version() if hasattr(tool, "get_version") else "unknown",
            "capabilities": tool.get_capabilities() if hasattr(tool, "get_capabilities") else {},
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.post("/hydra/scan")
async def run_hydra_scan(req: HydraScanRequest):
    """Run a Hydra brute force scan."""
    try:
        tool = get_hydra_tool()
        if not tool.is_available():
            return {
                "status": "error",
                "error": "Hydra not installed. Install from: https://github.com/vanhauser-thc/thc-hydra",
                "install_hint": "Place hydra/hydra.exe in ~/.sentinelx/tools/"
            }
        
        result = await tool.scan(
            target=req.target,
            service=req.service,
            username=req.username,
            username_file=req.username_file,
            password_file=req.password_file,
            port=req.port,
            threads=req.threads,
            timeout_sec=req.timeout_sec,
        )
        
        return {
            "status": "completed" if not result.errors else "completed_with_errors",
            "tool": "hydra",
            "target": result.target,
            "service": result.service,
            "successes": result.successes,
            "success_count": len(result.successes),
            "execution_time_seconds": round(result.execution_time_seconds, 2),
            "errors": result.errors,
            "tool_version": result.tool_version,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.post("/sqlmap/scan")
async def run_sqlmap_scan(req: SQLMapScanRequest):
    """Run a SQLMap SQL injection scan."""
    try:
        tool = get_sqlmap_tool()
        if not tool.is_available():
            return {
                "status": "error",
                "error": "SQLMap not installed. Install from: https://github.com/sqlmapproject/sqlmap",
                "install_hint": "Clone to ~/.sentinelx/tools/sqlmap/"
            }
        
        if req.enumerate_dbs:
            result = await tool.enumerate_databases(
                target=req.target,
                technique=req.technique,
                level=req.level,
                risk=req.risk,
                batch=req.batch,
                timeout_sec=req.timeout_sec,
            )
        else:
            result = await tool.scan(
                target=req.target,
                data=req.data,
                cookie=req.cookie,
                technique=req.technique,
                level=req.level,
                risk=req.risk,
                threads=req.threads,
                dbms=req.dbms,
                batch=req.batch,
                timeout_sec=req.timeout_sec,
            )
        
        return {
            "status": "completed" if not result.errors else "completed_with_errors",
            "tool": "sqlmap",
            "target": result.target,
            "technique": result.technique,
            "vulnerable_parameters": result.vulnerable_parameters,
            "vulnerable": len(result.vulnerable_parameters) > 0,
            "execution_time_seconds": round(result.execution_time_seconds, 2),
            "errors": result.errors,
            "tool_version": result.tool_version,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.post("/xxe/scan")
async def run_xxe_scan(req: XXEScanRequest):
    """Run XXE injection test."""
    try:
        tool = get_xxe_tool()
        
        result = await tool.scan(
            target=req.target,
            test_type=req.test_type,
            method=req.method,
            content_type=req.content_type,
            timeout_sec=req.timeout_sec,
            collaborator_url=req.collaborator_url,
        )
        
        return {
            "status": "completed",
            "tool": "xxe_tool",
            "target": result.target,
            "vulnerability_detected": result.vulnerability_detected,
            "findings": result.findings[:20],
            "findings_count": len(result.findings),
            "file_read_results": result.file_read_results,
            "execution_time_seconds": round(result.execution_time_seconds, 2),
            "errors": result.errors,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.get("/xxe/payloads")
async def get_xxe_payloads(test_type: str = "all"):
    """Get XXE payloads for manual testing."""
    try:
        tool = get_xxe_tool()
        payloads = tool.get_payloads(test_type)
        return {
            "status": "ok",
            "test_type": test_type,
            "payloads": payloads,
            "total_count": sum(len(v) for v in payloads.values()),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.post("/deserialization/scan")
async def run_deserialization_scan(req: DeserializationScanRequest):
    """Run insecure deserialization test."""
    try:
        tool = get_deserialization_tool()
        
        result = await tool.scan(
            target=req.target,
            language=req.language,
            command=req.command,
            method=req.method,
            timeout_sec=req.timeout_sec,
        )
        
        return {
            "status": "completed",
            "tool": "deserialization_tool",
            "target": result.target,
            "language": result.language,
            "vulnerability_detected": result.vulnerability_detected,
            "findings": result.findings[:20],
            "findings_count": len(result.findings),
            "payloads_generated": result.payloads_generated,
            "execution_time_seconds": round(result.execution_time_seconds, 2),
            "errors": result.errors,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.get("/deserialization/payloads")
async def generate_deserialization_payloads(language: str = "all", command: str = "id"):
    """Generate deserialization payloads for manual testing."""
    try:
        tool = get_deserialization_tool()
        payloads = tool.generate_payloads(language, command)
        total = sum(len(v) for v in payloads.values())
        return {
            "status": "ok",
            "language": language,
            "command": command,
            "payloads": payloads,
            "total_count": total,
            "supported_languages": tool.supported_languages,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@tool_router.get("/configuration")
async def get_tool_configuration():
    """Get tool configuration from tools.yaml."""
    import os as _os
    from pathlib import Path as _Path
    
    config_paths = [
        _Path(__file__).parent / "config" / "tools.yaml",
        _Path(_os.path.expanduser("~/.sentinelx/tools.yaml")),
    ]
    
    for path in config_paths:
        if path.exists():
            try:
                import yaml
                with open(path) as f:
                    config = yaml.safe_load(f)
                return {"status": "ok", "config": config, "source": str(path)}
            except Exception:
                pass
    
    return {
        "status": "ok",
        "note": "No tools.yaml found. Using default paths from ~/.sentinelx/tools/",
        "tools_dir": SENTINELX_TOOLS_DIR,
    }


@tool_router.get("/install-guide")
async def get_tool_install_guide():
    """Get installation guide for all tools."""
    return {
        "status": "ok",
        "tools_dir": SENTINELX_TOOLS_DIR,
        "tools": {
            "hydra": {
                "url": "https://github.com/vanhauser-thc/thc-hydra",
                "install": "git clone --depth 1 https://github.com/vanhauser-thc/thc-hydra ~/.sentinelx/tools/hydra",
                "binary_sources": ["apt install hydra", "brew install hydra", "https://github.com/vanhauser-thc/thc-hydra/releases"],
            },
            "sqlmap": {
                "url": "https://github.com/sqlmapproject/sqlmap",
                "install": "git clone --depth 1 https://github.com/sqlmapproject/sqlmap ~/.sentinelx/tools/sqlmap",
                "run": "python ~/.sentinelx/tools/sqlmap/sqlmap.py",
            },
            "xxe_tool": {
                "note": "Built-in payload generator. No installation required.",
                "test": "Use POST endpoint /api/tools/xxe/scan with target URL",
            },
            "deserialization_tool": {
                "note": "Built-in payload generator. No installation required.",
                "test": "Use POST endpoint /api/tools/deserialization/scan with target URL",
            },
        }
    }


def register_recon_endpoints(app):
    """Register reconnaissance and tool endpoints with the FastAPI app."""
    app.include_router(recon_router)
    app.include_router(tool_router)
    return recon_router, tool_router