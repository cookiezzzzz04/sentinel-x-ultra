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
    BigBountyReconTool,
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
                "1. Google Dorking (BigBountyRecon) - Initial reconnaissance using 58 Google dorking techniques",
                "2. Subdomain Enumeration (SubFinder + SubEnum) - Passive subdomain discovery",
                "3. HTTP Probing (httpx) - Find alive/responsive hosts",
                "4. URL Collection (waybackurls/gau) - Historical URL enumeration",
                "5. Parameter Extraction - Identify URL parameters for testing",
                "6. XSS Scanning (Dalfox) - XSS vulnerability detection",
                "7. SQL Injection Testing (Sqlifinder) - SQLi vulnerability discovery",
                "8. Nuclei Scanning - Template-based vulnerability scanning"
            ],
            "sources": [
                "https://github.com/Viralmaniar/BigBountyRecon",
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
            result = await workflow.bigbountyrecon.scan(req.target)
            return _format_recon_result(result, req.target, "dorking")
        elif req.phase == "subdomains":
            r1 = await workflow.subfinder.scan(req.target)
            r2 = await workflow.subenum.scan(req.target)
            combined = _combine_results([r1, r2])
            return _format_recon_result(combined, req.target, "subdomains")
        elif req.phase == "http_probing":
            # Requires targets from previous phase
            if not req.options or "targets" not in req.options:
                return {"status": "error", "error": "HTTP probing requires 'targets' in options"}
            result = await workflow.httpx.scan(req.options["targets"])
            return _format_recon_result(result, req.target, "http_probing")
        elif req.phase == "urls":
            if not req.options or "targets" not in req.options:
                return {"status": "error", "error": "URL collection requires 'targets' in options"}
            result = await workflow.waybackurls.scan(req.options["targets"])
            return _format_recon_result(result, req.target, "urls")
        elif req.phase == "xss":
            if not req.options or "targets" not in req.options:
                return {"status": "error", "error": "XSS scanning requires 'targets' in options"}
            result = await workflow.dalfox.scan(wordlist_file=workflow._write_urls_to_file(req.options["targets"]), mode="file")
            return _format_recon_result(result, req.target, "xss")
        elif req.phase == "sqli":
            result = await workflow.sqlifinder.scan(target=req.target)
            return _format_recon_result(result, req.target, "sqli")
        elif req.phase == "vulnerabilities":
            if not req.options or "targets" not in req.options:
                return {"status": "error", "error": "Nuclei scanning requires 'targets' in options"}
            result = await workflow.nuclei.scan(req.options["targets"])
            return _format_recon_result(result, req.target, "vulnerabilities")
        else:
            return {"status": "error", "error": f"Unknown phase: {req.phase}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@recon_router.get("/tools/{tool_name}")
async def get_tool_info(tool_name: str):
    """Get information about a specific reconnaissance tool."""
    tools = {
        "bigbountyrecon": {
            "name": "BigBountyRecon",
            "description": "Google Dorking reconnaissance tool using 58 different techniques",
            "methods": ["scan(target, dork_type)"],
            "install": "git clone https://github.com/Viralmaniar/BigBountyRecon",
            "methodology": [
                "site:*.{target} inurl:*admin|login* - Login page discovery",
                "site:*.{target} intext:sql syntax near - SQL injection patterns",
                "site:*.{target} inurl:/geoserver/ows?service=wfs - Geoserver enumeration"
            ]
        },
        "subfinder": {
            "name": "SubFinder",
            "description": "Passive subdomain enumeration tool",
            "methods": ["scan(target, recursive, all_sources)"],
            "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "methodology": ["subfinder -d {target} -all -recursive"]
        },
        "subenum": {
            "name": "SubEnum",
            "description": "Multi-source subdomain enumeration",
            "methods": ["scan(target, sources)"],
            "install": "git clone https://github.com/bing0o/SubEnum",
            "methodology": ["subenum -l target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder"]
        },
        "waybackurls": {
            "name": "Waybackurls",
            "description": "Collect historical URLs from Wayback Machine",
            "methods": ["scan(domains)"],
            "install": "go install github.com/tomnomnom/waybackurls@latest",
            "methodology": ["cat domains.txt | waybackurls"]
        },
        "dalfox": {
            "name": "Dalfox",
            "description": "XSS vulnerability scanner",
            "methods": ["scan(target, wordlist_file, mode)"],
            "install": "go install github.com/hahwul/dalfox/v2@latest",
            "methodology": ["dalfox file xss_urls.txt"]
        },
        "sqlifinder": {
            "name": "Sqlifinder",
            "description": "SQL injection vulnerability finder",
            "methods": ["scan(target, target_file)"],
            "install": "git clone https://github.com/americo/sqlifinder",
            "methodology": ["python3 sqlifinder.py -d domain.com"]
        },
        "httpx": {
            "name": "Httpx",
            "description": "Fast HTTP probe tool for finding alive hosts",
            "methods": ["scan(targets)"],
            "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "methodology": ["cat subs.txt | httpx -o alive.txt"]
        },
        "nuclei": {
            "name": "Nuclei",
            "description": "Template-based vulnerability scanner",
            "methods": ["scan(targets, templates, tags, severity)"],
            "install": "go install github.com/projectdiscovery/nuclei/v2@latest",
            "methodology": ["nuclei -list urls.txt -t vulnerabilities,cves"]
        },
        "gau": {
            "name": "Gau",
            "description": "Get All URLs - Alternative to waybackurls",
            "methods": ["scan(domains)"],
            "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
            "methodology": ["gau domain.com"]
        }
    }
    
    if tool_name.lower() in tools:
        return tools[tool_name.lower()]
    return {"error": f"Unknown tool: {tool_name}"}


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
                "tool": "BigBountyRecon",
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
            {"name": "BigBountyRecon", "source": "https://github.com/Viralmaniar/BigBountyRecon"},
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


def register_recon_endpoints(app):
    """Register reconnaissance endpoints with the FastAPI app."""
    app.include_router(recon_router)
    return recon_router