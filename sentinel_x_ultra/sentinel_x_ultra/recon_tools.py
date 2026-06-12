"""
Integrated Reconnaissance Tools for Sentinel-X

This module provides integrated access to various reconnaissance tools following
the methodology from the comprehensive bug bounty reconnaissance guide:

Tools Integrated:
2. SubFinder - Passive subdomain enumeration
3. SubEnum - Multi-source subdomain enumeration
4. Waybackurls - Historical URL collection
5. Dalfox - XSS vulnerability scanning
6. Sqlifinder - SQL injection discovery
7. Httpx - HTTP probe to find alive hosts
8. Nuclei - Vulnerability scanner based on templates
9. Gau - Get All URLs (alternative to waybackurls)

Methodology Flow:
2. Subdomain enumeration (SubFinder + SubEnum)
3. HTTP probing (httpx) to find alive hosts
4. URL collection (waybackurls/gau)
5. Parameter extraction for testing
6. XSS scanning (Dalfox)
7. SQL injection testing (Sqlifinder)
8. Nuclei vulnerability scanning
"""

import asyncio
import subprocess
import re
import os
import json
import tempfile
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import platform


# ============================================================================
# TOOL INSTALLATION AND PATH MANAGEMENT
# ============================================================================

SENTINELX_TOOLS_DIR = os.path.expanduser("~/.sentinelx/tools")

def _get_temp_path(filename: str) -> str:
    """Get a cross-platform temp file path."""
    return os.path.join(tempfile.gettempdir(), filename)


def _get_path_for_tool(tool_name: str) -> str:
    """Get the path to a tool executable, checking multiple locations."""
    # Check SENTINELX_TOOLS_DIR first
    sentinelx_path = os.path.join(SENTINELX_TOOLS_DIR, tool_name)
    if os.path.exists(sentinelx_path):
        return sentinelx_path
    
    # Check for .exe on Windows
    if platform.system() == "Windows":
        sentinelx_path_exe = os.path.join(SENTINELX_TOOLS_DIR, f"{tool_name}.exe")
        if os.path.exists(sentinelx_path_exe):
            return sentinelx_path_exe
    
    # Check GOPATH/bin for Go-installed tools
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    gobin_path = os.path.join(gopath, "bin", tool_name)
    if platform.system() == "Windows":
        gobin_path_exe = gobin_path + ".exe"
        if os.path.exists(gobin_path_exe):
            return gobin_path_exe
    if os.path.exists(gobin_path):
        return gobin_path
    
    # Check PATH
    for cmd in [tool_name, f"{tool_name}.exe"]:
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["where", cmd], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(["which", cmd], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split('\n')[0]
        except:
            pass
    
    return tool_name  # Return tool name, let caller handle if not found


def _ensure_sentinelx_dir():
    """Ensure the Sentinel-X tools directory exists."""
    os.makedirs(SENTINELX_TOOLS_DIR, exist_ok=True)


# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

async def install_subfinder() -> Dict[str, Any]:
    """Install subfinder using Go."""
    _ensure_sentinelx_dir()
    try:
        subprocess.run(
            ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            capture_output=True,
            timeout=120
        )
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        subfinder_path = os.path.join(gopath, "bin", "subfinder.exe") if platform.system() == "Windows" else os.path.join(gopath, "bin", "subfinder")
        if os.path.exists(subfinder_path):
            dest = os.path.join(SENTINELX_TOOLS_DIR, "subfinder.exe" if platform.system() == "Windows" else "subfinder")
            shutil.copy(subfinder_path, dest)
            return {"status": "success", "path": dest}
        return {"status": "success", "message": "Installed via Go (check GOPATH/bin)"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_waybackurls() -> Dict[str, Any]:
    """Install waybackurls using Go."""
    _ensure_sentinelx_dir()
    try:
        subprocess.run(
            ["go", "install", "github.com/tomnomnom/waybackurls@latest"],
            capture_output=True,
            timeout=60
        )
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        waybackurls_path = os.path.join(gopath, "bin", "waybackurls.exe" if platform.system() == "Windows" else "waybackurls")
        if os.path.exists(waybackurls_path):
            dest = os.path.join(SENTINELX_TOOLS_DIR, "waybackurls.exe" if platform.system() == "Windows" else "waybackurls")
            shutil.copy(waybackurls_path, dest)
            return {"status": "success", "path": dest}
        return {"status": "success", "message": "Installed via Go"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_dalfox() -> Dict[str, Any]:
    """Install dalfox using Go."""
    _ensure_sentinelx_dir()
    try:
        subprocess.run(
            ["go", "install", "github.com/hahwul/dalfox/v2@latest"],
            capture_output=True,
            timeout=60
        )
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        dalfox_path = os.path.join(gopath, "bin", "dalfox.exe" if platform.system() == "Windows" else "dalfox")
        if os.path.exists(dalfox_path):
            dest = os.path.join(SENTINELX_TOOLS_DIR, "dalfox.exe" if platform.system() == "Windows" else "dalfox")
            shutil.copy(dalfox_path, dest)
            return {"status": "success", "path": dest}
        return {"status": "success", "message": "Installed via Go"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_httpx() -> Dict[str, Any]:
    """Install httpx using Go."""
    _ensure_sentinelx_dir()
    try:
        subprocess.run(
            ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
            capture_output=True,
            timeout=60
        )
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        httpx_path = os.path.join(gopath, "bin", "httpx.exe" if platform.system() == "Windows" else "httpx")
        if os.path.exists(httpx_path):
            dest = os.path.join(SENTINELX_TOOLS_DIR, "httpx.exe" if platform.system() == "Windows" else "httpx")
            shutil.copy(httpx_path, dest)
            return {"status": "success", "path": dest}
        return {"status": "success", "message": "Installed via Go"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_nuclei() -> Dict[str, Any]:
    """Install nuclei using Go."""
    _ensure_sentinelx_dir()
    try:
        subprocess.run(
            ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2@latest"],
            capture_output=True,
            timeout=120
        )
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        nuclei_path = os.path.join(gopath, "bin", "nuclei.exe" if platform.system() == "Windows" else "nuclei")
        if os.path.exists(nuclei_path):
            dest = os.path.join(SENTINELX_TOOLS_DIR, "nuclei.exe" if platform.system() == "Windows" else "nuclei")
            shutil.copy(nuclei_path, dest)
            return {"status": "success", "path": dest}
        return {"status": "success", "message": "Installed via Go"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_gau() -> Dict[str, Any]:
    """Install gau (getallurls) using Go."""
    _ensure_sentinelx_dir()
    try:
        subprocess.run(
            ["go", "install", "github.com/lc/gau/v2/cmd/gau@latest"],
            capture_output=True,
            timeout=60
        )
        gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
        gau_path = os.path.join(gopath, "bin", "gau.exe" if platform.system() == "Windows" else "gau")
        if os.path.exists(gau_path):
            dest = os.path.join(SENTINELX_TOOLS_DIR, "gau.exe" if platform.system() == "Windows" else "gau")
            shutil.copy(gau_path, dest)
            return {"status": "success", "path": dest}
        return {"status": "success", "message": "Installed via Go"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_nuclei_templates() -> Dict[str, Any]:
    """Install nuclei vulnerability templates."""
    _ensure_sentinelx_dir()
    try:
        templates_path = os.path.join(SENTINELX_TOOLS_DIR, "nuclei-templates")
        if not os.path.exists(templates_path):
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/projectdiscovery/nuclei-templates", templates_path],
                capture_output=True,
                timeout=300
            )
            if result.returncode == 0:
                # Count templates
                template_count = sum(1 for _ in subprocess.run(
                    ["find", templates_path, "-name", "*.yaml"],
                    capture_output=True,
                    text=True
                ).stdout.split('\n') if _.strip())
                return {"status": "success", "path": templates_path, "template_count": template_count}
            else:
                return {"status": "error", "error": result.stderr.decode()}
        else:
            # Update existing templates
            result = subprocess.run(
                ["git", "-C", templates_path, "pull"],
                capture_output=True,
                timeout=60
            )
            return {"status": "success", "path": templates_path, "message": "templates already exist, pulled latest"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


async def install_all_tools() -> Dict[str, Any]:
    """Install all reconnaissance tools automatically."""
    results = {}
    
    # Go-installed tools
    for tool_name, install_func in [
        ("subfinder", install_subfinder),
        ("waybackurls", install_waybackurls),
        ("dalfox", install_dalfox),
        ("httpx", install_httpx),
        ("nuclei", install_nuclei),
        ("gau", install_gau),
    ]:
        results[tool_name] = await install_func()
    
    # Git-cloned tools
    try:
        _ensure_sentinelx_dir()
        
        results["bigbountyrecon"] = {"status": "success" if os.path.exists(bbr_path) else "pending", "path": bbr_path}
        
        # SubEnum
        se_path = os.path.join(SENTINELX_TOOLS_DIR, "SubEnum")
        if not os.path.exists(se_path):
            subprocess.run(["git", "clone", "--depth", "1", "https://github.com/bing0o/SubEnum", se_path], 
                          capture_output=True, timeout=120)
        results["subenum"] = {"status": "success" if os.path.exists(se_path) else "pending", "path": se_path}
        
        # Sqlifinder
        sf_path = os.path.join(SENTINELX_TOOLS_DIR, "sqlifinder")
        if not os.path.exists(sf_path):
            subprocess.run(["git", "clone", "--depth", "1", "https://github.com/americo/sqlifinder", sf_path], 
                          capture_output=True, timeout=120)
        results["sqlifinder"] = {"status": "success" if os.path.exists(sf_path) else "pending", "path": sf_path}
        
        # Nuclei templates
        nt_path = os.path.join(SENTINELX_TOOLS_DIR, "nuclei-templates")
        if not os.path.exists(nt_path):
            subprocess.run(["git", "clone", "--depth", "1", "https://github.com/projectdiscovery/nuclei-templates", nt_path], 
                          capture_output=True, timeout=300)
        results["nuclei-templates"] = {"status": "success" if os.path.exists(nt_path) else "pending", "path": nt_path}
        
    except Exception as e:
        results["git_tools"] = {"status": "error", "error": str(e)}
    
    return results


# ============================================================================
# TOOL VERSION FUNCTIONS
# ============================================================================

async def get_tool_version(tool_cmd: str) -> str:
    """Get version of any tool by running --version."""
    try:
        result = subprocess.run(
            [tool_cmd, "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()[:100]
    except:
        pass
    return "unknown"


# ============================================================================
# RECONNAISSANCE TOOL CLASSES
# ============================================================================

@dataclass
class ReconResult:
    """Structured result from reconnaissance operations."""
    tool: str
    target: str
    findings: List[Dict[str, Any]]
    errors: List[str]
    execution_time: float
    raw_output: str = ""
    status: str = "ok"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class BigBountyReconTool:
    """
    
    Performs reconnaissance using 58 different Google dorking techniques
    to discover endpoints, login pages, SQL errors, geoserver instances, etc.
    
    Methodology from guide:
        site:*.domain.com inurl:"*admin | login" | inurl:.php | .asp
        site:*.domain.com intext:sql syntax near | intext:syntax error
        site:*.domain.com inurl:/geoserver/ows?service=wfs
    
    Usage:
        result = await tool.scan("example.com")
    """
    
    def __init__(self):
        self.name = "bigbountyrecon"
    
    def is_available(self) -> bool:
        paths = [
        ]
        for path in paths:
            if os.path.exists(path):
                return True
        return False
    
    async def scan(self, target: str, dork_type: str = "all") -> "ReconResult":
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        tool_paths = [
        ]
        
        tool_path = None
        for path in tool_paths:
            if os.path.exists(path):
                tool_path = path
                break
        
        if not tool_path:
            return ReconResult(
                tool=self.name,
                target=target,
                findings=[],
                errors=errors,
                execution_time=(datetime.now() - start_time).total_seconds()
            )
        
        try:
            if platform.system() != "Windows":
                os.chmod(tool_path, 0o755)
            
            if platform.system() == "Windows":
                cmd = [tool_path, target]
            else:
                mono_path = shutil.which("mono")
                if mono_path:
                    cmd = [mono_path, tool_path, target]
                else:
                    cmd = [tool_path, target]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            for line in raw_output.split('\n'):
                if line.strip() and not line.startswith('['):
                    findings.append({
                        "type": "dork_result",
                        "value": line.strip(),
                        "dork_type": dork_type
                    })
            
        except asyncio.TimeoutError:
            errors.append("Scan timed out after 300 seconds")
        except Exception as e:
            errors.append(str(e))
        
        return ReconResult(
            tool=self.name,
            target=target,
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )
    
    @staticmethod
    def get_dork_techniques() -> List[Dict[str, str]]:
        """Return list of Google dorking techniques from the guide."""
        return [
            {"name": "admin_login", "query": "site:*.{target} inurl:*admin|login*"},
            {"name": "sql_errors", "query": "site:*.{target} intext:sql syntax near|intext:syntax error"},
            {"name": "geoserver", "query": "site:*.{target} inurl:/geoserver/ows?service=wfs"},
            {"name": "php_asp", "query": "site:*.{target} inurl:.php|.asp"},
            {"name": "config_files", "query": "site:*.{target} inurl:config|settings|backup"},
            {"name": "database_errors", "query": "site:*.{target} intext:Warning: mysql_|Warning: pg_"},
            {"name": "debug_mode", "query": "site:*.{target} intext:debug=true|debug=1"},
            {"name": "index_of", "query": 'site:*.{target} intitle:"index of"'},
            {"name": "exposed_files", "query": "site:*.{target} ext:log|ext:txt|ext:bak"},
            {"name": "login_pages", "query": 'site:*.{target} intitle:"login"|intitle:"sign in"'},
        ]


class SubFinderTool:
    """
    SubFinder - Passive subdomain enumeration tool.
    
    Discovers subdomains using multiple passive sources:
    - VirusTotal, Shodan, Censys (with API keys)
    - crt.sh, CertSpotter
    - JSKY, ThreatCrowd, etc.
    
    Methodology from guide:
        echo domain.com > target.txt
        subfinder -dL target.txt -all -recursive -o Subs01.txt
    
    Usage:
        tool = SubFinderTool()
        result = await tool.scan("example.com")
    """
    
    def __init__(self):
        self.name = "subfinder"
    
    def is_available(self) -> bool:
        """Check if subfinder is installed."""
        path = _get_path_for_tool("subfinder")
        if path and path != "subfinder" and os.path.exists(path):
            return True
        try:
            result = subprocess.run(
                ["subfinder", "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def scan(
        self,
        target: str,
        recursive: bool = True,
        all_sources: bool = True,
        timeout: int = 300
    ) -> "ReconResult":
        """
        Run subfinder subdomain enumeration.
        
        Args:
            target: Target domain
            recursive: Enable recursive subdomain finding
            all_sources: Use all passive sources
            timeout: Scan timeout in seconds
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if not self.is_available():
            return ReconResult(
                tool=self.name,
                target=target,
                findings=[],
                errors=["SubFinder not installed. Run: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
                execution_time=0
            )
        
        output_file = _get_temp_path("subfinder_results.txt")
        
        try:
            cmd = ["subfinder", "-d", target]
            if recursive:
                cmd.append("-recursive")
            if all_sources:
                cmd.append("-all")
            cmd.extend(["-o", output_file])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            # Parse subdomains from output file
            try:
                if os.path.exists(output_file):
                    with open(output_file, "r", encoding='utf-8', errors='replace') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain:
                                findings.append({
                                    "type": "subdomain",
                                    "value": subdomain,
                                    "source": "subfinder"
                                })
            except Exception as e:
                errors.append(f"Error reading results: {str(e)}")
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        finally:
            try:
                if os.path.exists(output_file):
                    os.remove(output_file)
            except:
                pass
        
        return ReconResult(
            tool=self.name,
            target=target,
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class SubEnumTool:
    """
    SubEnum - Multi-source subdomain enumeration.
    
    Enumerates subdomains using multiple sources and tools:
    - wayback, crt, abuseipdb, bufferover
    - Findomain, Subfinder, Amass, Assetfinder
    
    Methodology from guide:
        subenum -l target.txt -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Amass,Assetfinder -o Subs02.txt
    """
    
    def __init__(self):
        self.name = "subenum"
        self.install_url = "https://github.com/bing0o/SubEnum"
    
    def is_available(self) -> bool:
        """Check if SubEnum is installed."""
        paths = [
            os.path.join(SENTINELX_TOOLS_DIR, "SubEnum", "subenum.sh"),
            os.path.expanduser("~/SubEnum/subenum.sh"),
        ]
        for path in paths:
            if os.path.exists(path):
                return True
        return False
    
    async def scan(
        self,
        target: str,
        sources: List[str] = None,            output_file: str = None,
        timeout: int = 600
    ) -> "ReconResult":
        """
        Run SubEnum subdomain enumeration.
        
        Args:
            target: Target domain or file with domains
            sources: List of sources to use
            output_file: Output file for results
            timeout: Scan timeout
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if sources is None:
            sources = ["wayback", "crt", "abuseipdb", "bufferover", "Findomain", "Subfinder", "Amass", "Assetfinder"]
        
        tool_paths = [
            os.path.join(SENTINELX_TOOLS_DIR, "SubEnum", "subenum.sh"),
            os.path.expanduser("~/SubEnum/subenum.sh"),
        ]
        
        tool_path = None
        for path in tool_paths:
            if os.path.exists(path):
                tool_path = path
                break
        
        if not tool_path:
            errors.append(f"SubEnum not found. Install from: {self.install_url}")
            return ReconResult(
                tool=self.name,
                target=target,
                findings=[],
                errors=errors,
                execution_time=(datetime.now() - start_time).total_seconds()
            )
        
        try:
            # Make executable
            if platform.system() != "Windows":
                os.chmod(tool_path, 0o755)
            
            # Create target file if it's a single domain (use cross-platform temp dir)
            temp_dir = tempfile.gettempdir()
            target_file = os.path.join(temp_dir, "subenum_target.txt")
            if not os.path.exists(target):
                with open(target_file, "w") as f:
                    f.write(target)
                target_to_use = target_file
            else:
                target_to_use = target
            
            sources_str = ",".join(sources)
            output_file = output_file or _get_temp_path("subenum_results.txt")
            cmd = [tool_path, "-l", target_to_use, "-u", sources_str, "-o", output_file]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            # Parse output file
            try:
                if os.path.exists(output_file):
                    with open(output_file, "r", encoding='utf-8', errors='replace') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain:
                                findings.append({
                                    "type": "subdomain",
                                    "value": subdomain,
                                    "source": "subenum"
                                })
            except Exception as e:
                errors.append(f"Error reading results: {str(e)}")
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        
        return ReconResult(
            tool=self.name,
            target=target,
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class WaybackUrlsTool:
    """
    Waybackurls - Collect historical URLs from Wayback Machine.
    
    Retrieves archived URLs for a domain, useful for finding:
    - Old endpoints that may still be accessible
    - Parameters for testing
    - JavaScript files
    
    Methodology from guide:
        cat AliveSubs.txt | waybackurls | tee urls.txt
    """
    
    def __init__(self):
        self.name = "waybackurls"
    
    def is_available(self) -> bool:
        """Check if waybackurls is installed."""
        path = _get_path_for_tool("waybackurls")
        if path and path != "waybackurls" and os.path.exists(path):
            return True
        try:
            result = subprocess.run(
                ["waybackurls", "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def scan(
        self,
        domains: List[str],
        output_file: str = None,
        timeout: int = 300
    ) -> "ReconResult":
        """
        Collect Wayback URLs for domains.
        
        Args:
            domains: List of domains to query
            output_file: Optional output file
            timeout: Scan timeout
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if not self.is_available():
            return ReconResult(
                tool=self.name,
                target=",".join(domains),
                findings=[],
                errors=["waybackurls not installed. Run: go install github.com/tomnomnom/waybackurls@latest"],
                execution_time=0
            )
        
        try:
            input_data = "\n".join(domains).encode()
            
            proc = await asyncio.create_subprocess_exec(
                "waybackurls",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=input_data),
                timeout=timeout
            )
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            for line in raw_output.split('\n'):
                if line.strip():
                    url = line.strip()
                    findings.append({
                        "type": "wayback_url",
                        "value": url,
                        "source": "wayback_machine"
                    })
            
            if output_file:
                with open(output_file, "w") as f:
                    f.write(raw_output)
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        
        return ReconResult(
            tool=self.name,
            target=",".join(domains),
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class GauTool:
    """
    Gau - Get All URLs including from AlienVault OTX, Common Crawl, etc.
    
    Alternative to waybackurls that fetches from multiple sources.
    
    Methodology from guide:
        cat AliveSubs.txt | gau | tee urls.txt
    """
    
    def __init__(self):
        self.name = "gau"
    
    def is_available(self) -> bool:
        """Check if gau is installed."""
        path = _get_path_for_tool("gau")
        if path and path != "gau" and os.path.exists(path):
            return True
        try:
            result = subprocess.run(
                ["gau", "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def scan(
        self,
        domains: List[str],
        output_file: str = None,
        timeout: int = 300
    ) -> "ReconResult":
        """Collect URLs using gau."""
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if not self.is_available():
            return ReconResult(
                tool=self.name,
                target=",".join(domains),
                findings=[],
                errors=["gau not installed. Run: go install github.com/lc/gau/v2/cmd/gau@latest"],
                execution_time=0
            )
        
        try:
            for domain in domains:
                input_data = domain.encode()
                
                proc = await asyncio.create_subprocess_exec(
                    "gau",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=input_data),
                    timeout=timeout
                )
                
                domain_output = stdout.decode('utf-8', errors='replace')
                raw_output += domain_output
                
                for line in domain_output.split('\n'):
                    if line.strip():
                        findings.append({
                            "type": "gau_url",
                            "value": line.strip(),
                            "source": "gau"
                        })
            
            if output_file:
                with open(output_file, "w") as f:
                    f.write(raw_output)
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        
        return ReconResult(
            tool=self.name,
            target=",".join(domains),
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class HttpxTool:
    """
    Httpx - Fast HTTP probe tool.
    
    Checks if subdomains are alive/responsive.
    
    Methodology from guide:
        cat AllSubs.txt | httpx -o AliveSubs.txt
    """
    
    def __init__(self):
        self.name = "httpx"
    
    def is_available(self) -> bool:
        """Check if httpx is installed."""
        # Check ~/.sentinelx/tools/ and GOPATH/bin first
        path = _get_path_for_tool("httpx")
        if path and path != "httpx" and os.path.exists(path):
            return True
        # Fall back to PATH check
        try:
            result = subprocess.run(
                ["httpx", "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def scan(
        self,
        targets: List[str],
        output_file: str = None,
        timeout: int = 300
    ) -> "ReconResult":
        """
        Check which targets are alive.
        
        Args:
            targets: List of URLs or domains to check
            output_file: Optional output file
            timeout: Scan timeout
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if not self.is_available():
            return ReconResult(
                tool=self.name,
                target="multiple",
                findings=[],
                errors=["httpx not installed. Run: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"],
                execution_time=0
            )
        
        targets_file = _get_temp_path("httpx_targets.txt")
        results_file = output_file or _get_temp_path("httpx_results.txt")
        
        try:
            # Write targets to temp file
            with open(targets_file, "w") as f:
                f.write("\n".join(targets))
            
            cmd = ["httpx", "-list", targets_file, "-json", "-o", results_file]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            # Parse JSON output
            try:
                if os.path.exists(results_file):
                    with open(results_file, "r", encoding='utf-8', errors='replace') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line.strip())
                                    findings.append({
                                        "type": "alive_host",
                                        "url": data.get("url", ""),
                                        "status_code": data.get("status_code", 0),
                                        "content_type": data.get("content_type", ""),
                                        "length": data.get("length", 0)
                                    })
                                except:
                                    pass
            except Exception as e:
                errors.append(f"Error parsing results: {str(e)}")
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        finally:
            try:
                if os.path.exists(targets_file):
                    os.remove(targets_file)
            except:
                pass
        
        return ReconResult(
            tool=self.name,
            target="multiple",
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class DalfoxTool:
    """
    Dalfox - XSS vulnerability scanner.
    
    Fast and accurate XSS detection and analysis tool.
    Supports:
    - Single URL testing
    - File-based testing (bulk)
    - Pipeline input (stdin)
    
    Methodology from guide:
        cat urls.txt | uro | gf xss > xss.txt
        dalfox file xss.txt | tee XSSvulnerable.txt
    """
    
    def __init__(self):
        self.name = "dalfox"
    
    def is_available(self) -> bool:
        """Check if dalfox is installed."""
        path = _get_path_for_tool("dalfox")
        if path and path != "dalfox" and os.path.exists(path):
            return True
        try:
            result = subprocess.run(
                ["dalfox", "help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def scan(
        self,
        target: str = None,
        wordlist_file: str = None,
        mode: str = "url",
        timeout: int = 600
    ) -> "ReconResult":
        """
        Run Dalfox XSS scan.
        
        Args:
            target: Target URL (for url mode)
            wordlist_file: File with URLs to test (for file mode)
            mode: Scan mode - "url", "file", or "pipe"
            timeout: Scan timeout
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if not self.is_available():
            return ReconResult(
                tool=self.name,
                target=target or wordlist_file or "stdin",
                findings=[],
                errors=["Dalfox not installed. Run: go install github.com/hahwul/dalfox/v2@latest"],
                execution_time=0
            )
        
        try:
            cmd = ["dalfox"]
            
            if mode == "url" and target:
                cmd.extend(["url", target])
            elif mode == "file" and wordlist_file:
                cmd.extend(["file", wordlist_file])
            elif mode == "pipe":
                cmd.append("pipe")
            
            dalfox_output = _get_temp_path("dalfox_results.txt")
            cmd.extend(["--output", dalfox_output])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            # Parse dalfox output
            for line in raw_output.split('\n'):
                if "[POTENTIAL" in line.upper() or "XSS" in line.upper() or "found" in line.lower():
                    findings.append({
                        "type": "xss_vulnerability",
                        "value": line.strip(),
                        "tool": "dalfox"
                    })
            
            # Read output file
            try:
                if os.path.exists(dalfox_output):
                    with open(dalfox_output, "r", encoding='utf-8', errors='replace') as f:
                        for line in f:
                            if line.strip():
                                findings.append({
                                    "type": "xss_vulnerability",
                                    "value": line.strip(),
                                    "tool": "dalfox"
                                })
            except:
                pass
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        
        return ReconResult(
            tool=self.name,
            target=target or wordlist_file or "stdin",
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class SqlifinderTool:
    """
    Sqlifinder - SQL injection vulnerability finder.
    
    Discovers SQL injection vulnerabilities on target domains.
    
    Methodology from guide:
        python3 sqlifinder.py -d domain.com
    """
    
    def __init__(self):
        self.name = "sqlifinder"
        self.install_url = "https://github.com/americo/sqlifinder"
    
    def is_available(self) -> bool:
        """Check if sqlifinder is installed."""
        paths = [
            os.path.join(SENTINELX_TOOLS_DIR, "sqlifinder", "sqlifinder.py"),
            os.path.expanduser("~/sqlifinder/sqlifinder.py"),
        ]
        for path in paths:
            if os.path.exists(path):
                return True
        return False
    
    async def scan(
        self,
        target: str = None,
        target_file: str = None,
        timeout: int = 600
    ) -> "ReconResult":
        """
        Run Sqlifinder scan.
        
        Args:
            target: Target domain (when using -d option)
            target_file: File with targets (when using -l option)
            timeout: Scan timeout
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        tool_paths = [
            os.path.join(SENTINELX_TOOLS_DIR, "sqlifinder", "sqlifinder.py"),
            os.path.expanduser("~/sqlifinder/sqlifinder.py"),
        ]
        
        tool_path = None
        for path in tool_paths:
            if os.path.exists(path):
                tool_path = path
                break
        
        if not tool_path:
            errors.append(f"Sqlifinder not found. Install from: {self.install_url}")
            return ReconResult(
                tool=self.name,
                target=target or target_file or "unknown",
                findings=[],
                errors=errors,
                execution_time=(datetime.now() - start_time).total_seconds()
            )
        
        try:
            cmd = ["python3", tool_path]
            
            if target:
                cmd.extend(["-d", target])
            elif target_file:
                cmd.extend(["-l", target_file])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            # Parse SQL injection findings
            for line in raw_output.split('\n'):
                if "SQL" in line.upper() or "INJECT" in line.upper() or "sqli" in line.lower():
                    findings.append({
                        "type": "sql_injection",
                        "value": line.strip(),
                        "tool": "sqlifinder"
                    })
                elif line.strip().startswith("http"):
                    findings.append({
                        "type": "potential_sqli_url",
                        "value": line.strip(),
                        "tool": "sqlifinder"
                    })
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        
        return ReconResult(
            tool=self.name,
            target=target or target_file or "unknown",
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


class NucleiTool:
    """
    Nuclei - Vulnerability scanner based on templates.
    
    Scans URLs using predefined vulnerability templates.
    
    Methodology from guide:
        nuclei -list urls.txt -t /fuzzing-templates
        nuclei -list AliveSubs.txt -t /nuclei-templates/vulnerabilities -t /nuclei-templates/cves
    """
    
    def __init__(self):
        self.name = "nuclei"
    
    def is_available(self) -> bool:
        """Check if nuclei is installed."""
        path = _get_path_for_tool("nuclei")
        if path and path != "nuclei" and os.path.exists(path):
            return True
        try:
            result = subprocess.run(
                ["nuclei", "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def scan(
        self,
        targets: List[str],
        templates: List[str] = None,
        tags: List[str] = None,
        output_file: str = None,
        severity: List[str] = None,
        timeout: int = 600
    ) -> "ReconResult":
        """
        Run nuclei vulnerability scan.
        
        Args:
            targets: List of URLs to scan
            templates: Specific template paths to use
            tags: Template tags to use (e.g., ["lfi", "xss", "sqli"])
            output_file: Output file for results
            severity: Filter by severity (critical, high, medium, low, info)
            timeout: Scan timeout
        """
        start_time = datetime.now()
        errors = []
        findings = []
        raw_output = ""
        
        if not self.is_available():
            return ReconResult(
                tool=self.name,
                target="multiple",
                findings=[],
                errors=["nuclei not installed. Run: go install -v github.com/projectdiscovery/nuclei/v2@latest"],
                execution_time=0
            )
        
        targets_file = _get_temp_path("nuclei_targets.txt")
        
        try:
            # Write targets to temp file
            with open(targets_file, "w") as f:
                f.write("\n".join(targets))
            
            cmd = ["nuclei", "-list", targets_file, "-json"]
            
            if output_file:
                cmd.extend(["-o", output_file])
            
            if templates:
                for t in templates:
                    cmd.extend(["-t", t])
            
            if tags:
                for tag in tags:
                    cmd.extend(["-tags", tag])
            
            if severity:
                cmd.extend(["-severity", ",".join(severity)])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            raw_output = stdout.decode('utf-8', errors='replace')
            
            # Parse JSON output
            for line in raw_output.split('\n'):
                if line.strip() and line.startswith('{'):
                    try:
                        data = json.loads(line.strip())
                        info = data.get("info", {})
                        findings.append({
                            "type": "vulnerability",
                            "name": info.get("name", "Unknown"),
                            "severity": data.get("severity", "info"),
                            "matched_at": data.get("matched-at", ""),
                            "template": data.get("template", ""),
                            "template_id": data.get("template-id", ""),
                        })
                    except:
                        pass
            
            if output_file and raw_output:
                with open(output_file, "w") as f:
                    f.write(raw_output)
            
        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {timeout} seconds")
        except Exception as e:
            errors.append(str(e))
        finally:
            try:
                if os.path.exists(targets_file):
                    os.remove(targets_file)
            except:
                pass
        
        return ReconResult(
            tool=self.name,
            target="multiple",
            findings=findings,
            errors=errors,
            execution_time=(datetime.now() - start_time).total_seconds(),
            raw_output=raw_output
        )


# ============================================================================
# INTEGRATED RECON WORKFLOW
# ============================================================================

class ReconnaissanceWorkflow:
    """
    Integrated reconnaissance workflow following the methodology from the guide.
    
    Flow:
    2. Subdomain enumeration (SubFinder + SubEnum)
    3. HTTP probing (httpx) to find alive hosts
    4. URL collection (waybackurls/gau)
    5. Parameter extraction for testing
    6. XSS scanning (Dalfox)
    7. SQL injection testing (Sqlifinder)
    8. Nuclei vulnerability scanning
    """
    
    def __init__(self):
        self.subfinder = SubFinderTool()
        self.subenum = SubEnumTool()
        self.waybackurls = WaybackUrlsTool()
        self.gau = GauTool()
        self.dalfox = DalfoxTool()
        self.sqlifinder = SqlifinderTool()
        self.httpx = HttpxTool()
        self.nuclei = NucleiTool()
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get status of all reconnaissance tools."""
        return {
            "bigbountyrecon": self.bigbountyrecon.is_available(),
            "subfinder": self.subfinder.is_available(),
            "subenum": self.subenum.is_available(),
            "waybackurls": self.waybackurls.is_available(),
            "gau": self.gau.is_available(),
            "dalfox": self.dalfox.is_available(),
            "sqlifinder": self.sqlifinder.is_available(),
            "httpx": self.httpx.is_available(),
            "nuclei": self.nuclei.is_available(),
        }
    
    async def run_full_recon(self, target: str) -> Dict[str, ReconResult]:
        """
        Run the full reconnaissance workflow.
        
        Args:
            target: Target domain (e.g., "example.com")
        
        Returns:
            Dictionary of results from each tool
        """
        results = {}
        
        # Step 1: Google Dorking
        print(f"[+] Running Google Dorking on {target}...")
        results["bigbountyrecon"] = await self.bigbountyrecon.scan(target)
        
        # Step 2: Subdomain Enumeration
        print(f"[+] Enumerating subdomains for {target}...")
        results["subfinder"] = await self.subfinder.scan(target)
        results["subenum"] = await self.subenum.scan(target)
        
        # Combine and deduplicate subdomains
        all_subdomains = set()
        for r in [results.get("subfinder"), results.get("subenum")]:
            if r:
                for f in r.findings:
                    if f.get("type") == "subdomain":
                        all_subdomains.add(f.get("value"))
        
        if not all_subdomains:
            print(f"[-] No subdomains found for {target}")
            return results
        
        print(f"[+] Found {len(all_subdomains)} subdomains")
        
        # Step 3: HTTP probing to find alive hosts
        print(f"[+] Probing {len(all_subdomains)} subdomains for alive hosts...")
        subdomains_list = list(all_subdomains)
        results["httpx"] = await self.httpx.scan(subdomains_list)
        
        alive_hosts = [f["url"] for f in results["httpx"].findings if f.get("type") == "alive_host"]
        print(f"[+] Found {len(alive_hosts)} alive hosts")
        
        if not alive_hosts:
            print(f"[-] No alive hosts found")
            return results
        
        # Step 4: Collect URLs with waybackurls
        print(f"[+] Collecting URLs from Wayback Machine...")
        results["waybackurls"] = await self.waybackurls.scan(alive_hosts)
        print(f"[+] Found {len(results['waybackurls'].findings)} URLs")
        
        # Step 5: SQL Injection Testing
        print(f"[+] Running SQL injection scan on {target}...")
        results["sqlifinder"] = await self.sqlifinder.scan(target=target)
        
        return results
    
    async def run_recon_phase(self, phase: str, target: str, targets: List[str] = None) -> "ReconResult":
        """
        Run a specific reconnaissance phase.
        
        Args:
            phase: Phase name - "dorking", "subdomains", "http_probing", "urls", "xss", "sqli", "vulnerabilities"
            target: Target domain
            targets: Optional list of targets (for phases that need multiple inputs)
        """
        if phase == "dorking":
            return await self.bigbountyrecon.scan(target)
        elif phase == "subdomains":
            results = []
            r1 = await self.subfinder.scan(target)
            r2 = await self.subenum.scan(target)
            return r1  # Return first result, can be combined
        elif phase == "http_probing" and targets:
            return await self.httpx.scan(targets)
        elif phase == "urls" and targets:
            return await self.waybackurls.scan(targets)
        elif phase == "xss" and targets:
            return await self.dalfox.scan(wordlist_file=self._write_urls_to_file(targets), mode="file")
        elif phase == "sqli":
            return await self.sqlifinder.scan(target=target)
        elif phase == "vulnerabilities" and targets:
            return await self.nuclei.scan(targets)
        else:
            return ReconResult(
                tool=phase,
                target=target,
                findings=[],
                errors=[f"Unknown phase: {phase}"],
                execution_time=0
            )
    
    def _write_urls_to_file(self, urls: List[str]) -> str:
        """Write URLs to a temp file for tool input."""
        path = _get_temp_path("recon_urls.txt")
        with open(path, "w") as f:
            f.write("\n".join(urls))
        return path


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

_recon_workflow: Optional[ReconnaissanceWorkflow] = None

def get_recon_workflow() -> ReconnaissanceWorkflow:
    """Get or create global reconnaissance workflow instance."""
    global _recon_workflow
    if _recon_workflow is None:
        _recon_workflow = ReconnaissanceWorkflow()
    return _recon_workflow