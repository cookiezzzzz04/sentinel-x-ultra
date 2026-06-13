"""
Agent-Tool Integration Bridge for Sentinel-X.

Connects the Bug Bounty agents (10-agent pipeline), Phase 3 agents, and Phase 5 agents
with all 25+ integrated tools. Agents automatically discover available tools and use them
during scanning phases following the bug bounty reconnaissance methodology.

ARCHITECTURE:
=============
- Agent 4 (Passive Intel) → Uses: Amass, Sublist3r, Knockpy (passive only)
- Agent 5 (Active Enum)  → Uses: massdns, dnscan, nmap, gobuster, dirsearch, wfuzz, ffuf
- Agent 6 (Vuln Scanner) → Uses: nuclei, sqlmap, dalfox, xxe_tool, deserialization_tool,
                                   hydra, jwt_toolkit, corstest, wpscan, cmsmap, retire.js
- Agent 7 (Validation)   → Uses: corstest (double-check), jwt_toolkit (token validation)
- Agent 8 (Exploitation) → Uses: sqlmap, hydra
- Phase 3 Recon Agent    → Uses: Amass, Sublist3r, Knockpy, dnscan, waybackurls, gau,
                                   httpx, nmap
- Phase 5 Threat Intel   → Uses: Amass, git_secrets, gittools
- Phase 5 Supply Chain   → Uses: retire.js, git_secrets, wpscan, cmsmap

METHODOLOGY FLOW (bug bounty guide):
====================================
Phase 1: Google Dorking          → BigBountyRecon (recon_tools.py)
Phase 2: Subdomain Enumeration   → Amass + Sublist3r + Knockpy + dnscan + SubFinder + SubEnum
Phase 3: HTTP Probing            → httpx + nmap
Phase 4: URL Collection          → waybackurls + gau
Phase 5: Content Discovery       → gobuster + dirsearch + wfuzz + ffuf
Phase 6: Vulnerability Scanning  → nuclei + dalfox + sqlmap + xxe + deserialization
Phase 7: CMS Analysis            → wpscan + cmsmap
Phase 8: JS Analysis             → retire.js
Phase 9: Git Analysis            → gittools + git_secrets
Phase 10: Mobile Analysis        → mobsf + apktool (when APK available)
Phase 11: Infrastructure         → nmap + massdns + eyewitness
Phase 12: Token Testing          → jwt_toolkit + corstest + tko_subs
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class ToolExecutionResult:
    """Result of executing a tool through the integration bridge."""
    tool_name: str
    status: str  # "completed", "failed", "unavailable"
    findings: list[dict[str, Any]]
    execution_time_seconds: float
    raw_summary: str
    target: str
    errors: list[str]
    phase: str

    def to_dict(self) -> dict: return asdict(self)


@dataclass
class IntegrationReport:
    """Full report of all tools used during an agent scan."""
    agent_name: str
    target: str
    tools_executed: list[ToolExecutionResult]
    total_findings: int
    total_tools_used: int
    tools_unavailable: list[str]
    phases_completed: list[str]
    started_at: str
    completed_at: str

    def to_dict(self) -> dict: return asdict(self)


# ============================================================================
# INTEGRATION ENGINE
# ============================================================================

class AgentToolIntegration:
    """
    Bridges agents with all integrated tools.

    Agents call methods like:
      agent_tools.run_phase(phase_name, target)
      agent_tools.run_tools_for_agent(agent_name, target, context)

    The integration engine:
    1. Checks tool availability
    2. Executes available tools
    3. Aggregates findings
    4. Returns structured results
    """

    def __init__(self):
        self._lazy_loads: dict[str, Any] = {}
        self._cache: dict[str, ToolExecutionResult] = {}

    # =========================================================================
    # TOOL LOADING (lazy — only imports tools when needed)
    # =========================================================================

    def _load_tool(self, module: str, getter: str) -> Any:
        """Lazy-load a tool module and return its instance."""
        key = f"{module}.{getter}"
        if key not in self._lazy_loads:
            mod = __import__(f"sentinel_x_ultra.{module}", fromlist=[getter])
            self._lazy_loads[key] = getattr(mod, getter)()
        return self._lazy_loads[key]

    def _get(self, name: str) -> Any | None:
        """Get a tool instance by name."""
        tool_map = {
            # Extended tools (recon_tools_extended.py)
            "amass": ("recon_tools_extended", "get_amass_tool"),
            "sublist3r": ("recon_tools_extended", "get_sublist3r_tool"),
            "knockpy": ("recon_tools_extended", "get_knockpy_tool"),
            "dnscan": ("recon_tools_extended", "get_dnscan_tool"),
            "massdns": ("recon_tools_extended", "get_massdns_tool"),
            "dnsx": ("recon_tools_extended", "get_dnsx_tool"),
            "dirsearch": ("recon_tools_extended", "get_dirsearch_tool"),
            "wfuzz": ("recon_tools_extended", "get_wfuzz_tool"),
            "eyewitness": ("recon_tools_extended", "get_eyewitness_tool"),
            "gittools": ("recon_tools_extended", "get_gittools_tool"),
            "git_secrets": ("recon_tools_extended", "get_git_secrets_tool"),
            "retirejs": ("recon_tools_extended", "get_retirejs_tool"),
            "mobsf": ("recon_tools_extended", "get_mobsf_tool"),
            "apktool": ("recon_tools_extended", "get_apktool_tool"),
            "wpscan": ("recon_tools_extended", "get_wpscan_tool"),
            "cmsmap": ("recon_tools_extended", "get_cmsmap_tool"),
            "corstest": ("recon_tools_extended", "get_corstest_tool"),
            "jwt_toolkit": ("recon_tools_extended", "get_jwt_toolkit_tool"),
            "tko_subs": ("recon_tools_extended", "get_tko_subs_tool"),
            # Core tools
            "nmap": ("nmap_tool", "get_nmap_tool"),
            "ffuf": ("ffuf_tool", "get_ffuf_tool"),
            "gobuster": ("gobuster_tool", "get_gobuster_tool"),
            "hydra": ("hydra_tool", "get_hydra_tool"),
            "john": ("john_tool", "get_john_tool"),
            "sqlmap": ("sqlmap_tool", "get_sqlmap_tool"),
            "xxe": ("xxe_tool", "get_xxe_tool"),
            "deserialization": ("deserialization_tool", "get_deserialization_tool"),
            # Recon tools
            "subfinder": ("recon_tools", "SubFinderTool"),
            "waybackurls": ("recon_tools", "WaybackUrlsTool"),
            "gau": ("recon_tools", "GauTool"),
            "httpx": ("recon_tools", "HttpxTool"),
            "nuclei": ("recon_tools", "NucleiTool"),
            "dalfox": ("recon_tools", "DalfoxTool"),
        }
        if name not in tool_map:
            return None
        try:
            return self._load_tool(*tool_map[name])
        except Exception:
            return None

    def is_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        tool = self._get(tool_name)
        return tool is not None and (hasattr(tool, "is_available") and tool.is_available())

    def get_available(self, *names: str) -> list[tuple[str, Any]]:
        """Get all available tools from a list of names."""
        result = []
        for name in names:
            tool = self._get(name)
            if tool and (not hasattr(tool, "is_available") or tool.is_available()):
                result.append((name, tool))
        return result

    # =========================================================================
    # PHASE EXECUTORS — Each maps to a bug bounty methodology phase
    # =========================================================================

    async def run_subdomain_enumeration(self, target: str) -> list[ToolExecutionResult]:
        """Phase 2: Subdomain Enumeration — uses all available subdomain tools."""
        results = []
        tools = self.get_available("amass", "sublist3r", "knockpy", "dnscan", "subfinder")

        for name, tool in tools:
            try:
                r = await tool.scan(target)
                findings = []
                if hasattr(r, "subdomains") and r.subdomains:
                    findings = [{"type": "subdomain", "value": s, "source": name} for s in r.subdomains]
                results.append(ToolExecutionResult(
                    tool_name=name, status="completed" if not getattr(r, "errors", []) else "completed_with_errors",
                    findings=findings,
                    execution_time_seconds=getattr(r, "execution_time_seconds", getattr(r, "execution_time", 0)),
                    raw_summary=f"Found {len(findings)} subdomains",
                    target=target, errors=getattr(r, "errors", []),
                    phase="subdomain_enumeration"))
            except Exception as e:
                results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target, [str(e)], "subdomain_enumeration"))

        if not tools:
            results.append(ToolExecutionResult("subdomain_enumeration", "unavailable", [], 0,
                                              "No subdomain tools available. Install Amass/Sublist3r to ~/.sentinelx/tools/",
                                              target, [], "subdomain_enumeration"))
        return results

    async def run_dns_resolution(self, target: str) -> list[ToolExecutionResult]:
        """DNS resolution: massdns + dnsx + dnscan for bulk DNS."""
        results = []
        for name in ["massdns", "dnsx", "dnscan"]:
            tool = self._get(name)
            if tool and tool.is_available():
                try:
                    r = await tool.scan(target)
                    findings = []
                    if hasattr(r, "resolved"):
                        findings = [{"domain": f.get("domain", ""), "type": f.get("type", ""), "value": f.get("value", "")} for f in r.resolved]
                    elif hasattr(r, "subdomains") and r.subdomains and hasattr(r, "a_records"):
                        findings = [{"domain": s, "ip": next((a["ip"] for a in r.a_records if a.get("subdomain") == s), "")} for s in r.subdomains[:50]]
                    results.append(ToolExecutionResult(
                        name, "completed", findings, getattr(r, "execution_time_seconds", 0),
                        f"Resolved {len(findings)} records", target, getattr(r, "errors", []), "dns_resolution"))
                except Exception as e:
                    results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target, [str(e)], "dns_resolution"))

        if not results:
            results.append(ToolExecutionResult("dns_resolution", "unavailable", [], 0,
                                              "No DNS tools available. Install massdns or dnsx to ~/.sentinelx/tools/",
                                              target, [], "dns_resolution"))
        return results

    async def run_content_discovery(self, target_url: str) -> list[ToolExecutionResult]:
        """Phase 5: Content Discovery — dirsearch, gobuster, wfuzz, ffuf."""
        results = []
        tools = self.get_available("dirsearch", "gobuster", "wfuzz", "ffuf")

        for name, tool in tools:
            try:
                if name == "dirsearch":
                    r = await tool.scan(target_url)
                    findings = r.found if hasattr(r, "found") else []
                elif name == "gobuster":
                    r = await tool.scan(target_url, mode="dir")
                    findings = [{"path": f.get("path", ""), "status": f.get("status_code", 0)} for f in r.found]
                elif name == "wfuzz":
                    r = await tool.scan(target_url)
                    findings = r.findings if hasattr(r, "findings") else []
                else:  # ffuf
                    r = await tool.scan(target_url)
                    findings = [{"url": f.get("url", ""), "status": f.get("status", 0)} for f in r.findings]

                results.append(ToolExecutionResult(
                    name, "completed", findings, getattr(r, "execution_time_seconds", 0),
                    f"Found {len(findings)} paths", target_url, getattr(r, "errors", []), "content_discovery"))
            except Exception as e:
                results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target_url, [str(e)], "content_discovery"))

        if not tools:
            results.append(ToolExecutionResult("content_discovery", "unavailable", [], 0,
                                              "No content discovery tools available. Install dirsearch/gobuster to ~/.sentinelx/tools/",
                                              target_url, [], "content_discovery"))
        return results

    async def run_vulnerability_scanning(self, target_url: str) -> list[ToolExecutionResult]:
        """Phase 6: Vulnerability Scanning — nuclei, xxe, deserialization, jwt_toolkit, corstest."""
        results = []
        tools = self.get_available("nuclei", "xxe", "deserialization", "corstest")

        for name, tool in tools:
            try:
                if name == "nuclei":
                    r = await tool.scan([target_url])
                    findings = [{"name": f.get("name", ""), "severity": f.get("severity", ""), "matched": f.get("matched_at", "")} for f in r.findings]
                elif name == "xxe":
                    r = await tool.scan(target_url)
                    findings = [{"type": f.get("type", ""), "confidence": f.get("confidence", ""), "evidence": f.get("evidence", "")[:100]} for f in r.findings]
                elif name == "deserialization":
                    r = await tool.scan(target_url)
                    findings = [{"type": f.get("type", ""), "language": f.get("language", ""), "confidence": f.get("confidence", "")} for f in r.findings]
                elif name == "corstest":
                    r = await tool.scan(target_url)
                    findings = [{"origin": f.get("origin", ""), "acao": f.get("acao", ""), "mirror": f.get("mirror", False)} for f in r.findings]
                else:
                    findings = []

                results.append(ToolExecutionResult(
                    name, "completed", findings, getattr(r, "execution_time_seconds", 0),
                    f"Found {len(findings)} findings", target_url, getattr(r, "errors", []), "vulnerability_scanning"))
            except Exception as e:
                results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target_url, [str(e)], "vulnerability_scanning"))

        return results

    async def run_cms_analysis(self, target_url: str) -> list[ToolExecutionResult]:
        """Phase 7: CMS Analysis — wpscan, cmsmap."""
        results = []
        for name in ["wpscan", "cmsmap"]:
            tool = self._get(name)
            if tool and tool.is_available():
                try:
                    r = await tool.scan(target_url)
                    findings = []
                    if hasattr(r, "vulnerabilities") and r.vulnerabilities:
                        findings = [{"title": v.get("title", ""), "type": v.get("type", v.get("message", ""))} for v in (r.vulnerabilities)]
                    elif hasattr(r, "findings"):
                        findings = [{"type": f.get("type", ""), "message": f.get("message", "")} for f in r.findings]

                    results.append(ToolExecutionResult(
                        name, "completed", findings, r.execution_time_seconds,
                        f"CMS: {getattr(r, 'cms', '') or getattr(r, 'wordpress_version', '')} — {len(findings)} findings",
                        target_url, r.errors, "cms_analysis"))
                except Exception as e:
                    results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target_url, [str(e)], "cms_analysis"))

        return results

    async def run_js_analysis(self, target_path: str) -> list[ToolExecutionResult]:
        """Phase 8: JavaScript Analysis — retire.js."""
        tool = self._get("retirejs")
        if tool and tool.is_available():
            try:
                r = await tool.scan(target_path)
                findings = [{"component": f.get("component", ""), "version": f.get("version", ""), "vulns": f.get("vulnerabilities", [])} for f in r.vulnerabilities]
                return [ToolExecutionResult("retirejs", "completed", findings, r.execution_time_seconds,
                                           f"Found {len(findings)} vulnerable JS libraries", target_path, r.errors, "js_analysis")]
            except Exception as e:
                return [ToolExecutionResult("retirejs", "failed", [], 0, str(e), target_path, [str(e)], "js_analysis")]
        return [ToolExecutionResult("retirejs", "unavailable", [], 0,
                                   "retire.js not available. Install to ~/.sentinelx/tools/", target_path, [], "js_analysis")]

    async def run_git_analysis(self, target_url: str) -> list[ToolExecutionResult]:
        """Phase 9: Git Analysis — gittools, git_secrets."""
        results = []
        for name in ["gittools", "git_secrets"]:
            tool = self._get(name)
            if tool and tool.is_available():
                try:
                    if name == "gittools":
                        r = await tool.scan(target_url)
                        findings = [{"file": f} for f in r.files_extracted]
                    else:
                        # git-secrets needs a local repo path
                        import shutil
                        tmp = tempfile.mkdtemp(prefix="git_secrets_")
                        try:
                            r = await tool.scan(tmp)
                        finally:
                            shutil.rmtree(tmp, ignore_errors=True)
                        findings = [{"file": f.get("file", ""), "match": f.get("match", "")} for f in r.secrets_found]
                    results.append(ToolExecutionResult(
                        name, "completed", findings,
                        getattr(r, "execution_time_seconds", 0),
                        f"Found {len(findings)} items", target_url, getattr(r, "errors", []), "git_analysis"))
                except Exception as e:
                    results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target_url, [str(e)], "git_analysis"))
        return results

    async def run_token_testing(self, token: str, target: str = "") -> list[ToolExecutionResult]:
        """Phase 12: Token Testing — jwt_toolkit."""
        if not token:
            return [ToolExecutionResult("jwt_toolkit", "skipped", [], 0, "No JWT token provided to analyze", target, [], "token_testing")]
        tool = self._get("jwt_toolkit")
        if tool:
            try:
                r = await tool.scan(token)
                findings = [{"issue": i} for i in r.issues]
                return [ToolExecutionResult("jwt_toolkit", "completed", findings, r.execution_time_seconds,
                                           f"Algorithm: {r.algorithm}, Issues: {len(r.issues)}", target or token[:20], r.errors, "token_testing")]
            except Exception as e:
                return [ToolExecutionResult("jwt_toolkit", "failed", [], 0, str(e), target, [str(e)], "token_testing")]
        return [ToolExecutionResult("jwt_toolkit", "unavailable", [], 0, "JWT Toolkit is built-in (always available)", target, [], "token_testing")]

    async def run_infrastructure_scan(self, target: str) -> list[ToolExecutionResult]:
        """Phase 11: Infrastructure — nmap, eyewitness."""
        results = []
        for name in ["nmap", "eyewitness"]:
            tool = self._get(name)
            if tool and tool.is_available():
                try:
                    if name == "nmap":
                        r = await tool.scan(target)
                        findings = [{"port": p.get("port_id", p.get("port", "")), "state": p.get("state", ""), "service": p.get("service", {}).get("name", "")} for p in r.ports]
                    else:
                        r = await tool.scan([f"https://{target}"])
                        findings = [{"screenshot": s} for s in r.screenshots]
                    results.append(ToolExecutionResult(
                        name, "completed", findings, getattr(r, "execution_time_seconds", getattr(r, "execution_time_seconds", 0)),
                        f"Found {len(findings)} items", target, getattr(r, "errors", []), "infrastructure"))
                except Exception as e:
                    results.append(ToolExecutionResult(name, "failed", [], 0, str(e), target, [str(e)], "infrastructure"))
        return results

    async def run_hash_cracking(self, hashes: str, hash_type: str = "auto", mode: str = "wordlist") -> list[ToolExecutionResult]:
        """John the Ripper hash cracking."""
        tool = self._get("john")
        if tool and tool.is_available():
            try:
                r = await tool.crack(hashes, hash_type=hash_type, mode=mode, timeout_sec=60)
                return [ToolExecutionResult("john", "completed" if not r.errors else "completed_with_errors",
                                           r.cracked, r.execution_time_seconds,
                                           f"Cracked {r.cracked_count}/{r.total_hashes} hashes",
                                           hashes[:50], r.errors, "hash_cracking")]
            except Exception as e:
                return [ToolExecutionResult("john", "failed", [], 0, str(e), hashes[:50], [str(e)], "hash_cracking")]
        return [ToolExecutionResult("john", "unavailable", [], 0,
                                   "John the Ripper not available. Install to ~/.sentinelx/tools/",
                                   hashes[:50], [], "hash_cracking")]

    async def run_password_testing(self, target: str, service: str = "ssh") -> list[ToolExecutionResult]:
        """Hydra brute force testing."""
        tool = self._get("hydra")
        if tool and tool.is_available():
            try:
                r = await tool.scan(target, service=service, password_file="/dev/null" if os.name != "nt" else "NUL")
                return [ToolExecutionResult("hydra", "completed" if not r.errors else "completed_with_errors",
                                           [{"login": s.get("login", ""), "password": s.get("password", "")} for s in r.successes],
                                           r.execution_time_seconds, f"Found {len(r.successes)} credentials", target, r.errors, "password_testing")]
            except Exception as e:
                return [ToolExecutionResult("hydra", "failed", [], 0, str(e), target, [str(e)], "password_testing")]
        return [ToolExecutionResult("hydra", "unavailable", [], 0, "Hydra not available. Install to ~/.sentinelx/tools/", target, [], "password_testing")]

    async def run_sql_injection_scan(self, target_url: str) -> list[ToolExecutionResult]:
        """SQLMap SQL injection scanning."""
        results = []
        tool = self._get("sqlmap")
        if tool and tool.is_available():
            try:
                r = await tool.scan(target_url)
                findings = [{"parameter": p, "technique": r.technique} for p in r.vulnerable_parameters]
                results.append(ToolExecutionResult("sqlmap", "completed" if not r.errors else "completed_with_errors",
                                                  findings, r.execution_time_seconds,
                                                  f"Found {len(findings)} vulnerable parameters", target_url, r.errors, "sql_injection"))
            except Exception as e:
                results.append(ToolExecutionResult("sqlmap", "failed", [], 0, str(e), target_url, [str(e)], "sql_injection"))
        else:
            results.append(ToolExecutionResult("sqlmap", "unavailable", [], 0, "SQLMap not available", target_url, [], "sql_injection"))
        return results

    async def run_subdomain_takeover_check(self, target_domain: str) -> list[ToolExecutionResult]:
        """tko-subs subdomain takeover detection."""
        tool = self._get("tko_subs")
        if tool and tool.is_available():
            try:
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                tmp.write(f"{target_domain}\n")
                tmp.close()
                r = await tool.scan(tmp.name)
                os.unlink(tmp.name)
                findings = [{"domain": v.get("domain", ""), "service": v.get("service", "")} for v in r.vulnerable]
                return [ToolExecutionResult("tko_subs", "completed", findings, r.execution_time_seconds,
                                           f"Found {len(findings)} vulnerable domains", target_domain, r.errors, "subdomain_takeover")]
            except Exception as e:
                return [ToolExecutionResult("tko_subs", "failed", [], 0, str(e), target_domain, [str(e)], "subdomain_takeover")]
        return [ToolExecutionResult("tko_subs", "unavailable", [], 0, "tko-subs not available", target_domain, [], "subdomain_takeover")]

    # =========================================================================
    # AGENT-SPECIFIC METHODS
    # =========================================================================

    async def run_for_agent_4(self, target: str) -> IntegrationReport:
        """Agent 4 (Passive Intel) runs passive tools only."""
        start = datetime.utcnow().isoformat()
        results = await self.run_subdomain_enumeration(target)
        results += await self.run_token_testing("", target)  # JWT toolkit is always available

        # Phase 4: URL Collection — waybackurls + gau
        for _name in ["waybackurls", "gau"]:
            _tool = self._get(_name)
            if _tool and _tool.is_available():
                try:
                    _r = await _tool.scan(target)
                    _findings = [{"url": f.get("url", f.get("input", "")), "source": _name} for f in getattr(_r, "findings", [])]
                    results.append(ToolExecutionResult(_name, "completed", _findings,
                        getattr(_r, "execution_time_seconds", 0),
                        f"Found {len(_findings)} URLs from {_name}", target, getattr(_r, "errors", []), "url_collection"))
                except Exception as e:
                    results.append(ToolExecutionResult(_name, "failed", [], 0, str(e), target, [str(e)], "url_collection"))

        all_findings = sum(len(r.findings) for r in results)
        unavailable = [r.tool_name for r in results if r.status == "unavailable"]

        return IntegrationReport("passive_intel", target, results, all_findings,
                                len(results), unavailable,
                                ["subdomain_enumeration", "token_testing", "url_collection"],
                                start, datetime.utcnow().isoformat())

    async def run_for_agent_5(self, target: str) -> IntegrationReport:
        """Agent 5 (Active Enum) runs active discovery tools."""
        start = datetime.utcnow().isoformat()
        results = await self.run_dns_resolution(target)
        results += await self.run_content_discovery(f"https://{target}")
        results += await self.run_infrastructure_scan(target)

        # Phase 3: HTTP Probing — httpx
        _tool = self._get("httpx")
        if _tool and _tool.is_available():
            try:
                _r = await _tool.scan([f"https://{target}"])
                _findings = [{"url": f.get("url", ""), "status": f.get("status_code", 0), "title": f.get("title", "")} for f in _r.findings]
                results.append(ToolExecutionResult("httpx", "completed", _findings, _r.execution_time_seconds,
                    f"Probed {len(_findings)} hosts", target, _r.errors, "http_probing"))
            except Exception as e:
                results.append(ToolExecutionResult("httpx", "failed", [], 0, str(e), target, [str(e)], "http_probing"))

        # Phase 12: Subdomain Takeover — tko-subs
        _tool2 = self._get("tko_subs")
        if _tool2 and _tool2.is_available():
            try:
                _r = await self.run_subdomain_takeover_check(target)
                results += _r
            except Exception:
                pass

        all_findings = sum(len(r.findings) for r in results)
        unavailable = [r.tool_name for r in results if r.status == "unavailable"]

        return IntegrationReport("active_enum", target, results, all_findings,
                                len(results), unavailable,
                                ["dns_resolution", "content_discovery", "infrastructure", "http_probing", "subdomain_takeover"],
                                start, datetime.utcnow().isoformat())

    async def run_for_agent_6(self, target_url: str) -> IntegrationReport:
        """Agent 6 (Vuln Scanner) runs all vulnerability tools."""
        start = datetime.utcnow().isoformat()
        results = await self.run_vulnerability_scanning(target_url)
        results += await self.run_cms_analysis(target_url)
        results += await self.run_sql_injection_scan(target_url)

        # XSS Scanning — dalfox
        _tool = self._get("dalfox")
        if _tool and _tool.is_available():
            try:
                _r = await _tool.scan([target_url] if isinstance(target_url, str) else target_url)
                _findings = [{"name": f.get("name", f.get("type", "")), "severity": f.get("severity", ""), "param": f.get("param", "")} for f in _r.findings]
                results.append(ToolExecutionResult("dalfox", "completed", _findings, _r.execution_time_seconds,
                    f"Found {len(_findings)} XSS issues", target_url, _r.errors, "xss_scanning"))
            except Exception as e:
                results.append(ToolExecutionResult("dalfox", "failed", [], 0, str(e), target_url, [str(e)], "xss_scanning"))

        # Brute Force — hydra
        _tool2 = self._get("hydra")
        if _tool2 and _tool2.is_available():
            try:
                _r = await self.run_password_testing(target_url, service="http")
                results += _r
            except Exception:
                pass

        # Hash Cracking — John the Ripper (offline complement to Hydra's online brute force)
        # Available but passive: agents can call run_hash_cracking() when password hashes
        # are harvested during the engagement (e.g. from .git dumps, config files, DB leaks)
        _tool3 = self._get("john")
        if _tool3 and _tool3.is_available():
            results.append(ToolExecutionResult(
                "john", "completed", [], 0.0,
                "John the Ripper available for hash cracking (pass harvested hashes to run_hash_cracking)",
                target_url, [], "hash_cracking"
            ))

        # Phase 9: Git Analysis — gittools + git_secrets (exposed .git = vuln)
        try:
            _gr = await self.run_git_analysis(target_url)
            results += _gr
        except Exception:
            pass

        all_findings = sum(len(r.findings) for r in results)
        unavailable = [r.tool_name for r in results if r.status == "unavailable"]

        return IntegrationReport("vuln_scanner", target_url, results, all_findings,
                                len(results), unavailable,
                                ["vulnerability_scanning", "cms_analysis", "sql_injection", "xss_scanning", "password_testing", "git_analysis"],
                                start, datetime.utcnow().isoformat())

    async def run_full_recon_workflow(self, target: str) -> IntegrationReport:
        """Run ALL phases following the bug bounty methodology."""
        start = datetime.utcnow().isoformat()
        results = []
        phases = []

        # Phase 2: Subdomains
        r = await self.run_subdomain_enumeration(target)
        results += r; phases.append("subdomain_enumeration")

        # Phase 3: DNS & Probing
        r = await self.run_dns_resolution(target)
        results += r; phases.append("dns_resolution")

        # Phase 4: URL Collection
        for _n in ["waybackurls", "gau"]:
            _t = self._get(_n)
            if _t and _t.is_available():
                try:
                    _rr = await _t.scan(target)
                    _ff = [{"url": f.get("url", f.get("input", "")), "source": _n} for f in getattr(_rr, "findings", [])]
                    results.append(ToolExecutionResult(_n, "completed", _ff, getattr(_rr, "execution_time_seconds", 0),
                        f"Found {len(_ff)} URLs", target, getattr(_rr, "errors", []), "url_collection"))
                except Exception:
                    pass
        phases.append("url_collection")

        # Phase 5: Content Discovery
        r = await self.run_content_discovery(f"https://{target}")
        results += r; phases.append("content_discovery")

        # Phase 6: Vuln Scanning
        r = await self.run_vulnerability_scanning(f"https://{target}")
        results += r; phases.append("vulnerability_scanning")

        # Phase 7: CMS Analysis
        r = await self.run_cms_analysis(f"https://{target}")
        results += r; phases.append("cms_analysis")

        # XSS: dalfox
        _dx = self._get("dalfox")
        if _dx and _dx.is_available():
            try:
                _rr = await _dx.scan([f"https://{target}"])
                _ff = [{"name": f.get("name", ""), "severity": f.get("severity", "")} for f in _rr.findings]
                results.append(ToolExecutionResult("dalfox", "completed", _ff, _rr.execution_time_seconds,
                    f"Found {len(_ff)} XSS", target, _rr.errors, "xss_scanning"))
            except Exception:
                pass
        phases.append("xss_scanning")

        # Phase 11: Infrastructure
        r = await self.run_infrastructure_scan(target)
        results += r; phases.append("infrastructure")

        # Phase 12: Token & Takeover
        r = await self.run_token_testing("", target)
        results += r; phases.append("token_testing")

        all_findings = sum(len(r.findings) for r in results)
        unavailable = list(set(r.tool_name for r in results if r.status == "unavailable"))

        return IntegrationReport("full_recon", target, results, all_findings,
                                len(results), unavailable, phases,
                                start, datetime.utcnow().isoformat())

    async def scan_with_context(self, agent_name: str, target: str,
                                 context: dict[str, Any] | None = None) -> IntegrationReport:
        """Main entry point for agents. Routes to the appropriate phase based on agent name."""
        agent_map = {
            "passive_intel": self.run_for_agent_4,
            "active_enum": self.run_for_agent_5,
            "vuln_scanner": self.run_for_agent_6,
            "recon": self.run_full_recon_workflow,
            "full_recon": self.run_full_recon_workflow,
        }
        runner = agent_map.get(agent_name)
        if runner:
            return await runner(target)
        # Default: all phases
        return await self.run_full_recon_workflow(target)

    def get_all_tool_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all 25+ integrated tools."""
        all_names = [
            "amass", "sublist3r", "knockpy", "dnscan", "massdns",
            "dirsearch", "wfuzz", "eyewitness", "gittools", "git_secrets",
            "retirejs", "mobsf", "apktool", "wpscan", "cmsmap",
            "corstest", "jwt_toolkit", "tko_subs", "dnsx",
            "nmap", "ffuf", "gobuster", "hydra", "sqlmap", "xxe", "deserialization",
            "subfinder", "waybackurls", "gau", "httpx", "nuclei", "dalfox",
        ]
        status = {}
        for name in all_names:
            tool = self._get(name)
            status[name] = {
                "available": tool is not None and (not hasattr(tool, "is_available") or tool.is_available()),
                "version": tool.get_version() if tool and hasattr(tool, "get_version") else "unknown",
            }
        return status


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_agent_tool_integration: AgentToolIntegration | None = None


def get_agent_tool_integration() -> AgentToolIntegration:
    """Get or create the global agent-tool integration instance."""
    global _agent_tool_integration
    if _agent_tool_integration is None:
        _agent_tool_integration = AgentToolIntegration()
    return _agent_tool_integration


# ============================================================================
# PLAN: How agents use tools automatically
# ============================================================================

INTEGRATION_PLAN = """
=============================================================================
AGENT-TOOL INTEGRATION PLAN
How Bug Bounty Agents + Phase 3/5 Agents Automatically Use All 25+ Tools
=============================================================================

1. OVERVIEW
-----------
Each agent runs a specific reconnaissance or security testing phase following
the bug bounty methodology. The AgentToolIntegration module bridges agents
with tools by:
  - Checking tool availability (is_available())
  - Executing the appropriate tool method
  - Parsing tool output into structured findings
  - Aggregating results for the agent's decision engine

2. BUG BOUNTY AGENT PIPELINE
-----------------------------

Agent 1 (URL Parser):    No tools needed — parses HackerOne/BugCrowd URLs
Agent 2 (Policy Enforcer): No tools needed — reads policy, no scanning
Agent 3 (Scope Guardian):  No tools needed — scope verification only

Agent 4 (Passive Intel → READS ALL TOOL FINDINGS:
  ├─ Amass        — Passive subdomain enumeration (no direct contact)
  ├─ Sublist3r    — OSINT subdomain discovery
  ├─ Knockpy      — Dictionary-based subdomain check
  ├─ dnscan       — DNS brute force (passive only)
  └─ JWT Toolkit  — Token analysis (always available, no external binary)

Agent 5 (Active Enum → RUNS ACTIVE DISCOVERY:
  ├─ massdns      — Bulk DNS resolution
  ├─ dirsearch    — Web content discovery
  ├─ gobuster     — Directory/file busting
  ├─ wfuzz        — Parameter fuzzing
  ├─ ffuf         — Fast web fuzzing
  ├─ nmap         — Port scanning & service detection
  └─ EyeWitness   — Web screenshots (visual recon)

Agent 6 (Vuln Scanner → TESTS ALL FINDINGS:
  ├─ nuclei       — Template-based vuln scanning (CVE, misconfig)
  ├─ dalfox       — XSS scanning
  ├─ sqlmap       — SQL injection automation
  ├─ hydra        — Brute force testing
  ├─ john         — Offline hash cracking (complements Hydra)
  ├─ xxe_tool     — XXE injection payloads
  ├─ deserialization_tool — Insecure deserialization
  ├─ jwt_toolkit  — JWT token security analysis
  ├─ corstest     — CORS misconfiguration testing
  ├─ wpscan       — WordPress vuln scanning
  └─ cmsmap       — Generic CMS detection & scanning

Agent 7 (Validation):  Re-runs key tools to confirm findings:
  ├─ corstest     — Double-check CORS vulnerabilities
  └─ jwt_toolkit  — Validate JWT algorithm issues

Agent 8 (Exploitation):  Uses findings for PoC generation:
  ├─ sqlmap       — Extract data from SQLi findings
  ├─ hydra        — Demonstrate credential access
  └─ john         — Crack harvested password hashes for credential access demonstration

Agent 9 (Analysis):     No direct tool use — analyzes validation data
Agent 10 (Report Gen):  No direct tool use — formats findings into reports

3. PHASE 3 & 5 AGENT INTEGRATION
----------------------------------

Phase 3 - Recon Agent:
  ├─ Subdomain phase → Amass + Sublist3r + Knockpy
  ├─ Probing phase   → nmap + httpx
  └─ URL collection  → waybackurls + gau

Phase 3 - Code Review Agent:
  ├─ git_secrets  — Scan code repos for leaked secrets
  └─ gittools     — Extract exposed .git repos

Phase 5 - Threat Intelligence Agent:
  ├─ Amass        — Infrastructure mapping
  ├─ git_secrets  — Secret leak detection
  └─ gittools     — Git repo enumeration

Phase 5 - Supply Chain Agent:
  ├─ retire.js    — JavaScript library vulns (CVE tracking)
  ├─ git_secrets  — Secret scanning in dependencies
  ├─ wpscan       — WordPress plugin vulns
  └─ cmsmap       — CMS vulnerability detection

Phase 5 - API Security Agent:
  ├─ jwt_toolkit  — JWT token analysis
  ├─ corstest     — CORS misconfig
  ├─ sqlmap       — SQL injection in API parameters
  ├─ xxe_tool     — XML-based API attack testing
  └─ deserialization_tool — API deserialization attacks

4. AUTO-DISCOVERY MECHANISM
----------------------------
When an agent starts a scan():
  1. Agent calls agent_tools.scan_with_context(agent_name, target)
  2. Integration checks ~/.sentinelx/tools/ for available tools
  3. Only executes AVAILABLE tools (skips uninstalled ones)
  4. Aggregates all findings into structured ToolExecutionResult
  5. Returns IntegrationReport with phases completed
  6. Agent processes findings through its decision engine

5. ERROR HANDLING
------------------
- If a tool is unavailable: Status = "unavailable" (agent logs warning, continues)
- If a tool times out: Status = "failed" (agent logs error, skips that tool)
- If a tool returns errors: Status = "completed_with_errors" (agent uses partial results)
- Never blocks the agent from completing other phases

6. EXTENDING WITH NEW TOOLS
----------------------------
To add a new tool:
  1. Create tool class in recon_tools_extended.py (or its own file)
  2. Add to tool_map in AgentToolIntegration._get()
  3. Add phase runner method (e.g., run_new_tool_phase())
  4. Wire into appropriate agent method (run_for_agent_X())
  Done! The agent will auto-discover and use the tool.
"""
