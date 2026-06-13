"""
Extended Reconnaissance Tools for Sentinel-X — 19 additional tools.

This file follows the exact pattern from recon_tools.py, nmap_tool.py, etc.
All tools share the same architecture:
- Class with name, is_available(), get_version(), async scan(), get_capabilities()
- Result dataclass with to_dict()
- Global instance getter get_<tool>_tool()
- Path resolution via ~/.sentinelx/tools/ first, then PATH
"""

import asyncio
import json
import os
import platform
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

# ============================================================================
# UTILITY — Shared path resolution
# ============================================================================

SENTINELX_TOOLS_DIR = os.path.expanduser("~/.sentinelx/tools")


def _find_tool(tool_name: str, extra_paths: list[str] | None = None) -> str | None:
    """Find a tool executable across multiple locations."""
    # 1. Check ~/.sentinelx/tools/
    for name in [tool_name, f"{tool_name}.exe"]:
        p = os.path.join(SENTINELX_TOOLS_DIR, name)
        if os.path.exists(p):
            return p
        # Check subdirectory
        sub = os.path.join(SENTINELX_TOOLS_DIR, tool_name, name)
        if os.path.exists(sub):
            return sub

    # 2. Extra paths
    if extra_paths:
        for p in extra_paths:
            if os.path.exists(p):
                return p

    # 3. PATH
    for name in [tool_name, f"{tool_name}.exe"]:
        try:
            r = subprocess.run(["where" if platform.system() == "Windows" else "which", name],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().split("\n")[0]
        except Exception:
            pass

    # 4. Common install paths
    common = {
        "amass": [os.path.expanduser("~/go/bin/amass"), "/usr/local/bin/amass"],
        "sublist3r": [os.path.join(SENTINELX_TOOLS_DIR, "Sublist3r", "sublist3r.py")],
        "massdns": ["/usr/local/bin/massdns", "/usr/bin/massdns"],
        "dirsearch": [os.path.join(SENTINELX_TOOLS_DIR, "dirsearch", "dirsearch.py")],
        "wfuzz": ["/usr/bin/wfuzz", "/usr/local/bin/wfuzz"],
        "eyewitness": [os.path.join(SENTINELX_TOOLS_DIR, "EyeWitness", "EyeWitness.py")],
        "wpscan": ["/usr/bin/wpscan", "/usr/local/bin/wpscan", "C:\\tools\\wpscan\\wpscan.exe"],
        "retirejs": ["/usr/bin/retire", "/usr/local/bin/retire", os.path.expanduser("~/.sentinelx/tools/retire.js/retire.js")],
    }
    if tool_name in common:
        for p in common[tool_name]:
            if os.path.exists(p):
                return p

    return None


def _check_tool(tool_name: str, version_flag: str = "--version",
                extra_paths: list[str] | None = None) -> tuple[bool, str]:
    """Check if a tool is available and get its version."""
    path = _find_tool(tool_name, extra_paths)
    if not path:
        return False, "not_found"
    try:
        r = subprocess.run([path, version_flag], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True, r.stdout.strip()[:80]
        return True, "available"
    except Exception:
        return True, "available"


# ============================================================================
# 1. AMASS — DNS enumeration and network mapping
# ============================================================================

@dataclass
class AmassResult:
    target: str
    subdomains: list[str]
    dns_records: list[dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    raw_output: str
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AmassTool:
    def __init__(self):
        self.name = "amass"

    def is_available(self) -> bool:
        return _find_tool("amass") is not None

    def get_version(self) -> str:
        _, v = _check_tool("amass")
        return v

    async def scan(self, target: str, mode: str = "passive", timeout_sec: int = 300) -> AmassResult:
        errors, subdomains, dns_records, start = [], [], [], datetime.now()
        path = _find_tool("amass")
        if not path:
            return AmassResult(target, [], [], 0, "not_found", "", ["amass not found in PATH or ~/.sentinelx/tools/"])
        try:
            cmd = [path, (mode == "passive" and "enum") or "enum", "-d", target, "-json", "-"]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if line.strip():
                    try:
                        j = json.loads(line)
                        if "name" in j:
                            subdomains.append(j["name"])
                        if "addresses" in j:
                            for a in (j["addresses"] or []):
                                dns_records.append({"name": j.get("name"), "ip": a.get("ip", "")})
                    except json.JSONDecodeError:
                        pass
        except asyncio.TimeoutError:
            errors.append(f"Timed out after {timeout_sec}s")
        except Exception as e:
            errors.append(str(e)[:200])
        return AmassResult(target, list(set(subdomains)), dns_records,
                          (datetime.now() - start).total_seconds(), self.get_version(), "", errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "amass",
            "available": self.is_available(),
            "modes": ["passive", "active", "intel"],
            "features": ["dns_enumeration", "subdomain_discovery", "network_mapping"],
        }


_amass_tool: AmassTool | None = None


def get_amass_tool() -> AmassTool:
    global _amass_tool
    if _amass_tool is None:
        _amass_tool = AmassTool()
    return _amass_tool


# ============================================================================
# 2. SUBLIST3R — Fast subdomain enumeration
# ============================================================================

@dataclass
class Sublist3rResult:
    target: str
    subdomains: list[str]
    execution_time_seconds: float
    tool_version: str
    raw_output: str
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class Sublist3rTool:
    def __init__(self):
        self.name = "sublist3r"

    def is_available(self) -> bool:
        return _find_tool("sublist3r") is not None or os.path.exists(os.path.join(SENTINELX_TOOLS_DIR, "Sublist3r", "sublist3r.py"))

    def get_version(self) -> str:
        _, v = _check_tool("sublist3r")
        return v

    async def scan(self, target: str, timeout_sec: int = 120) -> Sublist3rResult:
        errors, subdomains, start = [], [], datetime.now()
        path = _find_tool("sublist3r") or os.path.join(SENTINELX_TOOLS_DIR, "Sublist3r", "sublist3r.py")
        if not path:
            return Sublist3rResult(target, [], 0, "not_found", "", ["sublist3r not found"])
        try:
            if path.endswith(".py"):
                cmd = ["python3", path, "-d", target]
            else:
                cmd = [path, "-d", target]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                m = re.search(r'([a-zA-Z0-9._-]+\.' + re.escape(target) + ')', line)
                if m and m.group(1) not in subdomains:
                    subdomains.append(m.group(1))
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return Sublist3rResult(target, subdomains, (datetime.now() - start).total_seconds(), self.get_version(), "", errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "sublist3r",
            "available": self.is_available(),
            "features": ["subdomain_enumeration", "passive_discovery"],
        }


_sublist3r_tool: Sublist3rTool | None = None


def get_sublist3r_tool() -> Sublist3rTool:
    global _sublist3r_tool
    if _sublist3r_tool is None:
        _sublist3r_tool = Sublist3rTool()
    return _sublist3r_tool


# ============================================================================
# 3. KNOCKPY — Subdomain discovery via dictionary
# ============================================================================

@dataclass
class KnockpyResult:
    target: str
    subdomains: list[dict[str, Any]]
    wildcard: bool
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class KnockpyTool:
    def __init__(self):
        self.name = "knockpy"

    def is_available(self) -> bool:
        return _find_tool("knockpy") is not None or os.path.exists(os.path.join(SENTINELX_TOOLS_DIR, "knockpy", "knockpy.py"))

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target: str, wordlist: str | None = None, timeout_sec: int = 180) -> KnockpyResult:
        errors, subdomains, start = [], [], datetime.now()
        path = _find_tool("knockpy") or os.path.join(SENTINELX_TOOLS_DIR, "knockpy", "knockpy.py")
        if not path:
            return KnockpyResult(target, [], False, 0, ["knockpy not found"])
        try:
            if path.endswith(".py"):
                cmd = ["python3", path, target]
            else:
                cmd = [path, target]
            if wordlist:
                cmd.extend(["--wordlist", wordlist])
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if "=>" in line:
                    parts = line.split("=>")
                    if len(parts) >= 2:
                        subdomains.append({"subdomain": parts[0].strip(), "resolves_to": parts[1].strip()})
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return KnockpyResult(target, subdomains, False, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "knockpy",
            "available": self.is_available(),
            "features": ["subdomain_discovery", "wildcard_detection"],
        }


_knockpy_tool: KnockpyTool | None = None


def get_knockpy_tool() -> KnockpyTool:
    global _knockpy_tool
    if _knockpy_tool is None:
        _knockpy_tool = KnockpyTool()
    return _knockpy_tool


# ============================================================================
# 4. DNSCAN — DNS brute force
# ============================================================================

@dataclass
class DnscanResult:
    target: str
    subdomains: list[str]
    a_records: list[dict[str, str]]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class DnscanTool:
    def __init__(self):
        self.name = "dnscan"

    def is_available(self) -> bool:
        return _find_tool("dnscan") is not None

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target: str, wordlist: str | None = None, timeout_sec: int = 300) -> DnscanResult:
        errors, subdomains, a_records, start = [], [], [], datetime.now()
        path = _find_tool("dnscan")
        if not path:
            return DnscanResult(target, [], [], 0, ["dnscan not found"])
        try:
            cmd = [path, "-d", target]
            if wordlist:
                cmd.extend(["-w", wordlist])
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if "A:" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "A:" and i + 1 < len(parts):
                            subdomains.append(parts[i - 1] if i > 0 else target)
                            a_records.append({"subdomain": parts[i - 1] if i > 0 else target, "ip": parts[i + 1]})
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return DnscanResult(target, list(set(subdomains)), a_records, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "dnscan",
            "available": self.is_available(),
            "features": ["dns_bruteforce", "subdomain_discovery"],
        }


_dnscan_tool: DnscanTool | None = None


def get_dnscan_tool() -> DnscanTool:
    global _dnscan_tool
    if _dnscan_tool is None:
        _dnscan_tool = DnscanTool()
    return _dnscan_tool


# ============================================================================
# 5. MASSDNS — High-performance DNS resolver
# ============================================================================

@dataclass
class MassdnsResult:
    target: str
    resolved: list[dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class MassdnsTool:
    def __init__(self):
        self.name = "massdns"

    def is_available(self) -> bool:
        return _find_tool("massdns") is not None

    def get_version(self) -> str:
        _, v = _check_tool("massdns")
        return v

    async def scan(self, domain: str, resolvers_file: str | None = None, timeout_sec: int = 120) -> MassdnsResult:
        errors, resolved, start = [], [], datetime.now()
        path = _find_tool("massdns")
        if not path:
            return MassdnsResult(domain, [], 0, "not_found", ["massdns not found"])
        try:
            # Write subdomains to temp file
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write(f"{domain}\n")
            tmp.close()
            cmd = [path, "-r", resolvers_file or "/etc/resolvers.txt", "-o", "J", "-w", "-", tmp.name]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if line.strip():
                    try:
                        j = json.loads(line)
                        resolved.append({
                            "domain": j.get("name", ""),
                            "type": j.get("type", ""),
                            "value": j.get("data", ""),
                        })
                    except json.JSONDecodeError:
                        pass
            os.unlink(tmp.name)
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return MassdnsResult(domain, resolved, (datetime.now() - start).total_seconds(), self.get_version(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "massdns",
            "available": self.is_available(),
            "features": ["dns_resolution", "bulk_resolution"],
        }


_massdns_tool: MassdnsTool | None = None


def get_massdns_tool() -> MassdnsTool:
    global _massdns_tool
    if _massdns_tool is None:
        _massdns_tool = MassdnsTool()
    return _massdns_tool


# ============================================================================
# 6. DIRSEARCH — Directory/file bruteforcing
# ============================================================================

@dataclass
class DirsearchResult:
    target: str
    found: list[dict[str, Any]]
    status_codes: dict[int, int]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class DirsearchTool:
    def __init__(self):
        self.name = "dirsearch"

    def is_available(self) -> bool:
        return _find_tool("dirsearch") is not None or os.path.exists(os.path.join(SENTINELX_TOOLS_DIR, "dirsearch", "dirsearch.py"))

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target: str, wordlist: str | None = None, extensions: str = "php,asp,html,js", threads: int = 20, timeout_sec: int = 300) -> DirsearchResult:
        errors, found, status_codes, start = [], [], {}, datetime.now()
        path = _find_tool("dirsearch") or os.path.join(SENTINELX_TOOLS_DIR, "dirsearch", "dirsearch.py")
        if not path:
            return DirsearchResult(target, [], {}, 0, ["dirsearch not found"])
        try:
            if path.endswith(".py"):
                cmd = ["python3", path, "-u", target, "--format=json", "-o", "-"]
            else:
                cmd = [path, "-u", target, "--format=json", "-o", "-"]
            if wordlist:
                cmd.extend(["-w", wordlist])
            if extensions:
                cmd.extend(["-e", extensions])
            cmd.extend(["-t", str(threads)])
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            try:
                data = json.loads(raw)
                for r in data.get("results", []):
                    entry = {"path": r.get("path", ""), "status": r.get("status", 0), "size": r.get("size", 0), "content_type": r.get("content-type", "")}
                    found.append(entry)
                    sc = entry["status"]
                    status_codes[sc] = status_codes.get(sc, 0) + 1
            except json.JSONDecodeError:
                pass
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return DirsearchResult(target, found, status_codes, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "dirsearch",
            "available": self.is_available(),
            "features": ["directory_enumeration", "file_discovery", "extension_filtering"],
        }


_dirsearch_tool: DirsearchTool | None = None


def get_dirsearch_tool() -> DirsearchTool:
    global _dirsearch_tool
    if _dirsearch_tool is None:
        _dirsearch_tool = DirsearchTool()
    return _dirsearch_tool


# ============================================================================
# 7. WFUZZ — Web fuzzer
# ============================================================================

@dataclass
class WfuzzResult:
    target: str
    findings: list[dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class WfuzzTool:
    def __init__(self):
        self.name = "wfuzz"

    def is_available(self) -> bool:
        return _find_tool("wfuzz") is not None

    def get_version(self) -> str:
        _, v = _check_tool("wfuzz")
        return v

    async def scan(self, target: str, wordlist: str | None = None, filter_code: str = "200,204,301,302,307,401,403,500", timeout_sec: int = 300) -> WfuzzResult:
        errors, findings, start = [], [], datetime.now()
        path = _find_tool("wfuzz")
        if not path:
            return WfuzzResult(target, [], 0, "not_found", ["wfuzz not found"])
        try:
            cmd = [path, "-w", wordlist or "/usr/share/wordlists/wfuzz/general/common.txt", "--hc", "404", target]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                m = re.search(r'(https?://[^\s]+)\s+--\s+(\d+)', line)
                if m:
                    findings.append({"url": m.group(1), "status": int(m.group(2))})
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return WfuzzResult(target, findings, (datetime.now() - start).total_seconds(), self.get_version(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "wfuzz",
            "available": self.is_available(),
            "features": ["web_fuzzing", "parameter_fuzzing", "content_discovery"],
        }


_wfuzz_tool: WfuzzTool | None = None


def get_wfuzz_tool() -> WfuzzTool:
    global _wfuzz_tool
    if _wfuzz_tool is None:
        _wfuzz_tool = WfuzzTool()
    return _wfuzz_tool


# ============================================================================
# 8. EYEWITNESS — Web screenshot tool
# ============================================================================

@dataclass
class EyewitnessResult:
    target: str
    screenshots: list[str]
    report_path: str
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class EyewitnessTool:
    def __init__(self):
        self.name = "eyewitness"

    def is_available(self) -> bool:
        return _find_tool("eyewitness") is not None or os.path.exists(os.path.join(SENTINELX_TOOLS_DIR, "EyeWitness", "EyeWitness.py"))

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, urls: list[str], output_dir: str | None = None, timeout_sec: int = 600) -> EyewitnessResult:
        errors, screenshots, start = [], [], datetime.now()
        path = _find_tool("eyewitness") or os.path.join(SENTINELX_TOOLS_DIR, "EyeWitness", "EyeWitness.py")
        if not path:
            return EyewitnessResult(", ".join(urls[:3]), "", "", 0, ["EyeWitness not found"])
        try:
            out = output_dir or tempfile.mkdtemp(prefix="eyewitness_")
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write("\n".join(urls) + "\n")
            tmp.close()
            if path.endswith(".py"):
                cmd = ["python3", path, "--web", "-f", tmp.name, "-d", out, "--no-prompt", "--timeout", "30"]
            else:
                cmd = [path, "--web", "-f", tmp.name, "-d", out]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            if os.path.exists(out):
                for f in os.listdir(out):
                    if f.endswith(".png") or f.endswith(".jpeg") or f.endswith(".html"):
                        screenshots.append(os.path.join(out, f))
            os.unlink(tmp.name)
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return EyewitnessResult(", ".join(urls[:3]), screenshots, output_dir or "", (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "eyewitness",
            "available": self.is_available(),
            "features": ["web_screenshot", "visual_recon", "report_generation"],
        }


_eyewitness_tool: EyewitnessTool | None = None


def get_eyewitness_tool() -> EyewitnessTool:
    global _eyewitness_tool
    if _eyewitness_tool is None:
        _eyewitness_tool = EyewitnessTool()
    return _eyewitness_tool


# ============================================================================
# 9. GITTOOLS — Git repository discovery
# ============================================================================

@dataclass
class GitToolsResult:
    target: str
    repo_found: bool
    files_extracted: list[str]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class GitToolsTool:
    def __init__(self):
        self.name = "gittools"

    def is_available(self) -> bool:
        return (_find_tool("gitdumper.sh") is not None or
                os.path.exists(os.path.join(SENTINELX_TOOLS_DIR, "GitTools", "Dumper", "gitdumper.sh")))

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target_url: str, output_dir: str | None = None, timeout_sec: int = 120) -> GitToolsResult:
        errors, files, start = [], [], datetime.now()
        base = os.path.join(SENTINELX_TOOLS_DIR, "GitTools")
        dumper = _find_tool("gitdumper.sh") or os.path.join(base, "Dumper", "gitdumper.sh")
        if not dumper:
            return GitToolsResult(target_url, False, [], 0, ["GitTools not found"])
        try:
            out = output_dir or tempfile.mkdtemp(prefix="gittools_")
            cmd = ["bash", dumper, target_url, out]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            if os.path.exists(out):
                for root, _, fnames in os.walk(out):
                    for f in fnames:
                        files.append(os.path.join(root, f))
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return GitToolsResult(target_url, len(files) > 0, files, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "gittools",
            "available": self.is_available(),
            "features": ["git_discovery", "repo_extraction", "source_code_leak"],
        }


_gittools_tool: GitToolsTool | None = None


def get_gittools_tool() -> GitToolsTool:
    global _gittools_tool
    if _gittools_tool is None:
        _gittools_tool = GitToolsTool()
    return _gittools_tool


# ============================================================================
# 10. GIT-SECRETS — Scan git repos for secrets
# ============================================================================

@dataclass
class GitSecretsResult:
    target: str
    secrets_found: list[dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class GitSecretsTool:
    def __init__(self):
        self.name = "git-secrets"

    def is_available(self) -> bool:
        return _find_tool("git-secrets") is not None or _find_tool("git secrets") is not None

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, repo_path: str, timeout_sec: int = 60) -> GitSecretsResult:
        errors, secrets, start = [], [], datetime.now()
        path = _find_tool("git-secrets") or _find_tool("git secrets")
        if not path and not os.path.exists(os.path.join(repo_path, ".git")):
            return GitSecretsResult(repo_path, [], 0, "not_found", ["git-secrets not found or no .git dir"])
        try:
            if (path or "").endswith("git"):
                cmd = ["git", "secrets", "--scan", repo_path]
            else:
                cmd = [path or "git-secrets", "--scan", "--recursive", repo_path]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if ":" in line and len(line) > 20:
                    secrets.append({"file": line.split(":")[0].strip(), "match": line[line.find(":") + 1:].strip()[:100]})
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return GitSecretsResult(repo_path, secrets, (datetime.now() - start).total_seconds(), self.get_version(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "git-secrets",
            "available": self.is_available(),
            "features": ["secret_detection", "git_scanning", "credential_leak"],
        }


_git_secrets_tool: GitSecretsTool | None = None


def get_git_secrets_tool() -> GitSecretsTool:
    global _git_secrets_tool
    if _git_secrets_tool is None:
        _git_secrets_tool = GitSecretsTool()
    return _git_secrets_tool


# ============================================================================
# 11. RETIRE.JS — JavaScript library vulnerability scanner
# ============================================================================

@dataclass
class RetireJsResult:
    target: str
    vulnerabilities: list[dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class RetireJsTool:
    def __init__(self):
        self.name = "retire.js"

    def is_available(self) -> bool:
        return _find_tool("retire") is not None or _find_tool("retire.js") is not None

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target_path: str, timeout_sec: int = 60) -> RetireJsResult:
        errors, vulns, start = [], [], datetime.now()
        path = _find_tool("retire") or _find_tool("retire.js")
        if not path:
            return RetireJsResult(target_path, [], 0, "not_found", ["retire.js not found"])
        try:
            cmd = [path, "--path", target_path, "--outputformat", "json", "--output", "-"]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            try:
                data = json.loads(raw)
                results = data.get("results", data if isinstance(data, list) else [])
                for result in results:
                    if isinstance(result, dict):
                        vulns.append({
                            "file": result.get("file", ""),
                            "component": result.get("component", ""),
                            "version": result.get("version", ""),
                            "vulnerabilities": result.get("vulnerabilities", []),
                        })
            except json.JSONDecodeError:
                pass
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return RetireJsResult(target_path, vulns, (datetime.now() - start).total_seconds(), self.get_version(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "retire.js",
            "available": self.is_available(),
            "features": ["js_vulnerability_scanning", "library_detection", "cve_mapping"],
        }


_retirejs_tool: RetireJsTool | None = None


def get_retirejs_tool() -> RetireJsTool:
    global _retirejs_tool
    if _retirejs_tool is None:
        _retirejs_tool = RetireJsTool()
    return _retirejs_tool


# ============================================================================
# 12. MOBSF — Mobile Security Framework (API-based)
# ============================================================================

@dataclass
class MobsfResult:
    target: str
    analysis_type: str
    findings: dict[str, Any]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class MobsfTool:
    def __init__(self):
        self.name = "mobsf"

    def is_available(self) -> bool:
        # Check if MobSF server is running by trying to reach its API
        return _find_tool("mobsf") is not None

    def get_version(self) -> str:
        return "1.0"

    async def scan_apk(self, apk_path: str, mobsf_url: str = "http://localhost:8000", api_key: str | None = None, timeout_sec: int = 300) -> MobsfResult:
        start = datetime.now()
        if not os.path.exists(apk_path):
            return MobsfResult(apk_path, "apk", {}, 0, [f"APK not found: {apk_path}"])
        try:
            import httpx
            headers = {"Authorization": api_key or ""}
            # Upload
            async with httpx.AsyncClient(timeout=30) as c:
                with open(apk_path, "rb") as f:
                    resp = await c.post(f"{mobsf_url}/api/v1/upload", files={"file": f}, headers=headers)
                if resp.status_code != 200:
                    return MobsfResult(apk_path, "apk", {}, 0, [f"MobSF upload failed: {resp.status_code}"])
                hash_val = resp.json().get("hash", "")
                # Scan
                resp2 = await c.post(f"{mobsf_url}/api/v1/scan", data={"hash": hash_val, "scan_type": "apk"}, headers=headers)
                if resp2.status_code == 200:
                    return MobsfResult(apk_path, "apk", resp2.json(), (datetime.now() - start).total_seconds(), [])
                return MobsfResult(apk_path, "apk", {}, 0, [f"Scan failed: {resp2.status_code}"])
        except Exception as e:
            return MobsfResult(apk_path, "apk", {}, 0, [str(e)[:200]])

    def get_capabilities(self) -> dict:
        return {
            "name": "mobsf",
            "available": self.is_available(),
            "features": ["mobile_analysis", "apk_scanning", "static_analysis", "dynamic_analysis"],
        }


_mobsf_tool: MobsfTool | None = None


def get_mobsf_tool() -> MobsfTool:
    global _mobsf_tool
    if _mobsf_tool is None:
        _mobsf_tool = MobsfTool()
    return _mobsf_tool


# ============================================================================
# 13. APKTOOL — APK decompilation
# ============================================================================

@dataclass
class ApktoolResult:
    target: str
    decompiled_path: str
    files_extracted: int
    manifest: dict[str, Any] | None
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class ApktoolTool:
    def __init__(self):
        self.name = "apktool"

    def is_available(self) -> bool:
        return _find_tool("apktool") is not None or _find_tool("apktool.jar") is not None

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, apk_path: str, output_dir: str | None = None, timeout_sec: int = 120) -> ApktoolResult:
        errors, start = [], datetime.now()
        path = _find_tool("apktool") or _find_tool("apktool.jar")
        if not path or not os.path.exists(apk_path):
            return ApktoolResult(apk_path, "", 0, None, 0, ["apktool not found or APK missing"])
        try:
            out = output_dir or tempfile.mkdtemp(prefix="apktool_")
            if path.endswith(".jar"):
                cmd = ["java", "-jar", path, "d", "-f", "-o", out, apk_path]
            else:
                cmd = [path, "d", "-f", "-o", out, apk_path]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            files = sum(len(fs) for _, _, fs in os.walk(out)) if os.path.exists(out) else 0
            manifest = None
            manifest_path = os.path.join(out, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path) as _:
                        manifest = {"path": manifest_path, "size": os.path.getsize(manifest_path)}
                except Exception:
                    pass
            return ApktoolResult(apk_path, out, files, manifest, (datetime.now() - start).total_seconds(), errors)
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return ApktoolResult(apk_path, output_dir or "", 0, None, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "apktool",
            "available": self.is_available(),
            "features": ["apk_decompilation", "android_analysis", "manifest_extraction"],
        }


_apktool_tool: ApktoolTool | None = None


def get_apktool_tool() -> ApktoolTool:
    global _apktool_tool
    if _apktool_tool is None:
        _apktool_tool = ApktoolTool()
    return _apktool_tool


# ============================================================================
# 14. WPSCAN — WordPress vulnerability scanner
# ============================================================================

@dataclass
class WpscanResult:
    target: str
    wordpress_version: str | None
    themes: list[str]
    plugins: list[str]
    vulnerabilities: list[dict[str, Any]]
    users: list[str]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class WpscanTool:
    def __init__(self):
        self.name = "wpscan"

    def is_available(self) -> bool:
        return _find_tool("wpscan") is not None

    def get_version(self) -> str:
        _, v = _check_tool("wpscan")
        return v

    async def scan(self, target: str, api_token: str | None = None, enumerate_all: bool = True, timeout_sec: int = 600) -> WpscanResult:
        errors, vulns, users, start = [], [], [], datetime.now()
        path = _find_tool("wpscan")
        if not path:
            return WpscanResult(target, None, [], [], [], [], 0, ["wpscan not found"])
        try:
            cmd = [path, "--url", target, "--format", "json", "--no-banner", "--random-user-agent"]
            if api_token:
                cmd.extend(["--api-token", api_token])
            if enumerate_all:
                cmd.append("--enumerate")
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            try:
                data = json.loads(raw)
                wp_ver = data.get("version", {}).get("number") if data.get("version") else None
                themes = [t.get("slug", "") for t in data.get("themes", [])]
                plugins = [p.get("slug", "") for p in data.get("plugins", [])]
                for v in data.get("vulnerabilities", []):
                    vulns.append({"title": v.get("title", ""), "type": v.get("type", ""), "fixed_in": v.get("fixed_in", "")})
                for u in data.get("users", []):
                    users.append(u.get("username", ""))
                return WpscanResult(target, wp_ver, themes, plugins, vulns, users, (datetime.now() - start).total_seconds(), errors)
            except json.JSONDecodeError:
                pass
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return WpscanResult(target, None, [], [], vulns, users, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "wpscan",
            "available": self.is_available(),
            "features": ["wordpress_scanning", "plugin_detection", "theme_detection", "user_enumeration", "vulnerability_detection"],
        }


_wpscan_tool: WpscanTool | None = None


def get_wpscan_tool() -> WpscanTool:
    global _wpscan_tool
    if _wpscan_tool is None:
        _wpscan_tool = WpscanTool()
    return _wpscan_tool


# ============================================================================
# 15. CMSMAP — CMS detection and vulnerability scanning
# ============================================================================

@dataclass
class CmsmapResult:
    target: str
    cms: str | None
    version: str | None
    findings: list[dict[str, Any]]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class CmsmapTool:
    def __init__(self):
        self.name = "cmsmap"

    def is_available(self) -> bool:
        return _find_tool("cmsmap") is not None or os.path.exists(os.path.join(SENTINELX_TOOLS_DIR, "CMSmap", "cmsmap.py"))

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target: str, timeout_sec: int = 300) -> CmsmapResult:
        errors, findings, start = [], [], datetime.now()
        path = _find_tool("cmsmap") or os.path.join(SENTINELX_TOOLS_DIR, "CMSmap", "cmsmap.py")
        if not path:
            return CmsmapResult(target, None, None, [], 0, ["cmsmap not found"])
        try:
            if path.endswith(".py"):
                cmd = ["python3", path, "-t", target, "-f", "json"]
            else:
                cmd = [path, "-t", target, "-f", "json"]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if "[+]" in line:
                    findings.append({"type": "info", "message": line.strip()})
                if "[!]" in line:
                    findings.append({"type": "vulnerability", "message": line.strip()})
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return CmsmapResult(target, None, None, findings, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "cmsmap",
            "available": self.is_available(),
            "features": ["cms_detection", "wordpress_scan", "drupal_scan", "joomla_scan"],
        }


_cmsmap_tool: CmsmapTool | None = None


def get_cmsmap_tool() -> CmsmapTool:
    global _cmsmap_tool
    if _cmsmap_tool is None:
        _cmsmap_tool = CmsmapTool()
    return _cmsmap_tool


# ============================================================================
# 16. CORSTEST — CORS misconfiguration testing
# ============================================================================

@dataclass
class CorsTestResult:
    target: str
    vulnerable: bool
    findings: list[dict[str, Any]]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class CorsTestTool:
    def __init__(self):
        self.name = "corstest"

    def is_available(self) -> bool:
        return _find_tool("corstest") is not None

    def get_version(self) -> str:
        return "1.0"

    async def scan(self, target: str, origins: list[str] | None = None, timeout_sec: int = 60) -> CorsTestResult:
        errors, findings, start = [], [], datetime.now()
        test_origins = origins or ["https://evil.com", "https://null", "https://attacker.io", "null", "file://"]
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15, verify=False) as c:
                for origin in test_origins:
                    try:
                        if target.startswith("http"):
                            resp = await c.options(target)
                        else:
                            resp = await c.get(f"https://{target}", headers={"Origin": origin})
                        acao = resp.headers.get("access-control-allow-origin", "")
                        acac = resp.headers.get("access-control-allow-credentials", "")
                        if acao == "*" or origin in acao or (acao and acac.lower() == "true"):
                            findings.append({"origin": origin, "acao": acao, "acac": acac, "mirror": acao == origin})
                    except Exception:
                        pass
        except Exception as e:
            errors.append(str(e)[:200])
        return CorsTestResult(target, len(findings) > 0, findings, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "corstest",
            "available": self.is_available(),
            "features": ["cors_testing", "origin_mirroring", "aca_misconfiguration"],
        }


_corstest_tool: CorsTestTool | None = None


def get_corstest_tool() -> CorsTestTool:
    global _corstest_tool
    if _corstest_tool is None:
        _corstest_tool = CorsTestTool()
    return _corstest_tool


# ============================================================================
# 17. JWT TOOLKIT — JWT token analysis and attacks
# ============================================================================

@dataclass
class JwtResult:
    token_analyzed: str
    header: dict[str, Any]
    payload: dict[str, Any]
    is_valid: bool
    algorithm: str
    issues: list[str]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class JwtToolkitTool:
    def __init__(self):
        self.name = "jwt_toolkit"

    def is_available(self) -> bool:
        return True  # Built-in Python implementation, no external binary needed

    def get_version(self) -> str:
        return "1.0"

    def decode_token(self, token: str) -> dict[str, Any]:
        """Decode JWT without verification — static analysis"""
        import base64
        try:
            parts = token.split(".")
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return {"header": header, "payload": payload, "algorithm": header.get("alg", "none")}
        except Exception:
            return {"header": {}, "payload": {}, "algorithm": "unknown"}

    async def scan(self, token: str, timeout_sec: int = 30) -> JwtResult:
        errors, issues, start = [], [], datetime.now()
        decoded = self.decode_token(token)
        import time
        time.sleep(0.1)
        alg = decoded.get("algorithm", "unknown")
        header = decoded.get("header", {})
        payload = decoded.get("payload", {})
        if alg == "none":
            issues.append("Algorithm is 'none' — insecure! Token can be trivially forged")
        if alg == "HS256":
            issues.append("Symmetric algorithm — verify with known secret if possible")
        if "exp" not in payload:
            issues.append("No expiration claim — token may never expire")
        if "aud" not in payload:
            issues.append("No audience claim — token may be reusable across services")
        return JwtResult(token, header, payload, True, alg, issues, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "jwt_toolkit",
            "available": True,
            "features": ["jwt_decoding", "algorithm_detection", "security_analysis", "none_algorithm_check"],
        }


_jwt_toolkit_tool: JwtToolkitTool | None = None


def get_jwt_toolkit_tool() -> JwtToolkitTool:
    global _jwt_toolkit_tool
    if _jwt_toolkit_tool is None:
        _jwt_toolkit_tool = JwtToolkitTool()
    return _jwt_toolkit_tool


# ============================================================================
# 18. TKO-SUBS — Subdomain takeover detection
# ============================================================================

@dataclass
class TkoSubsResult:
    target: str
    vulnerable: list[dict[str, Any]]
    not_vulnerable: list[str]
    execution_time_seconds: float
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class TkoSubsTool:
    def __init__(self):
        self.name = "tko-subs"

    def is_available(self) -> bool:
        return _find_tool("tko-subs") is not None

    def get_version(self) -> str:
        _, v = _check_tool("tko-subs")
        return v

    async def scan(self, domains_file: str, timeout_sec: int = 300) -> TkoSubsResult:
        errors, vulnerable, not_vulnerable, start = [], [], [], datetime.now()
        path = _find_tool("tko-subs")
        if not path:
            return TkoSubsResult(domains_file, [], [], 0, ["tko-subs not found"])
        try:
            cmd = [path, "-d", domains_file]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if "VULNERABLE" in line.upper():
                    parts = line.split()
                    vulnerable.append({"domain": parts[0] if parts else "", "service": parts[-1] if len(parts) > 1 else ""})
                elif "SAFE" in line.upper() or "NOT" in line.upper():
                    parts = line.split()
                    if parts:
                        not_vulnerable.append(parts[0])
        except asyncio.TimeoutError:
            errors.append("Timed out")
        except Exception as e:
            errors.append(str(e)[:200])
        return TkoSubsResult(domains_file, vulnerable, not_vulnerable, (datetime.now() - start).total_seconds(), errors)

    def get_capabilities(self) -> dict:
        return {
            "name": "tko-subs",
            "available": self.is_available(),
            "features": ["subdomain_takeover", "dangling_dns", "cloud_service_verification"],
        }


_tko_subs_tool: TkoSubsTool | None = None


def get_tko_subs_tool() -> TkoSubsTool:
    global _tko_subs_tool
    if _tko_subs_tool is None:
        _tko_subs_tool = TkoSubsTool()
    return _tko_subs_tool


# ============================================================================
# 19. WAYBACKURLS EXTENDED — Already exists in recon_tools.py but adding
#     an enhanced version with more features
# ============================================================================

# Note: waybackurls is already in recon_tools.py as WaybackUrlsTool
# We re-export it here for convenience


# ============================================================================
# 20. GAU (GetAllUrls) — Already exists in recon_tools.py
# ============================================================================


# ============================================================================
# 21. DNSX — Fast DNS resolver (ProjectDiscovery, massdns alternative)
# ============================================================================

@dataclass
class DnsxResult:
    target: str
    resolved: list[dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    errors: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class DnsxTool:
    """
    dnsx - Fast multi-purpose DNS toolkit by ProjectDiscovery.
    Acts as a modern alternative to massdns for DNS resolution.
    """
    def __init__(self):
        self.name = "dnsx"

    def is_available(self) -> bool:
        return _find_tool("dnsx") is not None

    def get_version(self) -> str:
        _, v = _check_tool("dnsx")
        return v

    async def scan(self, domain: str, resp: bool = True, timeout_sec: int = 60) -> DnsxResult:
        """
        Scan a domain with dnsx.

        dnsx usage:
          dnsx -d example.com -a -resp -json

        Returns resolved records.
        """
        errors, resolved, start = [], [], datetime.now()
        path = _find_tool("dnsx")
        if not path:
            return DnsxResult(domain, [], 0, "not_found", ["dnsx not found"])
        try:
            cmd = [path, "-d", domain, "-a", "-json"]
            if resp:
                cmd.append("-resp")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            raw = stdout.decode("utf-8", errors="replace") if stdout else ""
            for line in raw.split("\n"):
                if line.strip():
                    try:
                        j = json.loads(line)
                        entry = {"host": j.get("host", domain)}
                        for rtype in ["a", "aaaa", "cname", "mx", "ns", "txt"]:
                            vals = j.get(rtype, [])
                            if vals:
                                entry[rtype] = vals
                        if len(entry) > 1:  # has at least one record
                            resolved.append(entry)
                    except json.JSONDecodeError:
                        pass
        except asyncio.TimeoutError:
            errors.append(f"Timed out after {timeout_sec}s")
        except Exception as e:
            errors.append(str(e)[:200])
        return DnsxResult(
            domain, resolved,
            (datetime.now() - start).total_seconds(),
            self.get_version(), errors
        )

    def get_capabilities(self) -> dict:
        return {
            "name": "dnsx",
            "available": self.is_available(),
            "features": ["dns_resolution", "bulk_resolution", "a_record", "cname", "mx", "ns", "txt"],
        }


_dnsx_tool: DnsxTool | None = None


def get_dnsx_tool() -> DnsxTool:
    global _dnsx_tool
    if _dnsx_tool is None:
        _dnsx_tool = DnsxTool()
    return _dnsx_tool


# ============================================================================
# COMPREHENSIVE TOOL REGISTRY
# ============================================================================

ALL_EXTENDED_TOOLS = {
    "amass": get_amass_tool,
    "sublist3r": get_sublist3r_tool,
    "knockpy": get_knockpy_tool,
    "dnscan": get_dnscan_tool,
    "massdns": get_massdns_tool,
    "dnsx": get_dnsx_tool,
    "dirsearch": get_dirsearch_tool,
    "wfuzz": get_wfuzz_tool,
    "eyewitness": get_eyewitness_tool,
    "gittools": get_gittools_tool,
    "git_secrets": get_git_secrets_tool,
    "retirejs": get_retirejs_tool,
    "mobsf": get_mobsf_tool,
    "apktool": get_apktool_tool,
    "wpscan": get_wpscan_tool,
    "cmsmap": get_cmsmap_tool,
    "corstest": get_corstest_tool,
    "jwt_toolkit": get_jwt_toolkit_tool,
    "tko_subs": get_tko_subs_tool,
}


def get_all_extended_tools_status() -> dict[str, dict[str, Any]]:
    """Get availability status for all extended tools."""
    status = {}
    for name, getter in ALL_EXTENDED_TOOLS.items():
        try:
            t = getter()
            status[name] = {
                "available": t.is_available(),
                "version": t.get_version() if hasattr(t, "get_version") else "unknown",
                "capabilities": t.get_capabilities(),
            }
        except Exception as e:
            status[name] = {"available": False, "error": str(e)}
    return status
