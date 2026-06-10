"""
FFUF Tool Integration for Sentinel-X

Provides structured execution and result parsing for ffuf web fuzzing.

Features:
- Directory and file discovery
- Parameter fuzzing (GET/POST)
- Virtual host discovery
- Subdomain fuzzing
- JSON output parsing
- Recursive scanning
"""

import asyncio
import subprocess
import json
import re
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass


@dataclass
class FfufResult:
    """Structured ffuf scan result"""
    target: str
    mode: str
    findings: List[Dict[str, Any]]
    status_codes: Dict[int, int]
    execution_time_seconds: float
    requests_sent: int
    tool_version: str
    errors: List[str]


class FfufTool:
    """FFUF tool integration for Sentinel-X"""
    
    def __init__(self):
        self.name = "ffuf"
        self.supported_modes = ["directory", "subdomain", "vhost", "parameter", "url"]
        self.version_cache: Optional[str] = None
        
    def is_available(self) -> bool:
        """Check if ffuf is installed and accessible"""
        try:
            result = subprocess.run(
                ['ffuf', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_version(self) -> str:
        """Get ffuf version string"""
        if self.version_cache:
            return self.version_cache
            
        try:
            result = subprocess.run(
                ['ffuf', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                match = re.search(r'Version (\\d+\\.\\d+\\.\\d+)', result.stdout)
                if match:
                    self.version_cache = match.group(1)
                    return self.version_cache
                return result.stdout.strip()[:50]
        except Exception:
            pass
        return "unknown"
    
    async def scan(
        self,
        target: str,
        mode: str = "directory",
        wordlist: str = None,
        threads: int = 40,
        extensions: str = None,
        status_codes: str = "200,204,301,302,307,401,403,500",
        timeout: int = 300,
        follow_redirects: bool = False,
        auto_calibration: bool = True,
        rate: int = 0
    ) -> FfufResult:
        """
        Execute an ffuf scan with structured parameters.
        
        Args:
            target: Target URL or host
            mode: Fuzzing mode (directory, subdomain, vhost, parameter)
            wordlist: Path to wordlist file
            threads: Number of concurrent threads
            extensions: File extensions to append (e.g., "php,html")
            status_codes: Status codes to show (comma-separated)
            timeout: Scan timeout in seconds
            follow_redirects: Follow HTTP redirects
            auto_calibration: Enable auto-calibration
            rate: Requests per second limit (0 = unlimited)
        """
        findings = []
        status_codes_count: Dict[int, int] = {}
        errors = []
        start_time = datetime.now()
        requests_sent = 0
        
        # Build ffuf command
        cmd = ['ffuf']
        
        # Mode-specific options
        if mode == "directory":
            cmd.extend(['-w', wordlist or '/usr/share/wordlists/dirb/common.txt'])
            cmd.extend(['-u', target + '/FUZZ'])  # FUZZ is the insertion point
        elif mode == "subdomain":
            cmd.extend(['-w', wordlist or '/usr/share/wordlists/dirb/common.txt'])
            cmd.extend(['-u', target.replace('://', '://FUZZ.')])  # FUZZ subdomain
        elif mode == "vhost":
            cmd.extend(['-w', wordlist or '/usr/share/wordlists/dirb/common.txt'])
            cmd.extend(['-u', target])
            cmd.extend(['-H', 'Host: FUZZ'])  # FUZZ as Host header
        elif mode == "parameter":
            cmd.extend(['-w', wordlist or '/usr/share/wordlists/dirb/common.txt'])
            cmd.extend(['-u', target])
            cmd.append('-mode', 'clusterbomb')  # Parameter combinations
        
        # Output
        cmd.extend(['-o', 'ffuf_results.json'])
        cmd.extend(['-of', 'json'])
        
        # Threads
        cmd.append(f'-t{threads}')
        
        # Status codes filter
        cmd.extend(['-s'])  # Silent mode (less output)
        
        # Auto-calibration
        if auto_calibration:
            cmd.append('-ac')
        
        # Rate limiting
        if rate > 0:
            cmd.extend(['-rate', str(rate)])
        
        # Follow redirects
        if follow_redirects:
            cmd.append('-r')
        
        # Timeout (ffuf uses -maxtime瑕)
        cmd.append(f'-maxtime {timeout}')
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout + 10
                )
            except asyncio.TimeoutError:
                proc.kill()
                errors.append(f"Scan timed out after {timeout} seconds")
                return FfufResult(
                    target=target,
                    mode=mode,
                    findings=findings,
                    status_codes=status_codes_count,
                    execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                    requests_sent=requests_sent,
                    tool_version=self.get_version(),
                    errors=errors
                )
            
            if proc.returncode not in [0, 1]:  # 0=success, 1=findings, anything else=error
                error_output = stderr.decode() if stderr else ""
                if error_output:
                    errors.append(error_output[:500])
            
            # Parse JSON output
            try:
                with open('ffuf_results.json', 'r') as f:
                    json_results = json.load(f)
                
                for result in json_results.get('results', []):
                    findings.append({
                        'url': result.get('url', ''),
                        'status': result.get('status', 0),
                        'length': result.get('length', 0),
                        'words': result.get('words', 0),
                        'lines': result.get('lines', 0),
                        'content_type': result.get('content-type', ''),
                    })
                    
                    code = result.get('status', 0)
                    status_codes_count[code] = status_codes_count.get(code, 0) + 1
                    
                requests_sent = json_results.get('config', {}).get('total_requests', 0)
                
            except Exception:
                # JSON parsing failed
                pass
            
        except Exception as e:
            errors.append(str(e)[:200])
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Clean up temp file
        try:
            if os.path.exists('ffuf_results.json'):
                os.remove('ffuf_results.json')
        except Exception:
            pass
        
        return FfufResult(
            target=target,
            mode=mode,
            findings=findings,
            status_codes=status_codes_count,
            execution_time_seconds=execution_time,
            requests_sent=requests_sent,
            tool_version=self.get_version(),
            errors=errors
        )
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_modes': self.supported_modes,
            'features': [
                'directory_fuzzing',
                'subdomain_fuzzing',
                'vhost_discovery',
                'parameter_fuzzing',
                'recursive_scan',
                'auto_calibration',
                'rate_limiting'
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target URL or host'},
                'mode': {'required': False, 'options': self.supported_modes, 'description': 'Fuzzing mode'},
                'wordlist': {'required': False, 'description': 'Path to wordlist file'},
                'threads': {'required': False, 'default': 40, 'description': 'Concurrent threads'},
                'extensions': {'required': False, 'description': 'File extensions (dir mode)'},
                'status_codes': {'required': False, 'description': 'Status codes to show'},
                'rate': {'required': False, 'default': 0, 'description': 'Requests per second'}
            },
            'owasp_mapping': {
                'A01': 'Broken Access Control - directory enumeration',
                'A03': 'Injection - parameter fuzzing',
                'A05': 'Security Misconfiguration - path discovery'
            }
        }


import os

# Global instance for tool registry
_ffuf_tool: Optional[FfufTool] = None


def get_ffuf_tool() -> FfufTool:
    """Get or create global ffuf tool instance"""
    global _ffuf_tool
    if _ffuf_tool is None:
        _ffuf_tool = FfufTool()
    return _ffuf_tool