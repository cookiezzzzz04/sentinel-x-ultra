"""
Gobuster Tool Integration for Sentinel-X

Provides structured execution and result parsing for gobuster directory/DNS fuzzing.

Modes:
- dir: Directory and file enumeration
- dns: DNS subdomain discovery  
- vhost: Virtual host discovery
"""

import asyncio
import subprocess
import re
import os
import platform
import os.path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass


def _convert_msys_path(path: str) -> str:
    r"""Convert MSYS2/Unix-style path to Windows path if needed.
    
    In MSYS2 environments, paths like /tmp/wordlist.txt need to be
    converted to Windows paths (C:\Users\...) for Windows-native subprocesses.
    """
    if not path:
        return path
    
    # Check if it's an MSYS2-style path (starts with / and contains /tmp, /home, etc.)
    if path.startswith('/'):
        # Try to detect if this is an MSYS2 path that needs conversion
        try:
            # Use subprocess to get the Windows path
            result = subprocess.run(
                ['cygpath', '-w', path],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        # Manual conversion for common patterns
        if path.startswith('/tmp/'):
            # /tmp maps to the user's temp directory
            temp_dir = os.environ.get('TEMP') or os.environ.get('TMP') or os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp')
            return os.path.join(temp_dir, path[5:])
        elif path.startswith('/home/'):
            # /home/user maps to the user's profile directory
            home = os.environ.get('HOME') or os.environ.get('USERPROFILE') or ''
            if home:
                # Extract the user part and rest of path
                parts = path[6:].split('/', 1)
                if len(parts) >= 2:
                    return os.path.join(home, parts[1])
            return path
        elif path.startswith('/c/') or path.startswith('/C/'):
            # /c/... style MSYS2 paths to C:\...
            return 'C:\\' + path[3:].replace('/', '\\')
    
    return path


@dataclass
class GobusterResult:
    """Structured gobuster scan result"""
    target: str
    mode: str
    found: List[Dict[str, Any]]
    status_codes: Dict[int, int]
    execution_time_seconds: float
    tool_version: str
    wordlist: str
    errors: List[str]


class GobusterTool:
    """Gobuster tool integration for Sentinel-X"""
    
    def __init__(self):
        self.name = "gobuster"
        self.supported_modes = ["dir", "dns", "vhost"]
        self.version_cache: Optional[str] = None
        self._path_cache: Optional[str] = None
        
    def _get_gobuster_path(self) -> Optional[str]:
        """Get path to gobuster executable, checking PATH and common Windows locations"""
        if self._path_cache:
            return self._path_cache
        
        # Try finding gobuster in PATH first
        for cmd in ['gobuster', 'gobuster.exe']:
            try:
                result = subprocess.run(
                    [cmd, '--help'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0 and 'gobuster' in result.stdout.lower():
                    self._path_cache = cmd
                    return cmd
            except Exception:
                pass
        
        # Check Windows installation paths
        import os as os_module
        # Try HOME or USERPROFILE environment variables for proper expansion
        home = os.environ.get('HOME') or os.environ.get('USERPROFILE') or os_module.path.expanduser('~')
        windows_paths = [
            os_module.path.join(home, 'go', 'bin', 'gobuster.exe'),
            os_module.path.expanduser(r'~\go\bin\gobuster.exe'),
            r'C:\Go\bin\gobuster.exe',
            r'C:\Program Files\Gobuster\gobuster.exe',
            r'C:\tools\gobuster.exe',
        ]
        for path in windows_paths:
            if os_module.path.exists(path):
                self._path_cache = path
                return path
        
        return None

    def is_available(self) -> bool:
        """Check if gobuster is installed and accessible"""
        return self._get_gobuster_path() is not None
    
    def get_version(self) -> str:
        """Get gobuster version string"""
        if self.version_cache:
            return self.version_cache
        
        gobuster_path = self._get_gobuster_path()
        if not gobuster_path:
            return "unknown"
            
        try:
            result = subprocess.run(
                [gobuster_path, '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Parse version from first line like "gobuster v3.6" or "Gobuster v3.6"
                match = re.search(r'[Gg]obuster v?(\d+\.\d+(?:\.\d+)?)', result.stdout)
                if match:
                    self.version_cache = match.group(1)
                    return self.version_cache
                # Try to find version in any line
                match = re.search(r'version\s*:?\s*(\d+\.\d+(?:\.\d+)?)', result.stdout, re.IGNORECASE)
                if match:
                    self.version_cache = match.group(1)
                    return self.version_cache
        except Exception:
            pass
        return "unknown"
    
    async def scan(
        self,
        target: str,
        mode: str = "dir",
        wordlist: str = None,
        threads: int = 10,
        extensions: str = None,
        status_codes: str = "200,204,301,302,307,401,403",
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        timeout: int = 600,
        headers: Dict[str, str] = None,
        exclude_length: int = None,
        delay_ms: int = None
    ) -> GobusterResult:
        """
        Execute a gobuster scan with structured parameters.
        
        Args:
            target: Target URL or domain
            mode: Scan mode (dir, dns, vhost)
            wordlist: Path to wordlist file (default: built-in small wordlist)
            threads: Number of concurrent threads (default: 10)
            extensions: File extensions to append (e.g., "php,html,js")
            status_codes: Comma-separated status codes to show
            user_agent: Custom User-Agent string
            timeout: Scan timeout in seconds
            headers: Custom headers as dict
            exclude_length: Exclude responses of this size
            delay_ms: Delay between requests in milliseconds
        """
        found = []
        status_codes_count: Dict[int, int] = {}
        errors = []
        start_time = datetime.now()
        
        # Build gobuster command
        gobuster_path = self._get_gobuster_path() or 'gobuster'
        cmd = [gobuster_path, mode]
        
        # Target
        if mode == 'dir':
            cmd.extend(['-u', target])
        elif mode == 'dns':
            cmd.extend(['-d', target])
        elif mode == 'vhost':
            cmd.extend(['-u', target])
        
        # Wordlist (use default if not specified)
        # Convert MSYS2 paths to Windows paths for Windows-native subprocess
        if wordlist:
            wordlist = _convert_msys_path(wordlist)
        
        if not wordlist:
            wordlist = self._get_default_wordlist()
        if not wordlist:
            errors.append("No wordlist found. Please provide a wordlist path in the request or install wordlists to a standard location.")
            return GobusterResult(
                target=target,
                mode=mode,
                found=[],
                status_codes={},
                execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                tool_version=self.get_version(),
                wordlist="",
                errors=errors
            )
        
        # Verify wordlist exists
        if not os.path.exists(wordlist):
            errors.append(f"Wordlist file not found: {wordlist}")
            return GobusterResult(
                target=target,
                mode=mode,
                found=[],
                status_codes={},
                execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                tool_version=self.get_version(),
                wordlist=wordlist,
                errors=errors
            )
        cmd.extend(['-w', wordlist])
        
        # Threads
        cmd.extend(['-t', str(threads)])
        
        # Status codes (for dir mode)
        if mode == 'dir' and status_codes:
            cmd.extend(['-s', status_codes])
        
        # User-Agent
        cmd.extend(['-H', f'User-Agent: {user_agent}'])
        
        # Custom headers
        if headers:
            for key, value in headers.items():
                cmd.extend(['-H', f'{key}: {value}'])
        
        # Extensions (for dir mode)
        if extensions and mode == 'dir':
            cmd.extend(['-x', extensions])
        
        # Skip SSL verification (for testing)
        if mode == 'dir':
            cmd.append('-k')
        
        # Follow redirects
        if mode == 'dir':
            cmd.append('-f')
        
        # Exclude length
        if exclude_length:
            cmd.extend(['--exclude-length', str(exclude_length)])
        
        # Delay
        if delay_ms:
            cmd.extend(['--delay', f'{delay_ms}ms'])
        
        # Quiet mode (machine parseable)
        cmd.append('-q')
        
        # No progress output
        cmd.append('--no-progress')
        
        # Output will be read from stdout
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                errors.append(f"Scan timed out after {timeout} seconds")
                return GobusterResult(
                    target=target,
                    mode=mode,
                    found=found,
                    status_codes=status_codes_count,
                    execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                    tool_version=self.get_version(),
                    wordlist=wordlist,
                    errors=errors
                )
            
            if proc.returncode not in [0, 1]:  # 0=success, 1=findings, anything else=error
                error_output = stderr.decode() if stderr else ""
                if error_output:
                    errors.append(error_output[:500])
            
            # Parse output
            output = stdout.decode()
            found = self._parse_output(output, mode)
            
            # Count status codes
            for item in found:
                code = item.get('status_code', 0)
                status_codes_count[code] = status_codes_count.get(code, 0) + 1
                
        except Exception as e:
            errors.append(str(e)[:200])
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return GobusterResult(
            target=target,
            mode=mode,
            found=found,
            status_codes=status_codes_count,
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            wordlist=wordlist,
            errors=errors
        )
    
    def _parse_output(self, output: str, mode: str) -> List[Dict[str, Any]]:
        """Parse gobuster output into structured results"""
        results = []
        
        if mode == 'dir':
            # Gobuster quiet mode output: "Found: /path (Status: 200) [Size: 1234]"
            for line in output.split('\n'):
                if 'Found:' in line:
                    # Extract path - format: "Found: /path (Status: 200) [Size: 1234]"
                    path_match = re.search(r'Found:\s+(/[^\s(]+)', line)
                    status_match = re.search(r'Status:\s+(\d+)', line)
                    size_match = re.search(r'Size:\s+(\d+)', line)
                    
                    if path_match:
                        results.append({
                            'type': 'endpoint',
                            'path': path_match.group(1).strip(),
                            'status_code': int(status_match.group(1)) if status_match else 0,
                            'size': int(size_match.group(1)) if size_match else 0
                        })
                        
        elif mode == 'dns':
            # DNS matches: Found: subdomain.domain.com
            for line in output.split('\n'):
                if line.startswith('Found:'):
                    match = re.search(r'Found:\n*(\/[^\n]+)', line)
                    if match:
                        subdomain = match.group(1).strip()
                        results.append({
                            'type': 'subdomain',
                            'subdomain': subdomain
                        })
                        
        elif mode == 'vhost':
            # Vhost matches: Found: virtual.host.com (Status: 200)
            for line in output.split('\n'):
                if line.startswith('Found:'):
                    match = re.search(r'Found:\n*([^\n(]+)', line)
                    status_match = re.search(r'Status:\n*(\\d+)', line)
                    
                    if match:
                        results.append({
                            'type': 'vhost',
                            'vhost': match.group(1).strip(),
                            'status_code': int(status_match.group(1)) if status_match else 0
                        })
        
        return results
    
    def _get_default_wordlist(self) -> Optional[str]:
        """Get path to default wordlist, checking common Windows and Linux locations"""
        # Try common wordlist locations based on OS
        if platform.system() == 'Windows' or os.path.exists('C:'):
            windows_paths = [
                r'C:\wordlists\common.txt',
                r'C:\wordlists\directory-list-2.3-medium.txt',
                os.path.expanduser(r'~\wordlists\common.txt'),
                os.path.expanduser(r'~\Downloads\wordlists\common.txt'),
                r'C:\Users\Public\wordlists\common.txt',
                r'C:\Program Files\Gobuster\wordlists\common.txt',
                r'C:\tools\wordlists\common.txt',
            ]
            for path in windows_paths:
                if os.path.exists(path):
                    return path
        
        # Try Linux/Unix paths
        unix_paths = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/opt/seclists/Discovery/Web-Content/common.txt',
        ]
        for path in unix_paths:
            if os.path.exists(path):
                return path
        
        # No wordlist found - return None and let caller handle the error
        return None
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_modes': self.supported_modes,
            'features': [
                'directory_enumeration',
                'dns_subdomain_discovery',
                'virtual_host_discovery',
                'custom_wordlists',
                'thread_control',
                'status_code_filtering',
                'file_extension_scanning',
                'custom_headers',
                'user_agent_spoofing'
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target URL or domain'},
                'mode': {'required': True, 'options': self.supported_modes, 'description': 'Scan mode'},
                'wordlist': {'required': False, 'description': 'Path to wordlist file'},
                'threads': {'required': False, 'default': 10, 'description': 'Concurrent threads'},
                'extensions': {'required': False, 'description': 'File extensions (dir mode)'},
                'status_codes': {'required': False, 'description': 'Status codes to show'},
                'headers': {'required': False, 'description': 'Custom HTTP headers'},
                'delay_ms': {'required': False, 'description': 'Delay between requests'}
            },
            'owasp_mapping': {
                'A01': 'Broken Access Control - enumeration of hidden resources',
                'A02': 'Security Misconfiguration - directory scanning',
                'A05': 'Injection - path traversal discovery'
            }
        }


# Global instance for tool registry
_gobuster_tool: Optional[GobusterTool] = None


def get_gobuster_tool() -> GobusterTool:
    """Get or create global gobuster tool instance"""
    global _gobuster_tool
    if _gobuster_tool is None:
        _gobuster_tool = GobusterTool()
    return _gobuster_tool