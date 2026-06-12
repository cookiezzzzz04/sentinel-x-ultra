"""Hydra Tool Integration for Sentinel-X

Provides structured execution and result parsing for THC-Hydra brute force testing.

Features:
- Protocol-specific brute forcing (SSH, FTP, HTTP, HTTPS, MySQL, PostgreSQL, etc.)
- Username/password file-based attacks
- Single target and multi-target scanning
- Output parsing for multiple formats
"""

import asyncio
import subprocess
import re
import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class HydraResult:
    """Structured Hydra scan result"""
    target: str
    service: str
    attempts: int
    successes: List[Dict[str, Any]]
    execution_time_seconds: float
    tool_version: str
    raw_output: str
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HydraTool:
    """THC-Hydra tool integration for Sentinel-X"""

    def __init__(self):
        self.name = "hydra"
        self.supported_services = [
            "ssh", "ftp", "http-get", "http-post", "https-get", "https-post",
            "mysql", "postgresql", "mssql", "redis", "mongodb",
            "smtp", "pop3", "imap", "ldap", "rdp", "vnc", "telnet",
            "snmp", "cisco-enable", "cisco-aaa"
        ]
        self.version_cache: Optional[str] = None
        self._path_cache: Optional[str] = None

    def _get_hydra_path(self) -> Optional[str]:
        """Get hydra executable path, checking common locations"""
        if self._path_cache:
            return self._path_cache

        # Check SENTINELX_TOOLS_DIR first
        sentinelx_tools = os.path.expanduser("~/.sentinelx/tools")
        for cmd in ['hydra', 'hydra.exe']:
            path = os.path.join(sentinelx_tools, cmd)
            if os.path.exists(path):
                self._path_cache = path
                return path

        # Check PATH
        for cmd in ['hydra', 'hydra.exe']:
            try:
                result = subprocess.run(
                    [cmd, '--version'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    self._path_cache = cmd
                    return cmd
            except Exception:
                pass

        # Check common Windows paths
        windows_paths = [
            r'C:\Program Files\Hydra\hydra.exe',
            r'C:\tools\hydra\hydra.exe',
            os.path.expanduser(r'~\tools\hydra\hydra.exe'),
        ]
        for path in windows_paths:
            if os.path.exists(path):
                self._path_cache = path
                return path

        # Check common Linux paths
        linux_paths = [
            '/usr/bin/hydra',
            '/usr/local/bin/hydra',
            '/opt/hydra/hydra',
        ]
        for path in linux_paths:
            if os.path.exists(path):
                self._path_cache = path
                return path

        return None

    def is_available(self) -> bool:
        """Check if hydra is installed and accessible"""
        return self._get_hydra_path() is not None

    def get_version(self) -> str:
        """Get hydra version string"""
        if self.version_cache:
            return self.version_cache

        hydra_path = self._get_hydra_path()
        if not hydra_path:
            return "unknown"

        try:
            result = subprocess.run(
                [hydra_path, '--version'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                match = re.search(r'(\d+\.\d+(?:\.\d+)?)', result.stdout)
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
        service: str = "ssh",
        username: Optional[str] = None,
        username_file: Optional[str] = None,
        password_file: Optional[str] = None,
        port: Optional[int] = None,
        threads: int = 4,
        timeout_sec: int = 600,
        extra_args: Optional[List[str]] = None,
    ) -> HydraResult:
        """
        Execute a Hydra brute force scan.

        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post, mysql, etc.)
            username: Single username to try
            username_file: File with usernames
            password_file: File with passwords (required)
            port: Custom port (auto-detected if None)
            threads: Number of parallel connections
            timeout_sec: Scan timeout in seconds
            extra_args: Additional hydra arguments
        """
        errors = []
        successes = []
        start_time = datetime.now()
        raw_output = ""

        hydra_path = self._get_hydra_path()
        if not hydra_path:
            return HydraResult(
                target=target, service=service, attempts=0, successes=[],
                execution_time_seconds=0, tool_version="unknown",
                raw_output="", errors=["Hydra not found. Install from: https://github.com/vanhauser-thc/thc-hydra"]
            )

        if not password_file:
            return HydraResult(
                target=target, service=service, attempts=0, successes=[],
                execution_time_seconds=0, tool_version=self.get_version(),
                raw_output="", errors=["password_file is required for Hydra scans"]
            )

        if service not in self.supported_services:
            errors.append(f"Unsupported service: {service}. Supported: {', '.join(self.supported_services[:10])}...")

        cmd = [hydra_path]

        # Output format
        cmd.extend(['-o', '-'])  # stdout
        cmd.append('-v')  # verbose

        # Threads
        cmd.extend(['-t', str(threads)])

        # Timeout
        cmd.extend(['-w', '30'])  # Wait time between connections

        # Username
        if username_file:
            cmd.extend(['-L', username_file])
        elif username:
            cmd.extend(['-l', username])
        else:
            cmd.extend(['-l', 'admin'])  # Default if neither provided

        # Password file
        cmd.extend(['-P', password_file])

        # Custom port
        if port:
            cmd.extend(['-s', str(port)])

        # Target
        if service in ('http-get', 'http-post', 'https-get', 'https-post'):
            # For web services: hydra -l user -P pass target.com http-post-form "/path:user=^USER^&pass=^PASS^:F=incorrect"
            # We need URL format
            target = f"http://{target}" if not target.startswith('http') else target
            cmd.append(target)
            cmd.append(service)
        else:
            # Standard: hydra -l user -P pass target service
            cmd.append(target)
            cmd.append(service)

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_sec
                )
            except asyncio.TimeoutError:
                proc.kill()
                errors.append(f"Scan timed out after {timeout_sec} seconds")
                return HydraResult(
                    target=target, service=service, attempts=0, successes=successes,
                    execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                    tool_version=self.get_version(), raw_output=raw_output, errors=errors
                )

            if proc.returncode not in (0, 255):
                error_output = stderr.decode() if stderr else ""
                if error_output:
                    errors.append(error_output[:500])

            raw_output = stdout.decode('utf-8', errors='replace') if stdout else ""

            # Parse output for successful logins
            for line in raw_output.split('\n'):
                line = line.strip()
                if '[80]' in line or '[22]' in line or '[21]' in line or '[3306]' in line:
                    continue  # Skip status lines
                if 'login:' in line.lower() and 'password:' in line.lower():
                    successes.append(self._parse_success(line))
                elif 'host:' in line.lower() and ('login:' in line.lower() or 'password:' in line.lower()):
                    successes.append(self._parse_success(line))

        except Exception as e:
            errors.append(str(e)[:200])

        execution_time = (datetime.now() - start_time).total_seconds()

        return HydraResult(
            target=target, service=service,
            attempts=len(raw_output.split('\n')) if raw_output else 0,
            successes=successes,
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            raw_output=raw_output[:10000],
            errors=errors
        )

    def _parse_success(self, line: str) -> Dict[str, Any]:
        """Parse a successful login line from Hydra output"""
        result = {"raw": line, "host": "", "login": "", "password": "", "port": 0}

        # Parse: [22][ssh] host: 192.168.1.1   login: admin   password: secret
        host_match = re.search(r'host:\s*([^\s]+)', line)
        if host_match:
            result["host"] = host_match.group(1)

        login_match = re.search(r'login:\s*([^\s]+)', line)
        if login_match:
            result["login"] = login_match.group(1)

        password_match = re.search(r'password:\s*([^\s]+)', line)
        if password_match:
            result["password"] = password_match.group(1)

        port_match = re.search(r'\[(\d+)\]', line)
        if port_match:
            result["port"] = int(port_match.group(1))

        return result

    def get_capabilities(self) -> Dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_services': self.supported_services,
            'features': [
                'protocol_brute_force',
                'username_dictionary',
                'password_dictionary',
                'multi_threaded',
                'port_customization',
                'service_discovery',
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target IP or hostname'},
                'service': {'required': True, 'options': self.supported_services, 'description': 'Service to attack'},
                'username': {'required': False, 'description': 'Single username'},
                'username_file': {'required': False, 'description': 'File with usernames'},
                'password_file': {'required': True, 'description': 'File with passwords'},
                'port': {'required': False, 'description': 'Custom port number'},
                'threads': {'required': False, 'default': 4, 'description': 'Parallel connections'},
            },
            'owasp_mapping': {
                'A02': 'Broken Authentication - credential brute forcing',
                'A07': 'Identification and Authentication Failures - weak credentials',
            }
        }


# Global instance for tool registry
_hydra_tool: Optional[HydraTool] = None


def get_hydra_tool() -> HydraTool:
    """Get or create global hydra tool instance"""
    global _hydra_tool
    if _hydra_tool is None:
        _hydra_tool = HydraTool()
    return _hydra_tool
