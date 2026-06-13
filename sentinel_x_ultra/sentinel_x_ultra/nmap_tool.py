"""
Nmap Tool Integration for Sentinel-X

Provides structured execution and result parsing for nmap network scanning.

Features:
- Port scanning (basic, SYN, UDP)
- Service detection
- OS fingerprinting
- Script scanning (NSE)
- Output parsing for multiple formats
"""

import asyncio
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class NmapResult:
    """Structured nmap scan result"""
    target: str
    scan_type: str
    ports: list[dict[str, Any]]
    services: list[dict[str, Any]]
    os_detection: dict[str, Any] | None
    execution_time_seconds: float
    tool_version: str
    raw_output: str
    errors: list[str]


class NmapTool:
    """Nmap tool integration for Sentinel-X"""

    def __init__(self):
        self.name = "nmap"
        self.supported_scan_types = ["basic", "syn", "udp", "service", "os", "full"]
        self.version_cache: str | None = None
        self._path_cache: str | None = None

    def _get_nmap_path(self) -> str | None:
        """Get nmap executable path, checking common Windows locations"""
        if self._path_cache:
            return self._path_cache

        # Check if nmap is in PATH first
        for cmd in ['nmap', 'nmap.exe']:
            try:
                result = subprocess.run(
                    [cmd, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self._path_cache = cmd
                    return cmd
            except Exception:
                pass

        # Check common Windows installation paths
        windows_paths = [
            r'C:\Program Files (x86)\Nmap\nmap.exe',
            r'C:\Program Files\Nmap\nmap.exe',
            os.path.expanduser(r'~\AppData\Local\Programs\Nmap\nmap.exe'),
        ]

        for path in windows_paths:
            if os.path.exists(path):
                self._path_cache = path
                return path

        return None

    def is_available(self) -> bool:
        """Check if nmap is installed and accessible"""
        return self._get_nmap_path() is not None

    def get_version(self) -> str:
        """Get nmap version string"""
        if self.version_cache:
            return self.version_cache

        nmap_cmd = self._get_nmap_path()
        if not nmap_cmd:
            return "unknown"

        try:
            result = subprocess.run(
                [nmap_cmd, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                match = re.search(r'Nmap version (\d+\.\d+)', result.stdout)
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
        scan_type: str = "basic",
        ports: str = None,
        timing: int = 4,
        timeout: int = 300,
        scripts: bool = False,
        os_detection: bool = False,
        service_detection: bool = False
    ) -> NmapResult:
        """
        Execute an nmap scan with structured parameters.

        Args:
            target: Target IP or hostname
            scan_type: Type of scan (basic, syn, udp, service, os, full)
            ports: Port range (e.g., "1-1000", "80,443,8080")
            timing: Timing template (0-5, higher is faster)
            timeout: Scan timeout in seconds
            scripts: Enable NSE script scanning
            os_detection: Enable OS detection (-O)
            service_detection: Enable service detection (-sV)
        """
        errors = []
        start_time = datetime.now()
        raw_output = ""

        # Build nmap command using full path
        nmap_path = self._get_nmap_path() or 'nmap'
        cmd = [nmap_path]

        # Output options
        cmd.extend(['-oX', '-'])  # XML output to stdout
        cmd.append('-v')  # Verbose for now

        # Timing
        cmd.append(f'-T{timing}')

        # Scan type
        if scan_type == "syn":
            cmd.append('-sS')
        elif scan_type == "udp":
            cmd.append('-sU')
        elif scan_type == "service":
            cmd.append('-sV')
        elif scan_type == "os":
            cmd.append('-O')
        elif scan_type == "full":
            cmd.extend(['-sS', '-sV', '-O', '-sC'])

        # Custom ports
        if ports:
            cmd.append(f'-p{ports}')

        # Scripts
        if scripts:
            cmd.append('-sC')  # Default scripts

        # OS detection
        if os_detection:
            cmd.append('-O')

        # Service detection
        if service_detection:
            cmd.append('-sV')

        # Target
        cmd.append(target)

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
                return NmapResult(
                    target=target,
                    scan_type=scan_type,
                    ports=[],
                    services=[],
                    os_detection=None,
                    execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                    tool_version=self.get_version(),
                    raw_output="",
                    errors=errors
                )

            if proc.returncode != 0:
                error_output = stderr.decode() if stderr else ""
                if error_output:
                    errors.append(error_output[:500])

            raw_output = stdout.decode()

        except Exception as e:
            errors.append(str(e)[:200])

        execution_time = (datetime.now() - start_time).total_seconds()

        # Parse output
        ports, services, os_info = self._parse_xml_output(raw_output)

        return NmapResult(
            target=target,
            scan_type=scan_type,
            ports=ports,
            services=services,
            os_detection=os_info,
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            raw_output=raw_output[:5000],  # Limit raw output
            errors=errors
        )

    def _parse_xml_output(self, xml_output: str) -> tuple:
        """Parse nmap XML output into structured data"""
        ports = []
        services = []
        os_info = None

        if not xml_output:
            return ports, services, os_info

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)

            # Parse ports
            for port in root.iter('port'):
                port_data = {
                    'protocol': port.get('protocol', 'tcp'),
                    'port_id': int(port.get('portid', 0)),
                    'state': port.find('state').get('state', 'unknown') if port.find('state') is not None else 'unknown',
                }

                # Service info
                service = port.find('service')
                if service is not None:
                    port_data['service'] = {
                        'name': service.get('name', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', ''),
                    }
                    services.append({
                        'port': port_data['port_id'],
                        'protocol': port_data['protocol'],
                        'name': service.get('name', ''),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                    })

                ports.append(port_data)

            # Parse OS info
            osmatch = root.find('.//osmatch')
            if osmatch is not None:
                os_info = {
                    'name': osmatch.get('name', ''),
                    'accuracy': osmatch.get('accuracy', ''),
                    'line': osmatch.get('line', ''),
                }

        except Exception:
            # XML parsing failed, try text parsing fallback
            pass

        return ports, services, os_info

    def get_capabilities(self) -> dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_scan_types': self.supported_scan_types,
            'features': [
                'port_scanning',
                'service_detection',
                'os_fingerprinting',
                'script_scanning',
                'traceroute',
                'dns_resolution'
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target IP or hostname'},
                'scan_type': {'required': False, 'options': self.supported_scan_types, 'description': 'Type of scan'},
                'ports': {'required': False, 'description': 'Port range (e.g., "1-1000")'},
                'timing': {'required': False, 'default': 4, 'description': 'Speed (0-5)'},
                'scripts': {'required': False, 'default': False, 'description': 'Enable NSE scripts'},
                'os_detection': {'required': False, 'default': False, 'description': 'OS detection'},
                'service_detection': {'required': False, 'default': False, 'description': 'Service version detection'}
            },
            'owasp_mapping': {
                'A01': 'Broken Access Control - network reconnaissance',
                'A02': 'Security Misconfiguration - open ports/services detection',
                'A05': 'Injection - backdoor detection via unusual ports'
            }
        }


# Global instance for tool registry
_nmap_tool: NmapTool | None = None


def get_nmap_tool() -> NmapTool:
    """Get or create global nmap tool instance"""
    global _nmap_tool
    if _nmap_tool is None:
        _nmap_tool = NmapTool()
    return _nmap_tool
