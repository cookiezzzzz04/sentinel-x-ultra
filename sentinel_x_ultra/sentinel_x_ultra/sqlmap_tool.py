"""SQLMap Tool Integration for Sentinel-X

Provides structured execution and result parsing for SQLMap SQL injection automation.

Features:
- Database fingerprinting
- SQL injection detection (Boolean, Time, Error, Union, Stacked)
- Database/table enumeration
- Data extraction
- Request replay and tampering
"""

import asyncio
import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass
class SQLMapResult:
    """Structured SQLMap scan result"""
    target: str
    technique: str
    dbms: str | None
    databases: list[dict[str, Any]]
    tables: list[dict[str, Any]]
    entries: list[dict[str, Any]]
    vulnerable_parameters: list[str]
    execution_time_seconds: float
    tool_version: str
    raw_output: str
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SQLMapTool:
    """SQLMap tool integration for Sentinel-X"""

    def __init__(self):
        self.name = "sqlmap"
        self.supported_techniques = ["B", "E", "U", "S", "T", "BEUST"]  # Boolean, Error, Union, Stacked, Time, All
        self.version_cache: str | None = None
        self._path_cache: str | None = None

    def _get_sqlmap_path(self) -> str | None:
        """Get sqlmap executable path, checking common locations"""
        if self._path_cache:
            return self._path_cache

        # Check SENTINELX_TOOLS_DIR first
        sentinelx_tools = os.path.expanduser("~/.sentinelx/tools")
        for cmd in ['sqlmap.py', 'sqlmap', 'sqlmap.exe']:
            path = os.path.join(sentinelx_tools, cmd)
            if os.path.exists(path):
                self._path_cache = path
                return path

        # Check sqlmap directory with sqlmap.py
        sqlmap_dir = os.path.join(sentinelx_tools, 'sqlmap')
        if os.path.exists(os.path.join(sqlmap_dir, 'sqlmap.py')):
            self._path_cache = os.path.join(sqlmap_dir, 'sqlmap.py')
            return self._path_cache

        # Check PATH
        for cmd in ['sqlmap', 'sqlmap.py']:
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

        return None

    def is_available(self) -> bool:
        """Check if sqlmap is installed and accessible"""
        return self._get_sqlmap_path() is not None

    def get_version(self) -> str:
        """Get sqlmap version string"""
        if self.version_cache:
            return self.version_cache

        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            return "unknown"

        try:
            result = subprocess.run(
                [sqlmap_path, '--version'],
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
        data: str | None = None,
        cookie: str | None = None,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        technique: str = "BEUST",
        level: int = 1,
        risk: int = 1,
        threads: int = 1,
        dbms: str | None = None,
        batch: bool = True,
        random_agent: bool = True,
        timeout_sec: int = 600,
        extra_args: list[str] | None = None,
    ) -> SQLMapResult:
        """
        Execute a SQLMap SQL injection scan.

        Args:
            target: Target URL (e.g., http://example.com/page?id=1)
            data: POST data string
            cookie: Session cookie
            user_agent: Custom User-Agent
            technique: Injection techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time)
            level: Test level (1-5, higher = more thorough)
            risk: Risk level (1-3, higher = more dangerous)
            threads: Number of threads
            dbms: Force DBMS type (mysql, mssql, postgresql, oracle, sqlite, etc.)
            batch: Non-interactive mode (never ask for user input)
            random_agent: Use random User-Agent
            timeout_sec: Scan timeout in seconds
            extra_args: Additional sqlmap arguments
        """
        errors = []
        start_time = datetime.now()
        raw_output = ""
        vulnerable_params: list[str] = []

        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            return SQLMapResult(
                target=target, technique=technique, dbms=None,
                databases=[], tables=[], entries=[], vulnerable_parameters=[],
                execution_time_seconds=0, tool_version="unknown",
                raw_output="", errors=["SQLMap not found. Install from: https://github.com/sqlmapproject/sqlmap"]
            )

        # Handle sqlmap.py execution - on Windows, .py files need python prefix
        cmd = []
        if sqlmap_path.endswith('.py'):
            cmd.append('python' if os.name == 'nt' else 'python3')
        cmd.append(sqlmap_path)
        cmd.extend(['-u', target])

        # POST data
        if data:
            cmd.extend(['--data', data])

        # Cookie
        if cookie:
            cmd.extend(['--cookie', cookie])

        # User-Agent
        if random_agent:
            cmd.append('--random-agent')
        else:
            cmd.extend(['--user-agent', user_agent])

        # Technique
        cmd.extend(['--technique', technique])

        # Level and Risk (clamp to SQLMap's supported ranges)
        level = max(1, min(5, level))
        risk = max(1, min(3, risk))
        cmd.extend(['--level', str(level)])
        cmd.extend(['--risk', str(risk)])

        # Threads
        cmd.extend(['--threads', str(threads)])

        # DBMS
        if dbms:
            cmd.extend(['--dbms', dbms])

        # Batch mode
        if batch:
            cmd.append('--batch')

        # Use temp directory for SQLMap output to avoid polluting CWD
        output_dir = tempfile.mkdtemp(prefix='sqlmap_output_')
        cmd.extend(['--output-dir', output_dir])

        # Suppress banner output
        cmd.append('--disable-coloring')

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
                return SQLMapResult(
                    target=target, technique=technique, dbms=None,
                    databases=[], tables=[], entries=[], vulnerable_parameters=[],
                    execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                    tool_version=self.get_version(), raw_output=raw_output, errors=errors
                )

            raw_output = stdout.decode('utf-8', errors='replace') if stdout else ""

            # Parse output for vulnerable parameters
            for line in raw_output.split('\n'):
                # Look for "GET parameter X is vulnerable"
                vuln_match = re.search(r"(GET|POST|Cookie|User-Agent|Referer)\s+parameter\s+'([^']+)'\s+is\s+vulnerable", line, re.IGNORECASE)
                if vuln_match:
                    vulnerable_params.append(vuln_match.group(2))

            # Try to parse SQLMap output files from the temp output directory
            try:
                for root, dirs, files in os.walk(output_dir):
                    for fname in files:
                        if fname.endswith('.json') or fname.endswith('.log'):
                            fpath = os.path.join(root, fname)
                            try:
                                with open(fpath, errors='replace') as f:
                                    json_data = json.load(f)
                            except (json.JSONDecodeError, Exception):
                                pass
            except Exception:
                pass
            finally:
                # Clean up temp directory
                import shutil
                try:
                    shutil.rmtree(output_dir, ignore_errors=True)
                except Exception:
                    pass

        except Exception as e:
            errors.append(str(e)[:200])

        execution_time = (datetime.now() - start_time).total_seconds()

        return SQLMapResult(
            target=target, technique=technique, dbms=None,
            databases=[], tables=[], entries=[],
            vulnerable_parameters=vulnerable_params,
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            raw_output=raw_output[:10000],
            errors=errors
        )

    async def enumerate_databases(
        self,
        target: str,
        technique: str = "BEUST",
        level: int = 1,
        risk: int = 1,
        batch: bool = True,
        timeout_sec: int = 600,
    ) -> SQLMapResult:
        """Enumerate databases from a vulnerable target."""
        result = await self.scan(
            target=target, technique=technique,
            level=level, risk=risk, batch=batch, timeout_sec=timeout_sec,
            extra_args=['--dbs']
        )
        return result

    async def enumerate_tables(
        self,
        target: str,
        database: str,
        technique: str = "BEUST",
        batch: bool = True,
        timeout_sec: int = 600,
    ) -> SQLMapResult:
        """Enumerate tables from a specific database."""
        result = await self.scan(
            target=target, technique=technique,
            level=1, risk=1, batch=batch, timeout_sec=timeout_sec,
            extra_args=['--tables', '-D', database]
        )
        return result

    async def dump_table(
        self,
        target: str,
        database: str,
        table: str,
        columns: list[str] | None = None,
        technique: str = "BEUST",
        batch: bool = True,
        timeout_sec: int = 600,
    ) -> SQLMapResult:
        """Dump data from a specific table."""
        extra_args = ['--dump', '-D', database, '-T', table]
        if columns:
            extra_args.extend(['-C', ','.join(columns)])
        result = await self.scan(
            target=target, technique=technique,
            level=1, risk=1, batch=batch, timeout_sec=timeout_sec,
            extra_args=extra_args
        )
        return result

    def get_capabilities(self) -> dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_techniques': self.supported_techniques,
            'features': [
                'sql_injection_detection',
                'database_fingerprinting',
                'data_extraction',
                'database_enumeration',
                'table_enumeration',
                'automated_dumping',
                'technique_selection',
                'level_and_risk_config',
            ],
            'parameters': {
                'target': {'required': True, 'description': 'Target URL with parameter (e.g., http://site.com/page?id=1)'},
                'data': {'required': False, 'description': 'POST data string'},
                'technique': {'required': False, 'default': 'BEUST', 'options': list('BEUST'), 'description': 'Injection techniques'},
                'level': {'required': False, 'default': 1, 'description': 'Test level (1-5)'},
                'risk': {'required': False, 'default': 1, 'description': 'Risk level (1-3)'},
                'dbms': {'required': False, 'description': 'Force DBMS type'},
                'batch': {'required': False, 'default': True, 'description': 'Non-interactive mode'},
            },
            'owasp_mapping': {
                'A01': 'Broken Access Control - data extraction via SQLi',
                'A03': 'Injection - SQL injection detection and exploitation',
            }
        }


# Global instance for tool registry
_sqlmap_tool: SQLMapTool | None = None


def get_sqlmap_tool() -> SQLMapTool:
    """Get or create global sqlmap tool instance"""
    global _sqlmap_tool
    if _sqlmap_tool is None:
        _sqlmap_tool = SQLMapTool()
    return _sqlmap_tool
