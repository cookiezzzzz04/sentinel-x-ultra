"""John the Ripper Tool Integration for Sentinel-X

Provides structured execution and result parsing for John the Ripper
password hash cracking.

Features:
- Multi-hash format cracking (MD5, SHA1/256/512, bcrypt, NTLM, etc.)
- Wordlist mode with rules
- Single crack mode (login-based)
- Incremental (brute force) mode
- Hash file generation for common formats
- Output parsing for cracked passwords
"""

import asyncio
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass
class JohnResult:
    """Structured John the Ripper scan result"""
    hash_file: str
    hash_type: str
    mode: str
    cracked: list[dict[str, Any]]
    total_hashes: int
    cracked_count: int
    execution_time_seconds: float
    tool_version: str
    raw_output: str
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class JohnTool:
    """John the Ripper tool integration for Sentinel-X"""

    def __init__(self):
        self.name = "john"
        self.supported_formats = [
            "auto", "raw-md5", "raw-sha1", "raw-sha256", "raw-sha512",
            "bcrypt", "sha256crypt", "sha512crypt", "md5crypt",
            "nt", "lm", "mssql", "mysql", "mysql-sha1",
            "oracle", "postgres", "bsdi", "descrypt", "bsdicrypt",
            "phpass", "pbkdf2-hmac-sha256", "pbkdf2-hmac-sha512",
            "krb5tgs", "ssh", "rsa-private-key",
        ]
        self.version_cache: str | None = None
        self._path_cache: str | None = None
        self._known_formats: list[str] | None = None

    def _get_john_path(self) -> str | None:
        """Get john executable path, checking common locations"""
        if self._path_cache:
            return self._path_cache

        sentinelx_tools = os.path.expanduser("~/.sentinelx/tools")

        # Priority 1: Check the run/ subdirectory first (has all DLLs on Windows)
        # John bleeding-jumbo distributes the binary inside a run/ folder
        # Windows builds often have CPU-optimized variants (john-avx2.exe, john-sse4.exe, etc.)
        run_dir = os.path.join(sentinelx_tools, "john", "run")
        if os.path.isdir(run_dir):
            # Check optimized variants first (AVX2 > AVX > SSE4 > SSE2 > generic)
            for variant in ['john-avx2.exe', 'john-avx.exe', 'john-sse4.exe', 'john-sse2.exe',
                            'john-non-omp.exe', 'john.exe', 'john', 'John.exe']:
                path = os.path.join(run_dir, variant)
                if os.path.exists(path) and self._verify_binary(path):
                    self._path_cache = path
                    return path

        # Priority 2: Check the john subdirectory (some installs put binary directly here)
        for cmd in ['john-avx2.exe', 'john-avx.exe', 'john-sse4.exe', 'john-sse2.exe',
                    'john-non-omp.exe', 'john.exe', 'john', 'John.exe', 'John']:
            path = os.path.join(sentinelx_tools, "john", cmd)
            if os.path.exists(path) and self._verify_binary(path):
                self._path_cache = path
                return path

        # Priority 3: Check other common bleeding-jumbo paths
        for base in [sentinelx_tools, os.path.join(sentinelx_tools, "john-bleeding-jumbo")]:
            run_dir2 = os.path.join(base, "run")
            if os.path.isdir(run_dir2):
                for variant in ['john-avx2.exe', 'john-avx.exe', 'john-sse4.exe', 'john.exe', 'john']:
                    path = os.path.join(run_dir2, variant)
                    if os.path.exists(path) and self._verify_binary(path):
                        self._path_cache = path
                        return path

        # Priority 4: Check tools root (standalone copy — verify it works first)
        for cmd in ['john', 'john.exe', 'John', 'John.exe']:
            path = os.path.join(sentinelx_tools, cmd)
            if os.path.exists(path) and self._verify_binary(path):
                self._path_cache = path
                return path

        # Priority 5: Check PATH
        for cmd in ['john', 'john.exe']:
            try:
                which_cmd = 'where' if os.name == 'nt' else 'which'
                which_path = subprocess.run(
                    [which_cmd, cmd],
                    capture_output=True, text=True, timeout=5
                )
                if which_path.returncode == 0:
                    resolved = which_path.stdout.strip().split('\n')[0]
                    if resolved and self._verify_binary(resolved):
                        self._path_cache = resolved
                        return resolved
            except Exception:
                pass

        # Priority 6: Check common Windows paths
        windows_paths = [
            r'C:\Program Files\John the Ripper\run\john.exe',
            r'C:\Program Files\John the Ripper\run\john-avx2.exe',
            r'C:\Program Files\John the Ripper\john.exe',
            r'C:\John\run\john.exe',
            r'C:\tools\john\run\john.exe',
            r'C:\tools\john-bleeding-jumbo\run\john.exe',
            os.path.expanduser(r'~\tools\john\run\john.exe'),
        ]
        for path in windows_paths:
            if os.path.exists(path) and self._verify_binary(path):
                self._path_cache = path
                return path

        # Priority 7: Check common Linux paths
        linux_paths = [
            '/usr/bin/john',
            '/usr/local/bin/john',
            '/opt/john/run/john',
            '/opt/john/john',
            '/opt/john-bleeding-jumbo/run/john',
        ]
        for path in linux_paths:
            if os.path.exists(path) and self._verify_binary(path):
                self._path_cache = path
                return path

        return None

    def _verify_binary(self, path: str) -> bool:
        """Verify that a john binary can actually execute (has all DLLs, etc.)

        John the Ripper Windows builds (1.9.0-jumbo-1) don't support --version
        flag — they output version info when run with no arguments but return
        exit code 1. This method handles both cases.
        """
        try:
            work_dir = os.path.dirname(path)

            # Method 1: Try --version (works on Linux/Mac, some Windows builds)
            try:
                result = subprocess.run(
                    [path, '--version'],
                    capture_output=True, text=True, timeout=10,
                    cwd=work_dir
                )
                if result.returncode == 0 and result.stdout.strip():
                    return True
            except Exception:
                pass

            # Method 2: Run with no args — John outputs version on first line
            result = subprocess.run(
                [path],
                capture_output=True, text=True, timeout=10,
                cwd=work_dir
            )
            output = (result.stdout or '') + (result.stderr or '')
            # Version line looks like: "John the Ripper 1.9.0-jumbo-1 ..."
            if 'John the Ripper' in output:
                return True

        except Exception:
            pass
        return False

    def is_available(self) -> bool:
        """Check if john is installed and accessible (verifies binary works)"""
        return self._get_john_path() is not None

    def get_version(self) -> str:
        """Get john version string"""
        if self.version_cache:
            return self.version_cache

        john_path = self._get_john_path()
        if not john_path:
            return "unknown"

        work_dir = os.path.dirname(john_path)

        # Method 1: Try --version (works on Linux/Mac)
        try:
            result = subprocess.run(
                [john_path, '--version'],
                capture_output=True, text=True, timeout=10,
                cwd=work_dir
            )
            if result.returncode == 0 and result.stdout.strip():
                ver = result.stdout.strip()[:80]
                if ver:
                    self.version_cache = ver
                    return ver
        except Exception:
            pass

        # Method 2: Run with no args — first line contains version on Windows builds
        try:
            result = subprocess.run(
                [john_path],
                capture_output=True, text=True, timeout=10,
                cwd=work_dir
            )
            output = (result.stdout or '') + (result.stderr or '')
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('John the Ripper'):
                    self.version_cache = line[:80]
                    return line[:80]
        except Exception:
            pass

        return "unknown"

    def get_available_formats(self) -> list[str]:
        """Get list of supported hash formats from john --list=formats"""
        if self._known_formats:
            return self._known_formats

        john_path = self._get_john_path()
        if not john_path:
            return self.supported_formats

        try:
            result = subprocess.run(
                [john_path, '--list=formats'],
                capture_output=True, text=True, timeout=30,
                cwd=os.path.dirname(john_path)
            )
            if result.returncode == 0:
                formats = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('['):
                        formats.extend(f.lower().strip() for f in line.split(',') if f.strip())
                if formats:
                    self._known_formats = formats
                    return formats
        except Exception:
            pass
        return self.supported_formats

    def _write_hash_file(self, hashes: str | list[str], hash_type: str | None = None) -> str:
        """Write hash(es) to a temp file with optional format marker"""
        if isinstance(hashes, list):
            content = '\n'.join(hashes)
        else:
            content = hashes

        suffix = ''
        if hash_type and hash_type != 'auto':
            suffix = f'.{hash_type.replace("-", "").replace("_", "")}'

        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix=f'{suffix}.txt', delete=False,
            encoding='utf-8'
        )
        tmp.write(content)
        tmp.close()
        return tmp.name

    def _detect_hash_type(self, hash_str: str) -> str:
        """Attempt to detect hash type from format"""
        hash_str = hash_str.strip()

        # Standard format markers (john --list=format-details)
        markers = [
            (r'^\$2[ayb]\$\d{2}\$', 'bcrypt'),
            (r'^\$5\$', 'sha256crypt'),
            (r'^\$6\$', 'sha512crypt'),
            (r'^\$1\$', 'md5crypt'),
            (r'^\{SSHA\}', 'ssha'),
            (r'^\{SHA\}', 'sha1'),
        ]
        for pattern, fmt in markers:
            if re.search(pattern, hash_str):
                return fmt

        # Length-based detection
        hash_stripped = hash_str.replace(':', '').replace('$', '').replace('-', '')
        length = len(hash_stripped)

        # Remove username: prefix if present
        if ':' in hash_str and not hash_str.startswith('$'):
            parts = hash_str.split(':', 1)
            if len(parts) == 2 and len(parts[1]) > 0:
                hash_stripped = parts[1].strip()
                length = len(hash_stripped)

        common = {
            32: 'raw-md5',
            40: 'raw-sha1',
            56: 'raw-sha224',
            64: 'raw-sha256',
            96: 'raw-sha384',
            128: 'raw-sha512',
            16: 'descrypt',
            13: 'descrypt',
            34: 'lm',
            65: 'nt',
            60: 'bcrypt',
        }
        return common.get(length, 'auto')

    async def crack(
        self,
        hashes: str | list[str],
        hash_type: str = 'auto',
        mode: str = 'wordlist',
        wordlist: str | None = None,
        rules: bool = True,
        timeout_sec: int = 300,
        extra_args: list[str] | None = None,
        username: str | None = None,
    ) -> JohnResult:
        """
        Execute a John the Ripper cracking session.

        Args:
            hashes: Hash string or list of hash strings to crack
            hash_type: Hash format (auto-detect if 'auto')
            mode: Cracking mode ('wordlist', 'single', 'incremental', 'markov')
            wordlist: Path to wordlist file (optional, uses john's default if None)
            rules: Apply word-mangling rules
            timeout_sec: Maximum execution time
            extra_args: Additional john arguments
            username: Optional username for single crack mode
        """
        errors = []
        cracked = []
        start_time = datetime.now()
        raw_output = ""

        john_path = self._get_john_path()
        if not john_path:
            return JohnResult(
                hash_file="", hash_type=hash_type, mode=mode, cracked=[],
                total_hashes=0, cracked_count=0,
                execution_time_seconds=0, tool_version="unknown",
                raw_output="",
                errors=["John the Ripper not found. Install from: https://www.openwall.com/john/"]
            )

        # Detect hash type
        # When auto, don't pass --format at all — let John auto-detect from the hash content
        detected_type = hash_type
        if hash_type == 'auto':
            detected_type = ''
        elif hash_type:
            # User specified a format — use it as-is (John handles format name variations)
            pass

        # Write hash file
        hash_file_path = self._write_hash_file(hashes, detected_type if detected_type else None)

        cmd = [john_path]

        # Format — only pass --format when user explicitly specified a type
        # Note: Windows builds of John require --format=<name> (with = sign)
        if detected_type:
            cmd.append(f'--format={detected_type}')

        # Mode
        if mode == 'single':
            cmd.append('--single')
        elif mode == 'incremental':
            cmd.append('--incremental')
        elif mode == 'markov':
            cmd.append('--markov')
        else:
            # Wordlist mode (default)
            # Note: --wordlist uses space-separated syntax; the = sign doesn't work
            # with Windows backslash paths
            if wordlist:
                cmd.extend(['--wordlist', wordlist])
            else:
                default_wl = os.path.expanduser('~/.sentinelx/tools/wordlist.txt')
                if os.path.exists(default_wl):
                    cmd.extend(['--wordlist', default_wl])

        # Rules
        if rules and mode == 'wordlist':
            cmd.append('--rules')

        # Pot file in temp to avoid affecting user's john.pot
        # Note: Windows builds of John require --pot=<path> (with = sign)
        pot_file = tempfile.NamedTemporaryFile(suffix='.pot', delete=False)
        pot_path = pot_file.name
        pot_file.close()
        cmd.append(f'--pot={pot_path}')

        # Hash file
        cmd.append(hash_file_path)

        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        # Count total hashes
        total_hashes_input = len(hashes) if isinstance(hashes, list) else len(hashes.strip().split('\n'))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(john_path)
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_sec
                )
            except asyncio.TimeoutError:
                proc.kill()
                errors.append(f"Cracking timed out after {timeout_sec} seconds")
                # Try to get partial results from pot file
                cracked = self._parse_pot_file(pot_path)
                os.unlink(pot_path)
                os.unlink(hash_file_path)
                return JohnResult(
                    hash_file=hash_file_path, hash_type=detected_type, mode=mode,
                    cracked=cracked, total_hashes=total_hashes_input,
                    cracked_count=len(cracked),
                    execution_time_seconds=(datetime.now() - start_time).total_seconds(),
                    tool_version=self.get_version(), raw_output=raw_output[:10000],
                    errors=errors
                )

            raw_output = (stdout.decode('utf-8', errors='replace') if stdout else "") + \
                         ("\n" + stderr.decode('utf-8', errors='replace') if stderr else "")

            # Parse pot file for cracked passwords
            cracked = self._parse_pot_file(pot_path)

            # Also parse stdout for cracked passwords
            for line in raw_output.split('\n'):
                line = line.strip()
                # Match: username (hash-type): password
                match = re.search(r'^(.+?)\s*\((.+?)\):\s*(.+)$', line)
                if match:
                    cracked.append({
                        "username": match.group(1).strip(),
                        "hash_type": match.group(2).strip(),
                        "password": match.group(3).strip(),
                        "source": "stdout",
                    })

            # Parse errors
            if proc.returncode not in (0, 1):
                stderr_text = stderr.decode() if stderr else ""
                if stderr_text:
                    errors.append(stderr_text[:500])

        except Exception as e:
            errors.append(str(e)[:200])

        finally:
            # Cleanup temp files
            try:
                os.unlink(pot_path)
            except Exception:
                pass
            try:
                os.unlink(hash_file_path)
            except Exception:
                pass

        execution_time = (datetime.now() - start_time).total_seconds()

        # Deduplicate cracked
        seen = set()
        unique_cracked = []
        for c in cracked:
            key = c.get('password', '')
            if key and key not in seen:
                seen.add(key)
                unique_cracked.append(c)

        return JohnResult(
            hash_file=hash_file_path, hash_type=detected_type, mode=mode,
            cracked=unique_cracked,
            total_hashes=total_hashes_input,
            cracked_count=len(unique_cracked),
            execution_time_seconds=execution_time,
            tool_version=self.get_version(),
            raw_output=raw_output[:10000],
            errors=errors,
        )

    async def show_cracked(self, hash_file: str) -> JohnResult:
        """Show cracked passwords from a previous session."""
        errors = []
        cracked = []
        raw_output = ""
        start_time = datetime.now()

        john_path = self._get_john_path()
        if not john_path:
            return JohnResult(
                hash_file=hash_file, hash_type="", mode="show", cracked=[],
                total_hashes=0, cracked_count=0,
                execution_time_seconds=0, tool_version="unknown",
                raw_output="", errors=["John not found"]
            )

        try:
            result = subprocess.run(
                [john_path, '--show', hash_file],
                capture_output=True, text=True, timeout=30,
                cwd=os.path.dirname(john_path)
            )
            raw_output = result.stdout
            for line in result.stdout.split('\n'):
                line = line.strip()
                match = re.search(r'^(.+?)\s*\((.+?)\):\s*(.+)$', line)
                if match:
                    cracked.append({
                        "username": match.group(1).strip(),
                        "hash_type": match.group(2).strip(),
                        "password": match.group(3).strip(),
                    })
        except Exception as e:
            errors.append(str(e)[:200])

        return JohnResult(
            hash_file=hash_file, hash_type="", mode="show",
            cracked=cracked, total_hashes=0, cracked_count=len(cracked),
            execution_time_seconds=(datetime.now() - start_time).total_seconds(),
            tool_version=self.get_version(),
            raw_output=raw_output,
            errors=errors
        )

    def _parse_pot_file(self, pot_path: str) -> list[dict[str, Any]]:
        """Parse a John the Ripper pot file for cracked passwords.

        Pot file formats handled:
        - Raw hashes (MD5, SHA1, etc.): $dynamic_0$<hash>:<password>  (2 parts)
        - NTLM: username:RID:LM:NThash:::password  (many parts)
        - bcrypt: $2a$...$hash:password  (2 parts)
        - Generic $type$hash:password  (2 parts)
        """
        cracked = []
        try:
            with open(pot_path) as f:
                pot_data = f.read()
            for line in pot_data.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                if len(parts) >= 2:
                    # Two-part format: $type$hash:password
                    password = parts[-1]  # Last part is always the password
                    hash_part = ':'.join(parts[:-1])  # Everything before is the hash
                    if password and not password.startswith('$'):
                        cracked.append({
                            "hash": hash_part[:80],
                            "password": password.replace('\\', ''),
                            "source": "pot",
                        })
        except Exception:
            pass
        return cracked

    def generate_hash(self, password: str, hash_type: str = 'raw-md5') -> str:
        """Generate a hash from a password for testing purposes."""
        import hashlib
        password_bytes = password.encode('utf-8')

        if hash_type == 'raw-md5':
            return hashlib.md5(password_bytes).hexdigest()
        elif hash_type == 'raw-sha1':
            return hashlib.sha1(password_bytes).hexdigest()
        elif hash_type == 'raw-sha256':
            return hashlib.sha256(password_bytes).hexdigest()
        elif hash_type == 'raw-sha512':
            return hashlib.sha512(password_bytes).hexdigest()
        elif hash_type == 'nt':
            # NTLM hash
            return hashlib.new('md4', password_bytes).hexdigest().upper()
        else:
            return hashlib.md5(password_bytes).hexdigest()

    def get_capabilities(self) -> dict[str, Any]:
        """Return tool capabilities for tool discovery"""
        return {
            'name': self.name,
            'version': self.get_version(),
            'available': self.is_available(),
            'supported_formats': self.supported_formats,
            'features': [
                'hash_cracking',
                'wordlist_mode',
                'single_crack_mode',
                'incremental_mode',
                'markov_mode',
                'rule_based_attacks',
                'hash_detection',
                'hash_generation',
            ],
            'parameters': {
                'hashes': {'required': True, 'description': 'Hash string or list of hashes'},
                'hash_type': {'required': False, 'default': 'auto', 'description': 'Hash format (auto-detect if not specified)'},
                'mode': {'required': False, 'default': 'wordlist', 'options': ['wordlist', 'single', 'incremental', 'markov'],
                        'description': 'Cracking mode'},
                'wordlist': {'required': False, 'description': 'Path to wordlist file'},
                'rules': {'required': False, 'default': True, 'description': 'Apply word-mangling rules'},
            },
            'owasp_mapping': {
                'A02': 'Broken Authentication - weak password cracking',
                'A07': 'Identification and Authentication Failures - credential cracking',
                'A05': 'Security Misconfiguration - default/weak hash algorithms',
            }
        }


# Global instance for tool registry
_john_tool: JohnTool | None = None


def get_john_tool() -> JohnTool:
    """Get or create global john tool instance"""
    global _john_tool
    if _john_tool is None:
        _john_tool = JohnTool()
    return _john_tool
