"""Terminal Execution Workspace — V3.

Provides a *local* terminal execution environment for:

* Repository indexing
* Documentation processing
* File organization
* Dependency analysis
* Report generation
* Diagram generation

Every command run is recorded in an ``AUDIT_LOG`` with the structure
required by the V3 spec::

    timestamp
    agent
    command
    result
    reason

The workspace is *sandboxed*:

* Commands are executed inside a project workspace root (``cwd``).
* An optional command whitelist prevents arbitrary shell execution.
* A configurable timeout prevents runaway processes.
* Output is truncated to a safe size to keep memory bounded.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


# Commands that are always allowed. Anything not in this list is rejected
# unless ``allow_any=True`` is passed (used by trusted internal workflows).
DEFAULT_ALLOWLIST: tuple[str, ...] = (
    # File / repo inspection
    "ls", "dir", "pwd", "cat", "type", "head", "tail", "wc",
    "find", "grep", "findstr", "rg",
    "tree", "stat",
    # Indexing helpers
    "ctags", "git", "svn", "hg",
    # Reports / diagrams
    "dot", "mmdc", "pandoc", "wkhtmltopdf",
    # Build / dependency
    "npm", "pnpm", "yarn", "bun",
    "pip", "pip3", "poetry", "uv", "pip-compile",
    "go", "cargo", "mvn", "gradle", "dotnet",
    # Languages
    "python", "python3", "py", "node", "deno", "ruby", "php", "java",
    # Test runners (read-only)
    "pytest", "jest", "vitest", "mocha", "go test",
    # Security tooling (read-only by default)
    "nmap", "nikto", "whatweb", "testssl", "sslyze",
    "bandit", "semgrep", "trivy", "grype", "syft", "cyclonedx",
    "gitleaks", "trufflehog", "detect-secrets",
)


@dataclass
class AuditEntry:
    """A single line in the AUDIT_LOG."""

    timestamp: str
    agent: str
    command: str
    result: str  # ok | error | rejected
    reason: str = ""
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    duration_ms: int = 0
    entry_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_log_line(self) -> str:
        """One-line representation for appending to a log file."""
        return (
            f"[{self.timestamp}] agent={self.agent} result={self.result} "
            f"duration={self.duration_ms}ms :: {self.command}"
            + (f" :: reason={self.reason}" if self.reason else "")
        )


@dataclass
class TerminalResult:
    """Result of a single command execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    audit: AuditEntry


class TerminalWorkspace:
    """Audit-logged, sandboxed terminal executor."""

    def __init__(
        self,
        workspace_root: Path,
        audit_log_path: Path | None = None,
        *,
        allowlist: tuple[str, ...] | None = None,
        default_timeout_s: int = 60,
        max_output_chars: int = 16_000,
        allow_any: bool = False,
    ):
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)

        self.audit_log_path = audit_log_path or (
            self.workspace_root / "logs" / "audit.log"
        )
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        self.allowlist = tuple(allowlist) if allowlist else DEFAULT_ALLOWLIST
        self.default_timeout_s = default_timeout_s
        self.max_output_chars = max_output_chars
        self.allow_any = allow_any
        self._entries: list[AuditEntry] = []

    # ---- audit log --------------------------------------------------------

    def _append_log(self, entry: AuditEntry) -> None:
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(entry.to_log_line() + "\n")

    def get_audit_log(self, limit: int | None = None) -> list[AuditEntry]:
        if limit is None:
            return list(self._entries)
        return list(self._entries[-limit:])

    def get_audit_log_path(self) -> Path:
        return self.audit_log_path

    # ---- validation -------------------------------------------------------

    def _is_allowed(self, command: str) -> tuple[bool, str]:
        """Return (allowed, reason)."""
        if self.allow_any:
            return True, ""
        try:
            tokens = shlex.split(command, posix=(os.name != "nt"))
        except ValueError as e:
            return False, f"could not parse command: {e}"
        if not tokens:
            return False, "empty command"
        head = tokens[0]
        # Strip quotes/path for matching
        head_base = os.path.basename(head).lower()
        for allowed in self.allowlist:
            if head_base == allowed.lower():
                return True, ""
            if head_base == allowed.lower().split("/")[-1]:
                return True, ""
        return False, f"command '{head_base}' is not in the allow-list"

    # ---- execution --------------------------------------------------------

    async def execute(
        self,
        command: str,
        *,
        agent: str = "system",
        reason: str = "",
        timeout_s: int | None = None,
        cwd: Path | str | None = None,
    ) -> TerminalResult:
        """Run a single command, audit it, and return the result."""
        allowed, denial = self._is_allowed(command)
        ts = datetime.utcnow().isoformat()
        entry_id = str(uuid.uuid4())

        if not allowed:
            entry = AuditEntry(
                timestamp=ts,
                agent=agent,
                command=command,
                result="rejected",
                reason=denial,
                entry_id=entry_id,
            )
            self._entries.append(entry)
            self._append_log(entry)
            logger.warning("terminal_command_rejected", agent=agent, command=command, reason=denial)
            return TerminalResult(False, -1, "", denial, 0, entry)

        work_dir = Path(cwd) if cwd else self.workspace_root
        try:
            work_dir = work_dir.resolve()
            workspace_root = self.workspace_root.resolve()
            if not str(work_dir).startswith(str(workspace_root)):
                # CWD escape attempt — clamp to workspace
                work_dir = workspace_root
        except OSError:
            work_dir = self.workspace_root

        timeout = timeout_s if timeout_s is not None else self.default_timeout_s
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(work_dir),
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                stdout_b, stderr_b = b"", b"[timeout]"
                rc = -1
                result = "error"
                reason_txt = f"timed out after {timeout}s"
            else:
                rc = proc.returncode or 0
                result = "ok" if rc == 0 else "error"
                reason_txt = reason or ("" if rc == 0 else f"exit code {rc}")
        except Exception as e:  # pragma: no cover - defensive
            rc = -1
            stdout_b = b""
            stderr_b = str(e).encode("utf-8", "replace")
            result = "error"
            reason_txt = f"execution failed: {e}"

        duration = int((time.time() - start) * 1000)
        stdout = (stdout_b or b"").decode("utf-8", "replace")[: self.max_output_chars]
        stderr = (stderr_b or b"").decode("utf-8", "replace")[: self.max_output_chars]

        entry = AuditEntry(
            timestamp=ts,
            agent=agent,
            command=command,
            result=result,
            reason=reason_txt,
            exit_code=rc,
            stdout_excerpt=stdout[-500:],
            stderr_excerpt=stderr[-500:],
            duration_ms=duration,
            entry_id=entry_id,
        )
        self._entries.append(entry)
        self._append_log(entry)
        logger.info(
            "terminal_command_run",
            agent=agent,
            command=command,
            result=result,
            duration_ms=duration,
        )
        return TerminalResult(rc == 0, rc, stdout, stderr, duration, entry)


# Per-project registry so server.py can look up the right workspace.
class TerminalRegistry:
    def __init__(self) -> None:
        self._by_project: dict[str, TerminalWorkspace] = {}

    def get_or_create(
        self,
        project_id: str,
        workspace_root: Path,
        **kwargs: Any,
    ) -> TerminalWorkspace:
        if project_id not in self._by_project:
            self._by_project[project_id] = TerminalWorkspace(workspace_root, **kwargs)
        return self._by_project[project_id]

    def get(self, project_id: str) -> TerminalWorkspace | None:
        return self._by_project.get(project_id)

    def remove(self, project_id: str) -> None:
        self._by_project.pop(project_id, None)
