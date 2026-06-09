"""Code Analyzer - SAST with security pattern matching and data flow analysis."""

from __future__ import annotations

import uuid
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CWE(str, Enum):
    """Common Weakness Enumeration."""
    SQL_INJECTION = "CWE-89"
    XSS = "CWE-79"
    PATH_TRAVERSAL = "CWE-22"
    COMMAND_INJECTION = "CWE-78"
    DESERIALIZATION = "CWE-502"
    AUTH_BYPASS = "CWE-287"
    WEAK_CRYPTO = "CWE-327"
    HARDCODE_SECRET = "CWE-798"
    SSRF = "CWE-918"
    CSRF = "CWE-352"


@dataclass
class SecurityPattern:
    """A detected security pattern/vulnerability."""
    id: str
    name: str
    cwe: CWE
    severity: Severity
    description: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    matched_pattern: str
    confidence: str = "high"  # high | medium | low
    false_positive_risk: str = "low"  # high | medium | low
    references: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "cwe": self.cwe.value if isinstance(self.cwe, CWE) else self.cwe,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "matched_pattern": self.matched_pattern,
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
            "references": self.references,
            "created_at": self.created_at,
        }


@dataclass
class DataFlowNode:
    """A node in data flow analysis."""
    id: str
    node_type: str  # source | sanitization | sink
    file_path: str
    line: int
    expression: str
    tainted: bool = False
    sanitizer: str = ""
    sources: list[str] = field(default_factory=list)


@dataclass
class DataFlowAnalysis:
    """Result of data flow analysis."""
    id: str
    source: DataFlowNode
    sink: DataFlowNode
    path: list[DataFlowNode]
    sanitizers: list[str] = field(default_factory=list)
    is_safe: bool = False
    vulnerability_type: str = ""
    severity: Severity = Severity.MEDIUM
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": {
                "id": self.source.id,
                "node_type": self.source.node_type,
                "file_path": self.source.file_path,
                "line": self.source.line,
                "expression": self.source.expression,
                "tainted": self.source.tainted,
            },
            "sink": {
                "id": self.sink.id,
                "node_type": self.sink.node_type,
                "file_path": self.sink.file_path,
                "line": self.sink.line,
                "expression": self.sink.expression,
            },
            "path": [{"id": n.id, "line": n.line, "expression": n.expression} for n in self.path],
            "sanitizers": self.sanitizers,
            "is_safe": self.is_safe,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "created_at": self.created_at,
        }


@dataclass
class AuthFlowStep:
    """A step in authentication/authorization flow."""
    id: str
    step_type: str  # login | verify | authorize | token | session
    component: str
    file_path: str
    line: int
    description: str
    is_secure: bool = True
    issues: list[str] = field(default_factory=list)


@dataclass
class AuthFlowAnalysis:
    """Result of authentication/authorization flow analysis."""
    id: str
    flow_type: str  # authentication | authorization | session
    steps: list[AuthFlowStep]
    is_secure: bool = True
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "flow_type": self.flow_type,
            "steps": [
                {"id": s.id, "step_type": s.step_type, "component": s.component,
                 "file_path": s.file_path, "line": s.line, "description": s.description,
                 "is_secure": s.is_secure, "issues": s.issues}
                for s in self.steps
            ],
            "is_secure": self.is_secure,
            "issues": self.issues,
            "recommendations": self.recommendations,
            "created_at": self.created_at,
        }


# Security patterns for detection
SECURITY_PATTERNS = [
    {
        "name": "SQL Injection",
        "cwe": CWE.SQL_INJECTION,
        "severity": Severity.CRITICAL,
        "patterns": [
            r'execute.*["\"]SELECT.*%s',  # Python string formatting in SQL
            r'execute.*["\"]INSERT.*%s',
            r'"\\_.*\\+\\s*["\"]SELECT',  # String concat in SQL
            r'f"SELECT.*{',  # f-string in SQL
            r'query.*interpolation',
            r'cursor\\.execute.*\\+',  # String concat in execute
        ],
        "sanitizers": ["escape", "sanitize", "param", "bind", "prepared"],
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "cwe": CWE.XSS,
        "severity": Severity.HIGH,
        "patterns": [
            r'innerHTML\\s*=',
            r'dangerouslySetInnerHTML',
            r'\\.html\\(\\)',
            r'eval\\(',
            r'document\\.write',
            r'\\.append\\(',
            r'template.*\\.format',
        ],
        "sanitizers": ["escape", "sanitize", "textContent", "innerText", "DOMPurify"],
    },
    {
        "name": "Path Traversal",
        "cwe": CWE.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "patterns": [
            r'open\\(.*\\+',
            r'os\\.path\\.join.*\\+',
            r'FileInputStream.*\\+',
            r'ReadAllBytes.*\\+',
            r'\\.resolve\\(',
            r'\\.normalize\\(',
        ],
        "sanitizers": ["basename", "realpath", "abspath"],
    },
    {
        "name": "Command Injection",
        "cwe": CWE.COMMAND_INJECTION,
        "severity": Severity.CRITICAL,
        "patterns": [
            r'os\\.system',
            r'subprocess.*shell\\s*=\\s*True',
            r'exec\\(',
            r'eval\\(',
            r'child_process',
            r'Runtime\\.getRuntime\\(\\)\\.exec',
        ],
        "sanitizers": ["shlex", "escape", "sanitize"],
    },
    {
        "name": "Hardcoded Secret",
        "cwe": CWE.HARDCODE_SECRET,
        "severity": Severity.HIGH,
        "patterns": [
            r'api[_-]?key\\s*=\\s*["\"][a-zA-Z0-9]{20,}',
            r'secret\\s*=\\s*["\"][a-zA-Z0-9]{20,}',
            r'password\\s*=\\s*["\"]',
            r'token\\s*=\\s*["\"][a-zA-Z0-9]{20,}',
            r'aws[_-]?access[_-]?key',
            r'private[_-]?key\\s*=\\s*"',
        ],
        "sanitizers": [],
    },
    {
        "name": "Weak Cryptography",
        "cwe": CWE.WEAK_CRYPTO,
        "severity": Severity.MEDIUM,
        "patterns": [
            r'md5',
            r'sha1',
            r'DES\\(',
            r'RC4',
            r'Crypto\\.Cipher\\.DES',
            r'\\.createCipher',
        ],
        "sanitizers": ["AES", "RSA", "sha256", "sha512"],
    },
]


class CodeAnalyzer:
    """Static Application Security Testing (SAST) analyzer."""

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or str(uuid.uuid4())
        self._patterns: list[SecurityPattern] = []
        self._data_flows: list[DataFlowAnalysis] = []
        self._auth_flows: list[AuthFlowAnalysis] = []

        logger.info("code_analyzer_initialized", project_id=self.project_id)

    # ============ Pattern Detection ============

    def analyze_file(self, file_path: str, content: str, language: str | None = None) -> list[SecurityPattern]:
        """Analyze a source file for security patterns."""
        patterns = []

        for pattern_def in SECURITY_PATTERNS:
            matches = self._search_patterns(content, pattern_def["patterns"])

            for match in matches:
                pattern = self._create_pattern(
                    file_path=file_path,
                    content=content,
                    match=match,
                    pattern_def=pattern_def,
                )
                if pattern:
                    patterns.append(pattern)
                    self._patterns.append(pattern)

        logger.info("file_analyzed", file=file_path, patterns=len(patterns))
        return patterns

    def _search_patterns(self, content: str, patterns: list[str]) -> list[re.Match]:
        """Search for pattern matches in content."""
        matches = []
        lines = content.split("\n")

        for i, line in enumerate(lines):
            for pattern in patterns:
                try:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        matches.append(match)
                except re.error:
                    continue

        return matches

    def _create_pattern(
        self,
        file_path: str,
        content: str,
        match: re.Match,
        pattern_def: dict[str, Any],
    ) -> SecurityPattern | None:
        """Create a SecurityPattern from a match."""
        lines = content.split("\n")

        # Find line number
        line_num = 0
        for i, line in enumerate(lines):
            if match.group() in line:
                line_num = i + 1
                break

        # Get surrounding context (5 lines before and after)
        start_line = max(0, line_num - 6)
        end_line = min(len(lines), line_num + 5)
        context = "\n".join(lines[start_line:end_line])

        # Check for false positive mitigation
        is_likely_fp = self._check_false_positive(pattern_def, lines[line_num - 1] if line_num <= len(lines) else "")

        if is_likely_fp:
            confidence = "low"
            false_positive_risk = "high"
        else:
            confidence = "high"
            false_positive_risk = "low"

        return SecurityPattern(
            id=str(uuid.uuid4()),
            name=pattern_def["name"],
            cwe=pattern_def["cwe"],
            severity=pattern_def["severity"],
            description=self._generate_description(pattern_def["name"]),
            file_path=file_path,
            line_start=line_num,
            line_end=line_num,
            code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
            matched_pattern=match.group(),
            confidence=confidence,
            false_positive_risk=false_positive_risk,
            references=self._get_references(pattern_def["cwe"]),
        )

    def _check_false_positive(self, pattern_def: dict[str, Any], matched_line: str) -> bool:
        """Check if a match is likely a false positive."""
        matched_line_lower = matched_line.lower()

        # Check for sanitizers
        for sanitizer in pattern_def.get("sanitizers", []):
            if sanitizer.lower() in matched_line_lower:
                return True  # Likely sanitized

        # Check for test code
        if "test" in matched_line_lower or "mock" in matched_line_lower:
            return True

        # Check for example code
        if "example" in matched_line_lower or "# sample" in matched_line_lower:
            return True

        return False

    def _generate_description(self, pattern_name: str) -> str:
        """Generate a description for a pattern."""
        descriptions = {
            "SQL Injection": "User-controlled data is concatenated into SQL query, allowing attackers to modify query intent.",
            "Cross-Site Scripting (XSS)": "User input is inserted into HTML/JavaScript without proper sanitization, enabling script injection.",
            "Path Traversal": "File path is constructed from user input without validation, allowing access to unintended files.",
            "Command Injection": "User input is passed to system command execution without sanitization, allowing arbitrary command execution.",
            "Hardcoded Secret": "Sensitive credentials or API keys are hardcoded in source code, risking exposure.",
            "Weak Cryptography": "Insecure cryptographic algorithm (MD5, SHA1, DES) is used, risking data compromise.",
        }
        return descriptions.get(pattern_name, f"Potential {pattern_name} vulnerability detected.")

    def _get_references(self, cwe: CWE) -> list[str]:
        """Get reference links for a CWE."""
        references = {
            CWE.SQL_INJECTION: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
            CWE.XSS: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            CWE.PATH_TRAVERSAL: [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
            ],
            CWE.COMMAND_INJECTION: [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
            CWE.HARDCODE_SECRET: [
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            CWE.WEAK_CRYPTO: [
                "https://owasp.org/www-project-cheat-sheets/cheats-sheets/Cryptographic_Storage_Cheat_Sheet",
                "https://cwe.mitre.org/data/definitions/327.html",
            ],
        }
        return references.get(cwe, [])

    # ============ Data Flow Analysis ============

    def analyze_data_flow(self, file_path: str, content: str) -> list[DataFlowAnalysis]:
        """Perform data flow analysis to find taint propagation."""
        flows = []

        # Find user input sources
        sources = self._find_taint_sources(content)

        # Find sensitive sinks
        sinks = self._find_sensitive_sinks(content)

        # For each source-sink pair, trace the flow
        for source in sources:
            for sink in sinks:
                flow = self._trace_data_flow(file_path, content, source, sink)
                if flow and not flow.is_safe:
                    flows.append(flow)
                    self._data_flows.append(flow)

        logger.info("data_flow_analyzed", file=file_path, flows=len(flows))
        return flows

    def _find_taint_sources(self, content: str) -> list[DataFlowNode]:
        """Find sources of user-controlled data."""
        sources = []
        taint_patterns = [
            (r'request\\.args', "query_params"),
            (r'request\\.form', "form_data"),
            (r'request\\.json', "json_body"),
            (r'input\\(', "stdin"),
            (r'req\\.body', "request_body"),
            (r'REQUEST', "http_request"),
            (r'\\.get\\(["\"]', "dict_get"),
        ]

        lines = content.split("\n")
        for i, line in enumerate(lines):
            for pattern, source_type in taint_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sources.append(DataFlowNode(
                        id=str(uuid.uuid4()),
                        node_type="source",
                        file_path="",
                        line=i + 1,
                        expression=line.strip(),
                        tainted=True,
                        sources=[source_type],
                    ))

        return sources

    def _find_sensitive_sinks(self, content: str) -> list[DataFlowNode]:
        """Find sensitive sinks (where data reaches)."""
        sinks = []
        sink_patterns = [
            (r'execute\\(', "database_query"),
            (r'eval\\(', "code_execution"),
            (r'system\\(', "system_command"),
            (r'open\\(.*,\\s*["\"]w', "file_write"),
            (r'\\.format\\(.*\\)', "string_format"),
            (r'\\.query\\(', "database_query"),
            (r'\\.innerHTML', "dom_output"),
        ]

        lines = content.split("\n")
        for i, line in enumerate(lines):
            for pattern, sink_type in sink_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    sinks.append(DataFlowNode(
                        id=str(uuid.uuid4()),
                        node_type="sink",
                        file_path="",
                        line=i + 1,
                        expression=line.strip(),
                        tainted=True,
                    ))

        return sinks

    def _trace_data_flow(
        self,
        file_path: str,
        content: str,
        source: DataFlowNode,
        sink: DataFlowNode,
    ) -> DataFlowAnalysis | None:
        """Trace data flow from source to sink."""
        lines = content.split("\n")

        # Find the source and sink lines in the file
        source_line_idx = source.line - 1
        sink_line_idx = sink.line - 1

        if source_line_idx < 0 or sink_line_idx < 0:
            return None

        # Check if there's any sanitization between source and sink
        path_lines = lines[source_line_idx:sink_line_idx + 1]
        sanitizers_found = []

        for line in path_lines:
            if any(s in line.lower() for s in ["escape", "sanitize", "encode", "validate"]):
                sanitizers_found.append(line.strip())

        # If sanitizers found and seem effective, mark as safe
        is_safe = len(sanitizers_found) > 0

        return DataFlowAnalysis(
            id=str(uuid.uuid4()),
            source=source,
            sink=sink,
            path=[],
            sanitizers=sanitizers_found,
            is_safe=is_safe,
            vulnerability_type="tainted_input" if not is_safe else "none",
        )

    # ============ Auth Flow Analysis ============

    def analyze_auth_flow(self, file_path: str, content: str) -> AuthFlowAnalysis:
        """Analyze authentication and authorization flows."""
        steps = []
        issues = []

        lines = content.split("\n")

        for i, line in enumerate(lines):
            line_lower = line.lower()

            # Detect login/authentication
            if any(kw in line_lower for kw in ["login", "authenticate", "sign_in", "credential"]):
                step = self._analyze_auth_step(
                    file_path=file_path,
                    line_num=i + 1,
                    content=line,
                    step_type="login",
                )
                steps.append(step)
                if not step.is_secure:
                    issues.extend(step.issues)

            # Detect authorization checks
            if any(kw in line_lower for kw in ["authorize", "permission", "role", "access"]):
                step = self._analyze_auth_step(
                    file_path=file_path,
                    line_num=i + 1,
                    content=line,
                    step_type="authorize",
                )
                steps.append(step)
                if not step.is_secure:
                    issues.extend(step.issues)

            # Detect token handling
            if any(kw in line_lower for kw in ["token", "jwt", "session", "cookie"]):
                step = self._analyze_auth_step(
                    file_path=file_path,
                    line_num=i + 1,
                    content=line,
                    step_type="token",
                )
                steps.append(step)
                if not step.is_secure:
                    issues.extend(step.issues)

        analysis = AuthFlowAnalysis(
            id=str(uuid.uuid4()),
            flow_type="authentication" if any(s.step_type == "login" for s in steps) else "mixed",
            steps=steps,
            is_secure=len([s for s in steps if not s.is_secure]) == 0,
            issues=issues,
            recommendations=self._generate_auth_recommendations(issues),
        )

        self._auth_flows.append(analysis)
        return analysis

    def _analyze_auth_step(
        self,
        file_path: str,
        line_num: int,
        content: str,
        step_type: str,
    ) -> AuthFlowStep:
        """Analyze a single authentication/authorization step."""
        issues = []
        is_secure = True

        content_lower = content.lower()

        # Check for weak password handling
        if step_type == "login":
            if "plaintext" in content_lower or "not hashed" in content_lower:
                issues.append("Password may be stored/transmitted without hashing")
                is_secure = False

        # Check for missing authorization
        if step_type == "authorize":
            if "if" not in content_lower and "check" not in content_lower:
                issues.append("No visible authorization check")
                is_secure = False

        # Check for weak token handling
        if step_type == "token":
            if "decode" in content_lower and "verify" not in content_lower:
                issues.append("Token decoded but not verified")
                is_secure = False
            if "secret" in content_lower and "env" not in content_lower:
                issues.append("Secret may be hardcoded rather than from environment")

        return AuthFlowStep(
            id=str(uuid.uuid4()),
            step_type=step_type,
            component=file_path,
            file_path=file_path,
            line=line_num,
            description=content.strip(),
            is_secure=is_secure,
            issues=issues,
        )

    def _generate_auth_recommendations(self, issues: list[str]) -> list[str]:
        """Generate recommendations based on auth issues."""
        recommendations = []

        if any("password" in i.lower() for i in issues):
            recommendations.append("Use strong password hashing (bcrypt, Argon2)")

        if any("token" in i.lower() and "not verify" in i.lower() for i in issues):
            recommendations.append("Always verify JWT tokens with cryptographic signature")

        if any("authorization" in i.lower() and "no visible" in i.lower() for i in issues):
            recommendations.append("Add explicit authorization checks before sensitive operations")

        if not recommendations:
            recommendations.append("Authentication flow appears to follow best practices")

        return recommendations

    # ============ Getters ============

    def get_all_patterns(self) -> list[SecurityPattern]:
        """Get all detected patterns."""
        return self._patterns

    def get_patterns_by_severity(self, severity: Severity) -> list[SecurityPattern]:
        """Get patterns filtered by severity."""
        return [p for p in self._patterns if p.severity == severity]

    def get_patterns_by_cwe(self, cwe: CWE) -> list[SecurityPattern]:
        """Get patterns filtered by CWE."""
        return [p for p in self._patterns if p.cwe == cwe]

    def get_all_data_flows(self) -> list[DataFlowAnalysis]:
        """Get all data flow analyses."""
        return self._data_flows

    def get_all_auth_flows(self) -> list[AuthFlowAnalysis]:
        """Get all auth flow analyses."""
        return self._auth_flows

    # ============ Serialization ============

    def to_dict(self) -> dict[str, Any]:
        """Export analyzer results to dictionary."""
        return {
            "project_id": self.project_id,
            "patterns": [p.to_dict() for p in self._patterns],
            "data_flows": [f.to_dict() for f in self._data_flows],
            "auth_flows": [a.to_dict() for a in self._auth_flows],
        }

    def clear(self):
        """Clear all analysis results."""
        self._patterns.clear()
        self._data_flows.clear()
        self._auth_flows.clear()
        logger.info("code_analyzer_cleared")