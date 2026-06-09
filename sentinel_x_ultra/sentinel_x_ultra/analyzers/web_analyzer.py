"""Web Analyzer - Web crawling and vulnerability scanning."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class VulnerabilityType(str, Enum):
    """Types of web vulnerabilities."""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    CSRF = "csrf"
    IDOR = "idor"
    SSRF = "ssrf"
    INFORMATION_DISCLOSURE = "info_disclosure"
    MISSING_AUTH = "missing_auth"
    WEAK_TLS = "weak_tls"
    OPEN_REDIRECT = "open_redirect"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Parameter:
    """An HTTP parameter."""
    name: str
    param_type: str  # query | body | header | cookie | path
    value: str = ""
    is_sensitive: bool = False


@dataclass
class EndpointInfo:
    """Information about a discovered API endpoint."""
    id: str
    method: str  # GET, POST, PUT, DELETE, etc.
    path: str
    summary: str = ""
    parameters: list[Parameter] = field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = field(default_factory=dict)
    auth_required: bool = False
    auth_type: str = ""  # bearer, basic, cookie, etc.
    is_secure: bool = True
    issues: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "summary": self.summary,
            "parameters": [
                {"name": p.name, "param_type": p.param_type, "value": p.value, "is_sensitive": p.is_sensitive}
                for p in self.parameters
            ],
            "request_body": self.request_body,
            "responses": self.responses,
            "auth_required": self.auth_required,
            "auth_type": self.auth_type,
            "is_secure": self.is_secure,
            "issues": self.issues,
            "created_at": self.created_at,
        }


@dataclass
class Vulnerability:
    """A discovered web vulnerability."""
    id: str
    vuln_type: VulnerabilityType
    severity: Severity
    endpoint: str
    method: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    poc: str = ""  # Proof of concept
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "high"  # high | medium | low
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value if isinstance(self.vuln_type, VulnerabilityType) else self.vuln_type,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "evidence": self.evidence,
            "poc": self.poc,
            "remediation": self.remediation,
            "references": self.references,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }


@dataclass
class CrawlResult:
    """Result of web crawling."""
    id: str
    base_url: str
    endpoints: list[EndpointInfo]
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    sitemap: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "base_url": self.base_url,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": self.forms,
            "links": self.links,
            "technologies": self.technologies,
            "sitemap": self.sitemap,
            "created_at": self.created_at,
        }


# Vulnerability detection rules
VULNERABILITY_RULES = [
    {
        "name": "Reflected XSS",
        "type": VulnerabilityType.XSS,
        "severity": Severity.HIGH,
        "patterns": [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"alert\\(",
        ],
        "test_payloads": [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
        ],
    },
    {
        "name": "SQL Injection",
        "type": VulnerabilityType.SQL_INJECTION,
        "severity": Severity.CRITICAL,
        "patterns": [
            r"error",
            r"sql",
            r"syntax",
            r"mysql",
            r"postgres",
        ],
        "test_payloads": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND '1'='1",
        ],
    },
    {
        "name": "IDOR",
        "type": VulnerabilityType.IDOR,
        "severity": Severity.HIGH,
        "patterns": [
            r"/user/",
            r"/profile/",
            r"/order/",
            r"/id=",
            r"/\\d+",
        ],
        "test_payloads": [
            "/user/1",
            "/profile/123",
        ],
    },
]


class WebAnalyzer:
    """Web application security analyzer."""

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or str(uuid.uuid4())
        self._endpoints: list[EndpointInfo] = []
        self._vulnerabilities: list[Vulnerability] = []
        self._crawl_results: list[CrawlResult] = []

        logger.info("web_analyzer_initialized", project_id=self.project_id)

    # ============ Endpoint Discovery ============

    def add_endpoint(
        self,
        method: str,
        path: str,
        parameters: list[Parameter] | None = None,
        auth_required: bool = False,
        **kwargs,
    ) -> str:
        """Add a discovered endpoint."""
        endpoint = EndpointInfo(
            id=str(uuid.uuid4()),
            method=method.upper(),
            path=path,
            parameters=parameters or [],
            auth_required=auth_required,
            **kwargs,
        )

        self._endpoints.append(endpoint)
        return endpoint.id

    def get_endpoints(
        self,
        method: str | None = None,
        auth_required: bool | None = None,
    ) -> list[EndpointInfo]:
        """Get endpoints, optionally filtered."""
        results = self._endpoints

        if method:
            results = [e for e in results if e.method == method.upper()]
        if auth_required is not None:
            results = [e for e in results if e.auth_required == auth_required]

        return results

    # ============ Vulnerability Detection ============

    def analyze_endpoint(self, endpoint: EndpointInfo) -> list[Vulnerability]:
        """Analyze an endpoint for vulnerabilities."""
        vulns = []

        for rule in VULNERABILITY_RULES:
            vuln = self._check_vulnerability_rule(endpoint, rule)
            if vuln:
                vulns.append(vuln)
                self._vulnerabilities.append(vuln)

        logger.info("endpoint_analyzed", path=endpoint.path, vulns=len(vulns))
        return vulns

    def _check_vulnerability_rule(
        self,
        endpoint: EndpointInfo,
        rule: dict[str, Any],
    ) -> Vulnerability | None:
        """Check if an endpoint matches a vulnerability rule."""
        path_lower = endpoint.path.lower()

        # Check if path matches vulnerability patterns
        for pattern in rule.get("patterns", []):
            if pattern.lower() in path_lower:
                return Vulnerability(
                    id=str(uuid.uuid4()),
                    vuln_type=rule["type"],
                    severity=rule["severity"],
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=f"Potential {rule['name']} in endpoint {endpoint.path}",
                    evidence={"matched_pattern": pattern},
                    poc=f"Test with: {rule['test_payloads'][0]}",
                    remediation=self._get_remediation(rule["type"]),
                    references=self._get_vuln_references(rule["type"]),
                )

        # Check for missing authentication on sensitive endpoints
        sensitive_patterns = [
            "/admin", "/user", "/profile", "/account", "/settings",
            "/api/v1/", "/upload", "/download", "/export",
        ]

        if not endpoint.auth_required:
            for pattern in sensitive_patterns:
                if pattern in path_lower:
                    return Vulnerability(
                        id=str(uuid.uuid4()),
                        vuln_type=VulnerabilityType.MISSING_AUTH,
                        severity=Severity.HIGH,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        description=f"Sensitive endpoint {endpoint.path} does not require authentication",
                        evidence={"path": endpoint.path},
                        remediation="Add authentication requirement to this endpoint",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    )

        return None

    def _get_remediation(self, vuln_type: VulnerabilityType) -> str:
        """Get remediation advice for a vulnerability type."""
        remediations = {
            VulnerabilityType.XSS: "Implement input validation and output encoding. Use Content-Security-Policy headers.",
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
            VulnerabilityType.CSRF: "Implement anti-CSRF tokens. Use SameSite cookies. Check Origin/Referer headers.",
            VulnerabilityType.IDOR: "Implement proper authorization checks. Validate user owns requested resource.",
            VulnerabilityType.SSRF: "Validate and sanitize URLs. Use allowlists for permitted destinations.",
            VulnerabilityType.INFORMATION_DISCLOSURE: "Remove debug information from production. Configure error handlers.",
            VulnerabilityType.MISSING_AUTH: "Add authentication requirements for sensitive endpoints.",
            VulnerabilityType.WEAK_TLS: "Disable older TLS versions. Enforce HTTPS. Use modern cipher suites.",
            VulnerabilityType.OPEN_REDIRECT: "Validate redirect URLs against allowlists. Never follow unvalidated redirects.",
        }
        return remediations.get(vuln_type, "Review and fix this vulnerability.")

    def _get_vuln_references(self, vuln_type: VulnerabilityType) -> list[str]:
        """Get reference links for a vulnerability type."""
        references = {
            VulnerabilityType.XSS: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting",
            ],
            VulnerabilityType.SQL_INJECTION: [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection",
            ],
            VulnerabilityType.IDOR: [
                "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
                "https://portswigger.net/web-security/access-control/idor",
            ],
        }
        return references.get(vuln_type, ["https://owasp.org/www-project-top-ten/"])

    # ============ Vulnerability Analysis ============

    def get_all_vulnerabilities(
        self,
        severity: Severity | None = None,
        vuln_type: VulnerabilityType | None = None,
    ) -> list[Vulnerability]:
        """Get all vulnerabilities, optionally filtered."""
        results = self._vulnerabilities

        if severity:
            results = [v for v in results if v.severity == severity]
        if vuln_type:
            results = [v for v in results if v.vuln_type == vuln_type]

        return results

    def get_vulnerability_summary(self) -> dict[str, Any]:
        """Get a summary of discovered vulnerabilities."""
        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

        for vuln in self._vulnerabilities:
            severity_str = vuln.severity.value if isinstance(vuln.severity, Severity) else vuln.severity
            if severity_str in by_severity:
                by_severity[severity_str] += 1

        return {
            "total": len(self._vulnerabilities),
            "by_severity": by_severity,
            "by_type": {
                "xss": len([v for v in self._vulnerabilities if v.vuln_type == VulnerabilityType.XSS]),
                "sql_injection": len([v for v in self._vulnerabilities if v.vuln_type == VulnerabilityType.SQL_INJECTION]),
                "idor": len([v for v in self._vulnerabilities if v.vuln_type == VulnerabilityType.IDOR]),
                "missing_auth": len([v for v in self._vulnerabilities if v.vuln_type == VulnerabilityType.MISSING_AUTH]),
                "other": len([v for v in self._vulnerabilities if v.vuln_type not in [
                    VulnerabilityType.XSS, VulnerabilityType.SQL_INJECTION,
                    VulnerabilityType.IDOR, VulnerabilityType.MISSING_AUTH
                ]]),
            },
        }

    # ============ Crawl Results ============

    def add_crawl_result(self, crawl_result: CrawlResult):
        """Add a crawl result."""
        self._crawl_results.append(crawl_result)

    def get_latest_crawl(self) -> CrawlResult | None:
        """Get the most recent crawl result."""
        return self._crawl_results[-1] if self._crawl_results else None

    # ============ Serialization ============

    def to_dict(self) -> dict[str, Any]:
        """Export analyzer results to dictionary."""
        return {
            "project_id": self.project_id,
            "endpoints": [e.to_dict() for e in self._endpoints],
            "vulnerabilities": [v.to_dict() for v in self._vulnerabilities],
            "crawl_results": [c.to_dict() for c in self._crawl_results],
            "summary": self.get_vulnerability_summary(),
        }

    def clear(self):
        """Clear all analysis results."""
        self._endpoints.clear()
        self._vulnerabilities.clear()
        self._crawl_results.clear()
        logger.info("web_analyzer_cleared")