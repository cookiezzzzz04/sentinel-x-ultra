"""
SECURITY GUARD — Scope Validation, Output Sanitization, Ethical Guards & Resource Limits (Phase 7).

Provides safety-critical infrastructure for the bug bounty pipeline:
- ScopeValidator: Multi-layer scope validation before any agent action
- OutputSanitizer: Strip PII, secrets, and dangerous content from outputs
- EthicalGuard: Enforce foundational ethical rules at every stage
- ResourceLimiter: Cap resource consumption (findings, targets, API calls)
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── Ethical Rules ───────────────────────────────────────────────────────────

ETHICAL_RULES: list[dict[str, Any]] = [
    {
        "level": 1,
        "priority": "ABSOLUTE",
        "rule": "NEVER test unauthorized targets",
        "description": "Only test targets explicitly authorized by program scope",
    },
    {
        "level": 1,
        "priority": "ABSOLUTE",
        "rule": "NEVER cause service disruption or data loss",
        "description": "All testing must be read-only and non-destructive",
    },
    {
        "level": 1,
        "priority": "ABSOLUTE",
        "rule": "NEVER exfiltrate user data",
        "description": "Do not access, download, or store real user data",
    },
    {
        "level": 2,
        "priority": "MANDATORY",
        "rule": "ALWAYS verify scope before any action",
        "description": "Every target must be scope-checked before testing",
    },
    {
        "level": 2,
        "priority": "MANDATORY",
        "rule": "ALWAYS validate findings before reporting",
        "description": "No finding enters a report without validation",
    },
    {
        "level": 3,
        "priority": "STRICT",
        "rule": "Scope is law — if not in-scope, it's out-of-scope",
        "description": "Default deny: targets without scope evidence are blocked",
    },
    {
        "level": 3,
        "priority": "STRICT",
        "rule": "Quality over quantity — validate every finding",
        "description": "Maximum 3 findings per vulnerability class per project",
    },
    {
        "level": 4,
        "priority": "STANDARD",
        "rule": "Reports must be evidence-based",
        "description": "Every claim in a report must reference specific evidence",
    },
    {
        "level": 5,
        "priority": "GUIDELINE",
        "rule": "Minimize API calls to target infrastructure",
        "description": "Rate-limit requests to avoid service impact",
    },
]


# ── PII & Secret Patterns ───────────────────────────────────────────────────

PII_PATTERNS: list[tuple[str, str]] = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "EMAIL"),
    (r'\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b', "PHONE"),
    (r'\b\d{3}-\d{2}-\d{4}\b', "SSN"),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', "CREDIT_CARD"),
    (r'\b[A-Z]{2}[0-9]{2}(?:[A-Z0-9]){1,30}\b', "IBAN"),
    (r'\b[0-9]{9}\b', "NATIONAL_ID"),  # Generic, high false positive
]

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "API_KEY"),
    (r'(?i)(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36}', "GITHUB_TOKEN"),
    (r'(?i)(?:sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]{10,}', "STRIPE_KEY"),
    (r'(?i)(?:xox[parb]-)[A-Za-z0-9\-]{10,}', "SLACK_TOKEN"),
    (r'(?i)(?:-----BEGIN\s?(?:RSA\s)?PRIVATE\s?KEY-----)', "PRIVATE_KEY"),
    (r'(?i)(?:AKIA[0-9A-Z]{16})', "AWS_ACCESS_KEY"),
    (r'(?i)(?:mongodb\+srv|postgresql|mysql|redis|amqp)://[^\s"]+(?:@)[^\s"]+', "DATABASE_URL"),
]

DANGEROUS_PATTERNS: list[tuple[str, str]] = [
    (r'(?i)(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+)', "DESTRUCTIVE_SQL"),
    (r'(?i)(?:rm\s+-rf|format\s+|mkfs\.)', "DESTRUCTIVE_SHELL"),
    (r'(?i)(?:<script[\s>]|javascript:)', "XSS_PAYLOAD"),
    (r'(?i)(?:\\\\..*\.exe|%00|\\x00)', "BINARY_PAYLOAD"),
]


# ── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class ScopeValidationResult:
    """Result of a scope validation check."""
    allowed: bool = False
    reason: str = ""
    validated_at: str = ""
    validation_level: str = "STRICT"  # STRICT, MODERATE, PERMISSIVE
    matched_rules: list[str] = field(default_factory=list)


@dataclass
class SanitizationResult:
    """Result of sanitizing content."""
    original_length: int = 0
    sanitized_length: int = 0
    items_removed: int = 0
    removed_types: dict[str, int] = field(default_factory=dict)
    sanitized_content: str = ""


@dataclass
class EthicalCheckResult:
    """Result of an ethical rules check."""
    passed: bool = True
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rules_checked: list[str] = field(default_factory=list)


@dataclass
class ResourceLimitResult:
    """Result of a resource limit check."""
    allowed: bool = True
    reason: str = ""
    current_usage: dict[str, int] = field(default_factory=dict)
    limits: dict[str, int] = field(default_factory=dict)


# ── Scope Validator ─────────────────────────────────────────────────────────

class ScopeValidator:
    """
    Multi-layer scope validation before any agent action.

    Layers:
    1. Known good: Explicitly in-scope targets
    2. Known bad: Explicitly out-of-scope targets
    3. Pattern match: Wildcards, CIDR ranges, URL patterns
    4. Ownership: Verified owned domains
    5. Third-party detection: Known third-party services
    6. Uncertainty: Targets that need human review

    Default: DENY
    """

    def __init__(self):
        self._in_scope: set[str] = set()
        self._out_of_scope: set[str] = set()
        self._wildcards: list[str] = []
        self._owned_domains: set[str] = set()
        self._third_party_domains: dict[str, str] = {
            "s3.amazonaws.com": "AWS S3",
            "cloudfront.net": "AWS CloudFront",
            "akamai.net": "Akamai CDN",
            "akamaiedge.net": "Akamai CDN",
            "fastly.net": "Fastly CDN",
            "azureedge.net": "Azure CDN",
            "azure.com": "Microsoft Azure",
            "cloudflare.com": "Cloudflare",
            "googleapis.com": "Google APIs",
            "googleusercontent.com": "Google Cloud",
            "githubusercontent.com": "GitHub Pages",
            "github.io": "GitHub Pages",
            "netlify.app": "Netlify",
            "vercel.app": "Vercel",
            "pages.dev": "Cloudflare Pages",
            "firebaseapp.com": "Firebase",
            "herokuapp.com": "Heroku",
        }

    def add_scope(self, target: str, in_scope: bool = True):
        """Add a target to scope."""
        target = target.strip().lower()
        if target.startswith("*."):
            self._wildcards.append(target[2:])
        elif in_scope:
            self._in_scope.add(target)
        else:
            self._out_of_scope.add(target)

    def add_owned_domain(self, domain: str):
        """Add a known-owned domain."""
        self._owned_domains.add(domain.strip().lower())

    def validate(self, target: str) -> ScopeValidationResult:
        """
        Validate a target against all scope layers.

        1. Check out-of-scope rules first (fastest rejection)
        2. Check in-scope rules
        3. Check wildcards
        4. Check ownership
        5. Check third-party detection
        6. Default: DENY
        """
        target = target.strip().lower()
        now = datetime.now(timezone.utc).isoformat()

        # Layer 1: Known out-of-scope
        for oos in self._out_of_scope:
            if oos in target or target == oos:
                return ScopeValidationResult(
                    allowed=False,
                    reason=f"Target '{target}' is explicitly out of scope (matched: {oos})",
                    validated_at=now,
                    matched_rules=[f"oos:{oos}"],
                )

        # Layer 2: Known in-scope
        for ins in self._in_scope:
            if target == ins or target.endswith(f".{ins}"):
                return ScopeValidationResult(
                    allowed=True,
                    reason=f"Target '{target}' is in scope (matched: {ins})",
                    validated_at=now,
                    matched_rules=[f"ins:{ins}"],
                )

        # Layer 3: Wildcard match
        for wild in self._wildcards:
            if target.endswith(f".{wild}") or target == wild:
                return ScopeValidationResult(
                    allowed=True,
                    reason=f"Target '{target}' matches wildcard *.{wild}",
                    validated_at=now,
                    matched_rules=[f"wildcard:{wild}"],
                )

        # Layer 4: Owned domain
        for owned in self._owned_domains:
            if target == owned or target.endswith(f".{owned}"):
                return ScopeValidationResult(
                    allowed=True,
                    reason=f"Target '{target}' is a known owned domain (matched: {owned})",
                    validated_at=now,
                    matched_rules=[f"owned:{owned}"],
                    validation_level="MODERATE",
                )

        # Layer 5: Third-party detection
        for tp_domain, tp_name in self._third_party_domains.items():
            if tp_domain in target or target.endswith(f".{tp_domain}"):
                return ScopeValidationResult(
                    allowed=False,
                    reason=f"Target '{target}' appears to be a {tp_name} domain — third-party, not in scope",
                    validated_at=now,
                    matched_rules=[f"third_party:{tp_name}"],
                )

        # Layer 6: Default DENY
        return ScopeValidationResult(
            allowed=False,
            reason=f"Target '{target}' is not in any scope definition — default DENY",
            validated_at=now,
        )

    def batch_validate(self, targets: list[str]) -> dict[str, ScopeValidationResult]:
        """Validate multiple targets."""
        return {t: self.validate(t) for t in targets}

    def filter_in_scope(self, targets: list[str]) -> list[str]:
        """Return only targets that pass scope validation."""
        return [t for t in targets if self.validate(t).allowed]

    def filter_out_of_scope(self, targets: list[str]) -> list[str]:
        """Return only targets that fail scope validation."""
        return [t for t in targets if not self.validate(t).allowed]


# ── Output Sanitizer ────────────────────────────────────────────────────────

class OutputSanitizer:
    """
    Strip PII, secrets, and dangerous content from agent outputs.

    Modes:
    - STRICT: Redact ALL PII and secrets (default for reports)
    - MODERATE: Redact only high-confidence secrets (default for logs)
    - PERMISSIVE: Only redact critical secrets (for internal use)

    Redaction strategies:
    - PII: Replace with [REDACTED PII: TYPE]
    - Secrets: Replace with [REDACTED SECRET: TYPE]
    - Dangerous payloads: Replace with [REDACTED DANGEROUS CONTENT]
    """

    def __init__(self, mode: str = "MODERATE"):
        self.mode = mode.upper()
        self._redacted_count = 0
        self._redacted_types: dict[str, int] = {}

    def sanitize_text(self, text: str) -> SanitizationResult:
        """
        Sanitize text content by removing PII, secrets, and dangerous patterns.

        Returns the sanitized text and metadata about what was removed.
        """
        if not text:
            return SanitizationResult(
                sanitized_content="",
                original_length=0,
                sanitized_length=0,
            )

        original = text
        removed_types: dict[str, int] = {}

        # Always remove dangerous patterns
        for pattern, ptype in DANGEROUS_PATTERNS:
            count_before = len(text)
            text = re.sub(pattern, f"[REDACTED DANGEROUS: {ptype}]", text)
            count_after = len(text)
            if count_before != count_after:
                removed_types[ptype] = removed_types.get(ptype, 0) + 1

        # Remove secrets based on mode
        if self.mode in ("STRICT", "MODERATE"):
            for pattern, stype in SECRET_PATTERNS:
                count_before = len(text)
                text = re.sub(pattern, f"[REDACTED SECRET: {stype}]", text)
                count_after = len(text)
                if count_before != count_after:
                    removed_types[stype] = removed_types.get(stype, 0) + 1

        # Remove PII based on mode
        if self.mode == "STRICT":
            for pattern, ptype in PII_PATTERNS:
                count_before = len(text)
                text = re.sub(pattern, f"[REDACTED PII: {ptype}]", text)
                count_after = len(text)
                if count_before != count_after:
                    removed_types[ptype] = removed_types.get(ptype, 0) + 1

        total_removed = sum(removed_types.values())
        self._redacted_count += total_removed
        for t, c in removed_types.items():
            self._redacted_types[t] = self._redacted_types.get(t, 0) + c

        return SanitizationResult(
            original_length=len(original),
            sanitized_length=len(text),
            items_removed=total_removed,
            removed_types=removed_types,
            sanitized_content=text,
        )

    def sanitize_dict(self, data: dict[str, Any], depth: int = 0) -> dict[str, Any]:
        """Recursively sanitize all string values in a dict."""
        if depth > 5:
            return data  # Prevent infinite recursion

        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized = self.sanitize_text(value)
                result[key] = sanitized.sanitized_content
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value, depth + 1)
            elif isinstance(value, list):
                result[key] = self.sanitize_list(value, depth + 1)
            elif isinstance(value, (int, float, bool)):
                result[key] = value
            else:
                result[key] = value
        return result

    def sanitize_list(self, items: list[Any], depth: int = 0) -> list[Any]:
        """Recursively sanitize all items in a list."""
        if depth > 5:
            return items

        result: list[Any] = []
        for item in items:
            if isinstance(item, str):
                sanitized = self.sanitize_text(item)
                result.append(sanitized.sanitized_content)
            elif isinstance(item, dict):
                result.append(self.sanitize_dict(item, depth + 1))
            elif isinstance(item, list):
                result.append(self.sanitize_list(item, depth + 1))
            else:
                result.append(item)
        return result

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "total_redacted": self._redacted_count,
            "by_type": dict(self._redacted_types),
        }


# ── Ethical Guard ──────────────────────────────────────────────────────────

class EthicalGuard:
    """
    Enforce foundational ethical rules at every stage of the pipeline.

    Every agent action must pass the ethical guard before execution.
    Violations are logged and can trigger pipeline halt.
    """

    def __init__(self, fail_on_violation: bool = True):
        self.fail_on_violation = fail_on_violation
        self._violations: list[dict[str, Any]] = []
        self._warnings: list[dict[str, Any]] = []
        self._rules = ETHICAL_RULES

    def check_action(self, action: str, target: str, context: dict | None = None) -> EthicalCheckResult:
        """
        Check if an action against a target passes all ethical rules.

        Args:
            action: The action being performed (e.g., "scan", "report", "enumerate")
            target: The target being acted upon
            context: Optional additional context for the check

        Returns:
            EthicalCheckResult with pass/fail, violations, and warnings
        """
        violations = []
        warnings = []
        rules_checked = []

        action_lower = action.lower()
        target_lower = target.lower() if target else ""

        for rule in ETHICAL_RULES:
            rule_text = rule["rule"].lower()
            rules_checked.append(rule["rule"])

            # Check Level 1: Absolute rules
            if rule["level"] == 1 and rule["priority"] == "ABSOLUTE":
                if "unauthorized targets" in rule_text:
                    # This is checked by ScopeValidator separately
                    pass

                if "service disruption" in rule_text:
                    if action_lower in ("dos", "ddos", "flood", "stress", "crash"):
                        violations.append(f"ABSOLUTE VIOLATION: {rule['rule']}")
                        self._violations.append({
                            "rule": rule["rule"],
                            "action": action,
                            "target": target,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "severity": "CRITICAL",
                        })

                if "exfiltrate user data" in rule_text:
                    if action_lower in ("extract", "exfiltrate", "download_data", "steal"):
                        violations.append(f"ABSOLUTE VIOLATION: {rule['rule']}")

            # Check Level 2: Mandatory rules
            elif rule["level"] == 2:
                if "verify scope" in rule_text:
                    if not context or not context.get("scope_validated"):
                        warnings.append(f"MANDATORY: {rule['rule']} — scope not yet validated for {target}")
                        self._warnings.append({
                            "rule": rule["rule"],
                            "action": action,
                            "target": target,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })

                if "validate findings" in rule_text:
                    if action_lower in ("report", "submit") and (not context or not context.get("validated")):
                        warnings.append(f"MANDATORY: {rule['rule']} — finding not yet validated")

        result = EthicalCheckResult(
            passed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
            rules_checked=rules_checked,
        )

        return result

    def check_finding_before_report(self, finding: dict[str, Any]) -> EthicalCheckResult:
        """
        Specialized check for findings before they enter a report.

        Ensures:
        - Finding has been validated (Agent 7)
        - Finding has scope authorization
        - Finding has policy authorization
        - No PII in the finding
        - No destructive content in reproduction steps
        """
        violations = []
        warnings = []
        rules_checked = [
            "Finding must be validated (PROMOTE)",
            "Finding must have scope authorization (ALLOW)",
            "Finding must have policy authorization (ALLOW)",
            "Finding content must not contain PII",
            "Finding reproduction steps must not be destructive",
        ]

        # Check validation status
        validation = str(finding.get("validation_status", finding.get("validation_decision", ""))).upper()
        if validation != "PROMOTE":
            violations.append(f"Finding not validated: status={validation}")

        # Check scope authorization
        scope = str(finding.get("scope_status", "")).upper()
        if scope == "BLOCK":
            violations.append("Scope authorization is BLOCK")
        elif scope != "ALLOW":
            warnings.append(f"Scope authorization is {scope} — not confirmed ALLOW")

        # Check policy authorization
        policy = str(finding.get("policy_status", "")).upper()
        if policy in ("BLOCK", "REJECT"):
            violations.append(f"Policy authorization is {policy}")
        elif policy != "ALLOW":
            warnings.append(f"Policy authorization is {policy} — not confirmed ALLOW")

        # Check for PII in finding content
        content = json.dumps(finding)
        for pattern, ptype in PII_PATTERNS:
            if re.search(pattern, content):
                warnings.append(f"Finding contains potential PII ({ptype}) — strip before reporting")

        # Check for destructive content in reproduction steps
        steps = finding.get("reproduction_steps", [])
        for step in steps:
            step_text = str(step).lower()
            for pattern, dtype in DANGEROUS_PATTERNS:
                if re.search(pattern, step_text):
                    warnings.append(f"Reproduction step contains {dtype} — needs safety review")

        return EthicalCheckResult(
            passed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
            rules_checked=rules_checked,
        )

    @property
    def violation_log(self) -> list[dict[str, Any]]:
        return list(self._violations)

    @property
    def warning_log(self) -> list[dict[str, Any]]:
        return list(self._warnings)

    def reset_logs(self):
        self._violations.clear()
        self._warnings.clear()


# ── Resource Limiter ────────────────────────────────────────────────────────

class ResourceLimiter:
    """
    Cap resource consumption across the pipeline.

    Limits:
    - max_findings_per_project: Max total findings (default 100)
    - max_findings_per_vuln_class: Max per vuln class (default 3)
    - max_targets_per_project: Max unique targets (default 50)
    - max_api_calls_per_minute: Max external API calls (default 60)
    - max_report_size_bytes: Max report size (default 1MB)
    """

    def __init__(self):
        self._limits: dict[str, int] = {
            "max_findings_per_project": 100,
            "max_findings_per_vuln_class": 3,
            "max_targets_per_project": 50,
            "max_api_calls_per_minute": 60,
            "max_report_size_bytes": 1_048_576,  # 1MB
        }
        self._usage: dict[str, dict[str, int]] = {
            "findings_by_type": {},
            "targets_seen": {},
            "api_calls": {},
            "report_sizes": {},
        }
        self._api_call_timestamps: list[float] = []
        self._project_findings: dict[str, int] = {}
        self._project_targets: dict[str, set[str]] = {}

    def set_limit(self, limit_name: str, value: int):
        """Set a specific resource limit."""
        self._limits[limit_name] = value

    def check_add_finding(self, project_id: str, vuln_type: str) -> ResourceLimitResult:
        """
        Check if a new finding can be added under resource limits.

        Returns:
            ResourceLimitResult with allowed=True/False and reason
        """
        # Check per-project limit
        current_findings = self._project_findings.get(project_id, 0)
        max_findings = self._limits.get("max_findings_per_project", 100)
        if current_findings >= max_findings:
            return ResourceLimitResult(
                allowed=False,
                reason=f"Project '{project_id}' has reached max findings ({max_findings})",
                current_usage={"project_findings": current_findings},
                limits={"max_findings_per_project": max_findings},
            )

        # Check per-vuln-class limit
        findings_by_type = self._usage["findings_by_type"]
        vuln_count = findings_by_type.get(vuln_type, 0)
        max_per_class = self._limits.get("max_findings_per_vuln_class", 3)
        if vuln_count >= max_per_class:
            return ResourceLimitResult(
                allowed=False,
                reason=f"Vulnerability class '{vuln_type}' has reached max findings ({max_per_class})",
                current_usage={"findings_by_type": {vuln_type: vuln_count}},
                limits={"max_findings_per_vuln_class": max_per_class},
            )

        return ResourceLimitResult(allowed=True)

    def record_finding(self, project_id: str, vuln_type: str):
        """Record that a finding was added."""
        self._project_findings[project_id] = self._project_findings.get(project_id, 0) + 1
        self._usage["findings_by_type"][vuln_type] = self._usage["findings_by_type"].get(vuln_type, 0) + 1

    def check_add_target(self, project_id: str, target: str) -> ResourceLimitResult:
        """
        Check if a target can be added under resource limits.
        """
        if project_id not in self._project_targets:
            self._project_targets[project_id] = set()

        max_targets = self._limits.get("max_targets_per_project", 50)
        if len(self._project_targets[project_id]) >= max_targets:
            return ResourceLimitResult(
                allowed=False,
                reason=f"Project '{project_id}' has reached max targets ({max_targets})",
                current_usage={"project_targets": len(self._project_targets[project_id])},
                limits={"max_targets_per_project": max_targets},
            )

        return ResourceLimitResult(allowed=True)

    def record_target(self, project_id: str, target: str):
        """Record that a target was added."""
        if project_id not in self._project_targets:
            self._project_targets[project_id] = set()
        self._project_targets[project_id].add(target)

    def check_api_call(self) -> ResourceLimitResult:
        """
        Check if an API call can be made under rate limits.

        Uses a sliding window of 60 seconds.
        """
        import time
        now = time.monotonic()
        window_start = now - 60.0

        # Prune old timestamps
        self._api_call_timestamps = [t for t in self._api_call_timestamps if t > window_start]

        max_calls = self._limits.get("max_api_calls_per_minute", 60)
        if len(self._api_call_timestamps) >= max_calls:
            return ResourceLimitResult(
                allowed=False,
                reason=f"API call rate limit reached ({max_calls}/minute)",
                current_usage={"api_calls_per_minute": len(self._api_call_timestamps)},
                limits={"max_api_calls_per_minute": max_calls},
            )

        return ResourceLimitResult(allowed=True)

    def record_api_call(self):
        """Record that an API call was made."""
        import time
        self._api_call_timestamps.append(time.monotonic())
        self._usage["api_calls"]["total"] = self._usage["api_calls"].get("total", 0) + 1

    def check_report_size(self, report_content: str) -> ResourceLimitResult:
        """
        Check if a report is within size limits.
        """
        size_bytes = len(report_content.encode("utf-8"))
        max_size = self._limits.get("max_report_size_bytes", 1_048_576)
        if size_bytes > max_size:
            return ResourceLimitResult(
                allowed=False,
                reason=f"Report size ({size_bytes} bytes) exceeds limit ({max_size} bytes)",
                current_usage={"report_size_bytes": size_bytes},
                limits={"max_report_size_bytes": max_size},
            )
        return ResourceLimitResult(allowed=True)

    @property
    def usage_summary(self) -> dict[str, Any]:
        return {
            "findings_by_type": dict(self._usage["findings_by_type"]),
            "targets_by_project": {k: len(v) for k, v in self._project_targets.items()},
            "project_findings": dict(self._project_findings),
            "api_calls": dict(self._usage["api_calls"]),
            "api_calls_last_minute": len(self._api_call_timestamps),
            "limits": dict(self._limits),
        }


# ── Convenience Factory ─────────────────────────────────────────────────────

_default_scope_validator: ScopeValidator | None = None
_default_sanitizer: OutputSanitizer | None = None
_default_ethical_guard: EthicalGuard | None = None
_default_resource_limiter: ResourceLimiter | None = None


def get_scope_validator() -> ScopeValidator:
    """Get or create the default scope validator."""
    global _default_scope_validator
    if _default_scope_validator is None:
        _default_scope_validator = ScopeValidator()
    return _default_scope_validator


def get_output_sanitizer(mode: str = "MODERATE") -> OutputSanitizer:
    """Get or create the default output sanitizer."""
    global _default_sanitizer
    if _default_sanitizer is None:
        _default_sanitizer = OutputSanitizer(mode=mode)
    return _default_sanitizer


def get_ethical_guard(fail_on_violation: bool = True) -> EthicalGuard:
    """Get or create the default ethical guard."""
    global _default_ethical_guard
    if _default_ethical_guard is None:
        _default_ethical_guard = EthicalGuard(fail_on_violation=fail_on_violation)
    return _default_ethical_guard


def get_resource_limiter() -> ResourceLimiter:
    """Get or create the default resource limiter."""
    global _default_resource_limiter
    if _default_resource_limiter is None:
        _default_resource_limiter = ResourceLimiter()
    return _default_resource_limiter
