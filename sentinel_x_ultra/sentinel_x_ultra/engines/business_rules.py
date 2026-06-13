"""Business Rule Engine - Document and extract business rules, detect violations."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class RuleType(str, Enum):
    """Types of business rules."""
    VALIDATION = "validation"          # Input validation rules
    AUTHORIZATION = "authorization"    # Who can perform what
    PROCESS = "process"                # Business process constraints
    DATA_INTEGRITY = "data_integrity"  # Data consistency rules
    AUDIT = "audit"                    # Logging/audit requirements
    COMPLIANCE = "compliance"          # Regulatory compliance


class Severity(str, Enum):
    """Severity of rule violation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class BusinessRule:
    """Represents a business rule extracted from code/docs."""
    id: str
    name: str
    rule_type: RuleType
    description: str
    source_file: str = ""
    source_line: int = 0
    components: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)  # When rule applies
    actions: list[str] = field(default_factory=list)     # What rule requires
    exceptions: list[str] = field(default_factory=list)  # Known exceptions
    enforcement: str = "unknown"  # code | config | manual
    confidence: str = "medium"    # high | medium | low
    tags: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type.value if isinstance(self.rule_type, RuleType) else self.rule_type,
            "description": self.description,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "components": self.components,
            "conditions": self.conditions,
            "actions": self.actions,
            "exceptions": self.exceptions,
            "enforcement": self.enforcement,
            "confidence": self.confidence,
            "tags": self.tags,
            "created_at": self.created_at,
        }


@dataclass
class RuleViolation:
    """Represents a detected violation of a business rule."""
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    component: str
    description: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    violation_type: str = "unimplemented"  # unimplemented | bypassed | weakly_enforced
    suggested_fix: str = ""
    bypass_conditions: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "component": self.component,
            "description": self.description,
            "evidence": self.evidence,
            "violation_type": self.violation_type,
            "suggested_fix": self.suggested_fix,
            "bypass_conditions": self.bypass_conditions,
            "created_at": self.created_at,
        }


class BusinessRuleEngine:
    """Engine for extracting and validating business rules."""

    # Patterns for detecting business rules in code
    RULE_PATTERNS = {
        "validation": [
            (r"if.*validate", "validation"),
            (r"assert.*", "validation"),
            (r"check.*permission", "authorization"),
            (r"require.*auth", "authorization"),
            (r"only.*allowed", "authorization"),
        ],
        "authorization": [
            (r"@require.*role", "authorization"),
            (r"@permission", "authorization"),
            (r"allowed_roles", "authorization"),
            (r"check_access", "authorization"),
        ],
        "audit": [
            (r"log.*action", "audit"),
            (r"audit.*event", "audit"),
            (r"@audit", "audit"),
        ],
    }

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or str(uuid.uuid4())
        self._rules: dict[str, BusinessRule] = {}
        self._violations: list[RuleViolation] = []
        self._component_rules: dict[str, list[str]] = {}  # component -> rule IDs

        logger.info("business_rule_engine_initialized", project_id=self.project_id)

    # ============ Rule Extraction ============

    def extract_rules_from_code(self, file_path: str, code: str) -> list[BusinessRule]:
        """Extract business rules from source code."""
        rules = []

        lines = code.split("\n")

        for i, line in enumerate(lines):
            line_lower = line.lower()

            # Check for validation rules
            if any(kw in line_lower for kw in ["validate", "assert", "check", "verify"]):
                rule = self._extract_validation_rule(file_path, i + 1, line, lines)
                if rule:
                    rules.append(rule)

            # Check for authorization rules
            if any(kw in line_lower for kw in ["permission", "authorize", "access", "role"]):
                rule = self._extract_authorization_rule(file_path, i + 1, line, lines)
                if rule:
                    rules.append(rule)

            # Check for audit rules
            if any(kw in line_lower for kw in ["audit", "log", "event", "track"]):
                rule = self._extract_audit_rule(file_path, i + 1, line, lines)
                if rule:
                    rules.append(rule)

        # Add all extracted rules
        for rule in rules:
            self.add_rule(rule)

        logger.info("rules_extracted", file=file_path, count=len(rules))
        return rules

    def _extract_validation_rule(self, file_path: str, line_num: int, line: str, context: list[str]) -> BusinessRule | None:
        """Extract a validation rule from code."""
        # Look for validation patterns
        if "email" in line.lower():
            return BusinessRule(
                id=str(uuid.uuid4()),
                name="Email Validation",
                rule_type=RuleType.VALIDATION,
                description="Email addresses must be validated before processing",
                source_file=file_path,
                source_line=line_num,
                conditions=["on user input"],
                actions=["validate email format", "check domain"],
                enforcement="code",
                tags=["input-validation", "pii"],
            )

        if "password" in line.lower():
            return BusinessRule(
                id=str(uuid.uuid4()),
                name="Password Strength Validation",
                rule_type=RuleType.VALIDATION,
                description="Passwords must meet strength requirements",
                source_file=file_path,
                source_line=line_num,
                conditions=["on user registration", "on password change"],
                actions=["enforce minimum length", "require complexity"],
                enforcement="code",
                tags=["authentication", "password-policy"],
            )

        if "amount" in line.lower() or "quantity" in line.lower():
            return BusinessRule(
                id=str(uuid.uuid4()),
                name="Amount Validation",
                rule_type=RuleType.VALIDATION,
                description="Numeric amounts must be validated for正当性",
                source_file=file_path,
                source_line=line_num,
                conditions=["on financial transactions"],
                actions=["validate range", "check positivity"],
                enforcement="code",
                tags=["financial", "integrity"],
            )

        return None

    def _extract_authorization_rule(self, file_path: str, line_num: int, line: str, context: list[str]) -> BusinessRule | None:
        """Extract an authorization rule from code."""
        if "admin" in line.lower():
            return BusinessRule(
                id=str(uuid.uuid4()),
                name="Admin Authorization",
                rule_type=RuleType.AUTHORIZATION,
                description="Admin operations require admin role",
                source_file=file_path,
                source_line=line_num,
                conditions=["on admin actions"],
                actions=["verify admin role", "log access"],
                enforcement="code",
                tags=["access-control", "admin"],
            )

        if "owner" in line.lower() or "self" in line.lower():
            return BusinessRule(
                id=str(uuid.uuid4()),
                name="Owner Authorization",
                rule_type=RuleType.AUTHORIZATION,
                description="Users can only access their own resources",
                source_file=file_path,
                source_line=line_num,
                conditions=["on resource access"],
                actions=["verify ownership", "deny others"],
                enforcement="code",
                tags=["access-control", "privacy"],
            )

        return None

    def _extract_audit_rule(self, file_path: str, line_num: int, line: str, context: list[str]) -> BusinessRule | None:
        """Extract an audit rule from code."""
        if "action" in line.lower() or "event" in line.lower():
            return BusinessRule(
                id=str(uuid.uuid4()),
                name="Action Audit Logging",
                rule_type=RuleType.AUDIT,
                description="Important actions must be logged for audit trail",
                source_file=file_path,
                source_line=line_num,
                conditions=["on important actions"],
                actions=["log action details", "include timestamp"],
                enforcement="code",
                tags=["audit", "compliance"],
            )

        return None

    def extract_rules_from_documentation(self, doc_id: str, content: str) -> list[BusinessRule]:
        """Extract business rules from documentation."""
        rules = []

        # Look for rule-like statements in documentation
        rule_indicators = [
            "must", "shall", "required", "should", "always",
            "never", "prohibited", "mandatory", "only",
        ]

        lines = content.split("\n")

        for i, line in enumerate(lines):
            line_lower = line.lower()

            # Check if line contains rule-like language
            if any(indicator in line_lower for indicator in rule_indicators):
                rule = BusinessRule(
                    id=str(uuid.uuid4()),
                    name=self._extract_rule_name(line),
                    rule_type=self._classify_rule_type(line),
                    description=line.strip(),
                    source_file=doc_id,
                    source_line=i + 1,
                    enforcement="manual",  # Documentation implies manual enforcement
                    confidence="medium",
                    tags=self._extract_tags(line),
                )
                rules.append(rule)

        for rule in rules:
            self.add_rule(rule)

        logger.info("rules_from_docs", doc_id=doc_id, count=len(rules))
        return rules

    def _extract_rule_name(self, line: str) -> str:
        """Extract a name from a rule statement."""
        # Take first meaningful words
        words = line.split()
        if len(words) >= 3:
            return " ".join(words[:4]) + "..."
        return line[:50]

    def _classify_rule_type(self, line: str) -> RuleType:
        """Classify the type of rule based on content."""
        line_lower = line.lower()

        if any(kw in line_lower for kw in ["validate", "check", "must be", "format"]):
            return RuleType.VALIDATION
        if any(kw in line_lower for kw in ["permission", "access", "authorize", "role"]):
            return RuleType.AUTHORIZATION
        if any(kw in line_lower for kw in ["process", "workflow", "step"]):
            return RuleType.PROCESS
        if any(kw in line_lower for kw in ["audit", "log", "record"]):
            return RuleType.AUDIT
        if any(kw in line_lower for kw in ["comply", "regulation", "gdpr", "pci"]):
            return RuleType.COMPLIANCE

        return RuleType.DATA_INTEGRITY

    def _extract_tags(self, line: str) -> list[str]:
        """Extract relevant tags from rule text."""
        tags = []
        line_lower = line.lower()

        tag_keywords = {
            "authentication": ["auth", "login", "password", "credential"],
            "authorization": ["permission", "access", "role", "privilege"],
            "validation": ["validate", "check", "format", "input"],
            "data-protection": ["pii", "personal", "sensitive", "private"],
            "financial": ["payment", "amount", "transaction", "currency"],
            "compliance": ["gdpr", "pci", "hipaa", "regulation"],
            "audit": ["log", "audit", "track", "record"],
        }

        for tag, keywords in tag_keywords.items():
            if any(kw in line_lower for kw in keywords):
                tags.append(tag)

        return tags if tags else ["general"]

    # ============ Rule Management ============

    def add_rule(self, rule: BusinessRule) -> str:
        """Add a rule to the engine."""
        self._rules[rule.id] = rule

        # Update component index
        for component in rule.components:
            if component not in self._component_rules:
                self._component_rules[component] = []
            self._component_rules[component].append(rule.id)

        logger.debug("rule_added", rule_id=rule.id, rule_type=rule.rule_type)
        return rule.id

    def get_rule(self, rule_id: str) -> BusinessRule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_rules_by_type(self, rule_type: RuleType) -> list[BusinessRule]:
        """Get all rules of a specific type."""
        return [r for r in self._rules.values() if r.rule_type == rule_type]

    def get_rules_for_component(self, component: str) -> list[BusinessRule]:
        """Get all rules for a specific component."""
        rule_ids = self._component_rules.get(component, [])
        return [self._rules[rid] for rid in rule_ids if rid in self._rules]

    def get_all_rules(self) -> list[BusinessRule]:
        """Get all rules."""
        return list(self._rules.values())

    # ============ Violation Detection ============

    def detect_violations(self, code: str, component: str) -> list[RuleViolation]:
        """Detect business rule violations in code."""
        violations = []

        # Get relevant rules for this component
        relevant_rules = self.get_rules_for_component(component)

        # If no component-specific rules, check all rules
        if not relevant_rules:
            relevant_rules = list(self._rules.values())

        for rule in relevant_rules:
            violation = self._check_rule_violation(rule, code, component)
            if violation:
                violations.append(violation)

        self._violations.extend(violations)
        logger.info("violations_detected", component=component, count=len(violations))
        return violations

    def _check_rule_violation(
        self,
        rule: BusinessRule,
        code: str,
        component: str,
    ) -> RuleViolation | None:
        """Check if a rule is violated in the given code."""
        code_lower = code.lower()

        # Check for missing enforcement
        if rule.enforcement == "manual" and rule.rule_type in [RuleType.VALIDATION, RuleType.AUTHORIZATION]:
            # Look for implementation that should exist
            if rule.rule_type == RuleType.VALIDATION:
                if "validate" not in code_lower and "check" not in code_lower:
                    return RuleViolation(
                        id=str(uuid.uuid4()),
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=Severity.HIGH,
                        component=component,
                        description=f"Validation rule '{rule.name}' appears unimplemented",
                        violation_type="unimplemented",
                        suggested_fix=f"Add validation for: {rule.description}",
                        evidence=[{"source": "code_analysis", "match": "missing validation"}],
                    )

            if rule.rule_type == RuleType.AUTHORIZATION:
                if "permission" not in code_lower and "auth" not in code_lower and "access" not in code_lower:
                    return RuleViolation(
                        id=str(uuid.uuid4()),
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=Severity.HIGH,
                        component=component,
                        description=f"Authorization rule '{rule.name}' appears unimplemented",
                        violation_type="unimplemented",
                        suggested_fix=f"Add authorization check for: {rule.description}",
                        evidence=[{"source": "code_analysis", "match": "missing auth check"}],
                    )

        # Check for weak enforcement (e.g., comments but no code)
        if rule.enforcement == "code":
            # If rule says it should be enforced in code, check if it actually is
            pass  # Simplified - would need deeper analysis

        return None

    def get_violations_by_severity(self, severity: Severity) -> list[RuleViolation]:
        """Get all violations of a specific severity."""
        return [v for v in self._violations if v.severity == severity]

    def get_violations_by_type(self, violation_type: str) -> list[RuleViolation]:
        """Get all violations of a specific type."""
        return [v for v in self._violations if v.violation_type == violation_type]

    # ============ Serialization ============

    def to_dict(self) -> dict[str, Any]:
        """Export business rules to dictionary."""
        return {
            "project_id": self.project_id,
            "rules": [r.to_dict() for r in self._rules.values()],
            "violations": [v.to_dict() for v in self._violations],
            "component_rules": self._component_rules,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BusinessRuleEngine":
        """Import business rules from dictionary."""
        engine = cls(project_id=data.get("project_id"))

        for rule_data in data.get("rules", []):
            rule_data_copy = rule_data.copy()
            if "rule_type" in rule_data_copy:
                rule_data_copy["rule_type"] = RuleType(rule_data_copy["rule_type"])
            rule = BusinessRule(**rule_data_copy)
            engine.add_rule(rule)

        for violation_data in data.get("violations", []):
            violation_data_copy = violation_data.copy()
            if "severity" in violation_data_copy:
                violation_data_copy["severity"] = Severity(violation_data_copy["severity"])
            violation = RuleViolation(**violation_data_copy)
            engine._violations.append(violation)

        engine._component_rules = data.get("component_rules", {})

        return engine

    def clear(self):
        """Clear all rules and violations."""
        self._rules.clear()
        self._violations.clear()
        self._component_rules.clear()
        logger.info("business_rule_engine_cleared")
