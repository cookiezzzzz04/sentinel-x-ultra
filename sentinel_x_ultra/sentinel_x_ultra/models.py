"""Data Models for SENTINEL-X ULTRA."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Confidence(str, Enum):
    VERIFIED = "Verified"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class FindingStatus(str, Enum):
    PENDING = "PENDING"
    DEBATE_IN_PROGRESS = "DEBATE_IN_PROGRESS"
    PROMOTED = "PROMOTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REJECTED = "REJECTED"


@dataclass
class Evidence:
    """Evidence for a finding."""
    source: str
    description: str
    data: dict[str, Any]
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "description": self.description,
            "data": self.data,
            "confidence": self.confidence,
        }


@dataclass
class AttackScenario:
    """Step-by-step attack scenario."""
    steps: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    attacker_capability: str = "authenticated"
    estimated_effort: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "prerequisites": self.prerequisites,
            "attacker_capability": self.attacker_capability,
            "estimated_effort": self.estimated_effort,
        }


@dataclass
class Finding:
    """Security finding."""
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    affected_components: list[str]
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    attack_scenario: AttackScenario | None = None
    business_impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    source_agent: str = ""
    status: FindingStatus = FindingStatus.PENDING
    cwe_ids: list[str] = field(default_factory=list)
    owasp_references: list[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "confidence": self.confidence.value if isinstance(self.confidence, Enum) else self.confidence,
            "affected_components": self.affected_components,
            "description": self.description,
            "evidence": [e.to_dict() if hasattr(e, 'to_dict') else e for e in self.evidence],
            "attack_scenario": self.attack_scenario.to_dict() if self.attack_scenario else None,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "references": self.references,
            "source_agent": self.source_agent,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "cwe_ids": self.cwe_ids,
            "owasp_references": self.owasp_references,
            "created_at": self.created_at,
        }


@dataclass
class Anomaly:
    """Anomaly requiring human review."""
    id: str
    anomaly_type: str  # permission | code | architectural | configuration | dependency
    component: str
    description: str
    confidence: Confidence
    suggested_investigation: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "anomaly_type": self.anomaly_type,
            "component": self.component,
            "description": self.description,
            "confidence": self.confidence.value if isinstance(self.confidence, Enum) else self.confidence,
            "suggested_investigation": self.suggested_investigation,
            "created_at": self.created_at,
        }


@dataclass
class DebateVerdict:
    """Result from Debate Engine."""
    finding_id: str
    verdict: str  # PROMOTE | NEEDS_REVIEW | REJECT
    final_confidence: Confidence
    final_severity: Severity
    advocate_summary: str
    skeptic_challenges: list[str]
    missing_evidence: list[str]
    impact_analysis: str
    debate_transcript: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "final_confidence": self.final_confidence.value if isinstance(self.final_confidence, Enum) else self.final_confidence,
            "final_severity": self.final_severity.value if isinstance(self.final_severity, Enum) else self.final_severity,
            "advocate_summary": self.advocate_summary,
            "skeptic_challenges": self.skeptic_challenges,
            "missing_evidence": self.missing_evidence,
            "impact_analysis": self.impact_analysis,
            "debate_transcript": self.debate_transcript,
        }


@dataclass
class AttackChain:
    """Chained attack path."""
    id: str
    name: str
    findings: list[str]  # Finding IDs
    entry_point: str
    final_impact: str
    required_capability: str
    chain_cvss: float = 0.0
    narrative: str = ""
    recommended_priority: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "findings": self.findings,
            "entry_point": self.entry_point,
            "final_impact": self.final_impact,
            "required_capability": self.required_capability,
            "chain_cvss": self.chain_cvss,
            "narrative": self.narrative,
            "recommended_priority": self.recommended_priority,
        }
