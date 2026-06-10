"""Report Template (Blank.md) — V3.

Implements the bug-bounty report structure from
``ZephrFish/BugBountyTemplates/Blank.md`` so that the Reporting Agent
can produce a standardized, evidence-rich report.

V3 spec: ``Report Intelligence`` says the Reporting Agent should
generate Executive / Technical / Developer / Remediation reports and
always include Evidence, Confidence, Impact, Remediation, Coverage,
and Validation Status.

This module provides a single :class:`BlankReportRenderer` that takes
a list of promoted findings and renders Markdown in the Blank.md
shape, plus a "report intelligence" view that bundles multiple report
types into a single payload.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Iterable

import structlog

from .methodology import BLANK_MD_TEMPLATE_SECTIONS
from .validation import (
    CandidateFinding,
    EvidenceItem,
    ValidationOutcome,
)

logger = structlog.get_logger()


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


@dataclass
class ReportFinding:
    """A finding in the format Blank.md expects."""

    title: str
    issue_description: str
    affected_url: str
    risk_rating: str
    cvss: str = ""
    difficulty_to_exploit: str = "Medium"
    authentication_required: str = "Unknown"
    user_interaction_required: str = "Unknown"
    impact: str = ""
    attack_scenario: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    request: str = ""
    response: str = ""
    screenshots: list[str] = field(default_factory=list)
    affected_demographic: str = ""
    recommended_fix: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "Medium"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    validation_status: str = "PROMOTED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BlankReportRenderer:
    """Renders one or more findings into Blank.md-style Markdown."""

    def __init__(self, project_name: str = "Project"):
        self.project_name = project_name
        self.generated_at = datetime.utcnow().isoformat()

    # ---- per-finding rendering -------------------------------------------

    def render_finding(self, finding: ReportFinding) -> str:
        steps_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(finding.steps_to_reproduce)) or "1. _Not provided_"
        shots_md = "\n".join(f"- {s}" for s in finding.screenshots) or "- _None_"
        refs_md = "\n".join(f"- {r}" for r in finding.references) or "- _None_"
        ev_md = "\n".join(
            f"- **source:** `{e.get('source','')}`  •  **location:** `{e.get('location','')}`"
            f"  •  **confidence:** {e.get('confidence','')}\n  {e.get('context','')}"
            for e in finding.evidence
        ) or "- _No evidence attached_"

        return textwrap.dedent(
            f"""
            # {finding.title}

            ## Issue Description
            {finding.issue_description}

            ## Affected URL/Area
            - {finding.affected_url}

            ## Risk Rating
            - Risk: **{finding.risk_rating}**
            - Difficulty to Exploit: **{finding.difficulty_to_exploit}**
            - Authentication Required: **{finding.authentication_required}**
            - User Interaction Required: **{finding.user_interaction_required}**
            - CVSS 3.1 Score: {finding.cvss or "_Not scored_"}
            - Model Confidence: **{finding.confidence}**
            - Validation Status: **{finding.validation_status}**

            ### Impact
            {finding.impact}

            ### Attack Scenario
            {finding.attack_scenario}

            ## Steps to Reproduce / PoC
            {steps_md}

            ### Request
            ```http
            {finding.request or "_Not captured_"}
            ```

            ### Response
            ```http
            {finding.response or "_Not captured_"}
            ```

            ### Evidence
            {ev_md}

            ### Screenshots
            {shots_md}

            ## Affected Demographic / User Base
            {finding.affected_demographic}

            ## Recommended Fix
            {finding.recommended_fix}

            ## References
            {refs_md}
            """
        ).strip() + "\n"

    # ---- full report ------------------------------------------------------

    def render_report(
        self,
        findings: Iterable[ReportFinding],
        *,
        coverage: dict[str, float] | None = None,
        overall_coverage: float | None = None,
    ) -> str:
        findings = list(findings)
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.risk_rating, 99))
        counts = {
            "critical": sum(1 for f in findings if f.risk_rating == "Critical"),
            "high":     sum(1 for f in findings if f.risk_rating == "High"),
            "medium":   sum(1 for f in findings if f.risk_rating == "Medium"),
            "low":      sum(1 for f in findings if f.risk_rating == "Low"),
            "info":     sum(1 for f in findings if f.risk_rating == "Informational"),
        }
        cov_lines: list[str] = []
        if coverage:
            for k, v in coverage.items():
                cov_lines.append(f"- **{k.title()}**: {v:.0f}%")
            if overall_coverage is None and coverage:
                overall_coverage = sum(coverage.values()) / len(coverage)
            if overall_coverage is not None:
                cov_lines.append(f"- **Overall**: {overall_coverage:.0f}%")
        cov_md = "\n".join(cov_lines) if cov_lines else "_No coverage metrics available_"
        body = "\n\n---\n\n".join(self.render_finding(f) for f in findings)
        return textwrap.dedent(
            f"""
            # Security Assessment Report — {self.project_name}

            - **Generated:** {self.generated_at}
            - **Total findings:** {len(findings)}
            - **Critical / High / Medium / Low / Info:** {counts['critical']} / {counts['high']} / {counts['medium']} / {counts['low']} / {counts['info']}

            ## Coverage
            {cov_md}

            ## Findings
            {body if body else "_No findings._"}
            """
        ).strip() + "\n"

    # ---- report-intelligence views ---------------------------------------

    def render_executive(
        self, findings: Iterable[ReportFinding]
    ) -> str:
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.risk_rating, 99))
        lines = [f"# Executive Summary — {self.project_name}", ""]
        lines.append(f"_Generated {self.generated_at}_\n")
        lines.append("## Top Risks\n")
        for f in findings[:5]:
            lines.append(f"- **{f.risk_rating}** — {f.title}")
        lines.append("\n## Recommendations\n")
        for f in findings:
            if f.risk_rating in ("Critical", "High"):
                lines.append(f"- {f.recommended_fix or 'See technical report.'}")
        return "\n".join(lines) + "\n"

    def render_developer(
        self, findings: Iterable[ReportFinding]
    ) -> str:
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.risk_rating, 99))
        lines = [f"# Developer Remediation Guide — {self.project_name}", ""]
        for f in findings:
            lines.append(f"## {f.title}")
            lines.append(f"_Risk: {f.risk_rating} • Confidence: {f.confidence}_\n")
            lines.append(f"**Where:** {f.affected_url}")
            lines.append(f"**How to fix:**\n\n{f.recommended_fix or '_Not specified_'}\n")
            lines.append("---\n")
        return "\n".join(lines)


# ---- Bridge helpers ----------------------------------------------------------

def finding_to_report_finding(
    finding: CandidateFinding,
    outcome: ValidationOutcome | None = None,
) -> ReportFinding:
    """Convert a CandidateFinding into the Blank.md shape."""
    ev_dicts = [e.to_dict() for e in finding.evidence]
    request, response = "", ""
    # Heuristic: first pair of evidence items with raw http in context become
    # request/response blocks.
    for e in finding.evidence:
        ctx = (e.context or "").strip()
        if ctx.startswith("REQUEST"):
            request = ctx.removeprefix("REQUEST").strip()
        elif ctx.startswith("RESPONSE"):
            response = ctx.removeprefix("RESPONSE").strip()
    return ReportFinding(
        title=finding.title,
        issue_description=finding.description,
        affected_url=", ".join(finding.affected_components) or "_Not specified_",
        risk_rating=finding.severity,
        confidence=finding.confidence,
        evidence=ev_dicts,
        validation_status=(outcome.status.value if outcome else "CANDIDATE"),
    )
