"""
AGENT 10 — STRICT EVIDENCE-TO-REPORT RENDERING ENGINE (Blank.md FORMAT)

Converts ONLY validated security data into a bug bounty submission report
using the Blank.md template. This agent is a deterministic renderer.

ABSOLUTE RULE:
If a field is not explicitly provided in input data: IT MUST NOT APPEAR IN OUTPUT.
No placeholders. No guessing. No defaults. No "assumed values".

HARD GATE:
Requires: finding + analysis + poc + validation_status=PROMOTE +
scope_status=ALLOW + policy_status=ALLOW. If ANY fails → REVIEW.

NO INTERPRETATION:
All values are PASSED THROUGH as-is from Agent 8 (PoC), Agent 9 (Analysis),
and validated finding metadata.
"""

import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


# ── Constants for strict UNKNOWN handling ───────────────────────────────────

UNKNOWN = "UNKNOWN"
NOT_DEMONSTRATED = "NOT DEMONSTRATED"
NOT_CAPTURED = "NOT CAPTURED"
NOT_PROVIDED = "NOT PROVIDED"

# ── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class VulnerabilityReport:
    """Report data — strict pass-through from validated inputs only.

    Every field defaults to empty string. If a field is empty during
    render_markdown(), the section is rendered with the appropriate
    UNKNOWN / NOT DEMONSTRATED / NOT CAPTURED / NOT PROVIDED constant
    as specified in the Blank.md specification. Screenshots section
    is OMITTED entirely if empty (no screenshots placeholder).
    """
    title: str = ""
    issue_description: str = ""
    affected_url: str = ""
    risk_rating: str = ""
    cvss: str = ""
    impact: str = ""
    attack_scenario: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    request: str = ""
    response: str = ""
    screenshots: List[str] = field(default_factory=list)
    affected_demographic: str = ""
    recommended_fix: str = ""
    references: List[str] = field(default_factory=list)
    generated_at: str = ""
    decision: str = ""  # GENERATE | REVIEW | BLOCK

    def render_markdown(self) -> str:
        """Render the report as Markdown in strict Blank.md format.

        Follows the exact structure from the Blank.md specification.
        No placeholders, no defaults, no assumed values.
        Only UNKNOWN / NOT DEMONSTRATED / NOT CAPTURED / NOT PROVIDED.
        """
        lines = []

        # Title
        lines.append(f"# {self.title or UNKNOWN}")
        lines.append("")

        # Issue Description — ONLY directly observed behavior from evidence
        lines.append("## Issue Description")
        lines.append(self.issue_description or UNKNOWN)
        lines.append("")

        # Affected Asset / URL — from validated scope evidence only
        lines.append("## Affected Asset / URL")
        lines.append(self.affected_url or UNKNOWN)
        lines.append("")

        # Risk Rating — direct pass-through from Agent 9
        lines.append("## Risk Rating")
        lines.append(self.risk_rating or UNKNOWN)
        lines.append("")

        # CVSS 3.1 Score — direct pass-through ONLY
        lines.append("## CVSS 3.1 Score")
        lines.append(self.cvss or UNKNOWN)
        lines.append("")

        # Impact — ONLY confirmed impact from evidence
        lines.append("## Impact")
        lines.append(self.impact or NOT_DEMONSTRATED)
        lines.append("")

        # Attack Scenario — ONLY from PoC steps
        lines.append("## Attack Scenario")
        lines.append(self.attack_scenario or NOT_DEMONSTRATED)
        lines.append("")

        # Steps to Reproduce (PoC) — MUST be copied verbatim from Agent 8
        lines.append("## Steps to Reproduce (PoC)")
        if self.steps_to_reproduce:
            for i, step in enumerate(self.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
        else:
            lines.append(NOT_DEMONSTRATED)
        lines.append("")

        # Request — ONLY from PoC evidence
        lines.append("## Request")
        lines.append(self.request or NOT_CAPTURED)
        lines.append("")

        # Response — ONLY from PoC evidence
        lines.append("## Response")
        lines.append(self.response or NOT_CAPTURED)
        lines.append("")

        # Affected Users / Demographic — ONLY if explicitly stated
        lines.append("## Affected Users / Demographic")
        lines.append(self.affected_demographic or UNKNOWN)
        lines.append("")

        # Recommended Fix — ONLY from Analysis Agent or remediation field
        lines.append("## Recommended Fix")
        lines.append(self.recommended_fix or NOT_PROVIDED)
        lines.append("")

        # References — ONLY CWE + OWASP from Agent 9
        lines.append("## References")
        if self.references:
            for ref in self.references:
                if ref:
                    lines.append(f"- {ref}")
        else:
            lines.append(UNKNOWN)
        lines.append("")

        # Screenshots — ONLY if explicitly provided in PoC
        # Otherwise: SECTION MUST BE OMITTED
        if self.screenshots:
            lines.append("## Screenshots")
            for s in self.screenshots:
                lines.append(f"- ![Screenshot]({s})")
            lines.append("")

        # Generated At — system timestamp only
        if self.generated_at:
            lines.append(f"**Generated At:** {self.generated_at}")
            lines.append("")

        return "\n".join(lines)


# ── Strict Evidence-to-Blank.md Render Engine ───────────────────────────────

class ReportGenerationAgent:
    """
    Agent 10: Strict Evidence-to-Report Rendering Engine.

    This agent is a deterministic renderer.
    It performs ZERO analysis. It performs ZERO interpretation.
    It performs ZERO enrichment.
    It ONLY formats pre-validated outputs from:
    - Agent 8 (PoC / reproduction evidence)
    - Agent 9 (security analysis)
    - Validation Engine (Agent 7)

    HARD GATE: If validation_status != PROMOTE or scope_status != ALLOW
    or policy_status != ALLOW → REVIEW with no report generated.
    """

    def __init__(self, llm_provider=None, memory=None):
        self.reports: List[VulnerabilityReport] = []
        self.llm_provider = llm_provider
        self.memory = memory

    async def generate_report(
        self,
        finding: Dict[str, Any],
        analysis: Dict[str, Any],
        poc: Dict[str, Any],
    ) -> VulnerabilityReport:
        """Generate a strict evidence-to-Blank.md vulnerability report.

        HARD GATE:
        - Requires finding, analysis, poc all present
        - Requires validation_status == PROMOTE
        - Requires scope_status == ALLOW
        - Requires policy_status == ALLOW

        If ANY condition fails → output REVIEW report with no content.

        All values are PASSED THROUGH as-is from the inputs.
        No interpretation, no rewriting, no summarization.
        """
        now = datetime.utcnow().isoformat()

        # === HARD GATE ===
        validation_status = str(finding.get("validation_status",
                               finding.get("validation_decision", ""))).upper()
        scope_status = str(finding.get("scope_status", "")).upper()
        policy_status = str(finding.get("policy_status", "")).upper()

        gate_failed = False
        gate_reasons = []

        if validation_status != "PROMOTE":
            gate_failed = True
            gate_reasons.append("validation_status != PROMOTE")

        if scope_status != "ALLOW":
            gate_failed = True
            gate_reasons.append("scope_status != ALLOW")

        if policy_status != "ALLOW":
            gate_failed = True
            gate_reasons.append("policy_status != ALLOW")

        if gate_failed:
            report = VulnerabilityReport(
                title=finding.get("title", UNKNOWN),
                issue_description=f"REVIEW — Input gate rejected: {'; '.join(gate_reasons)}",
                decision="REVIEW",
                generated_at=now,
            )
            self.reports.append(report)
            return report

        # === TRUTH SOURCE PRIORITY ===
        # 1. PoC Evidence (Agent 8) → highest authority
        # 2. Analysis Output (Agent 9)
        # 3. Finding metadata
        #
        # If conflict exists → REVIEW (do not resolve)

        # Detect conflicts between sources (Phase 5 Deep: AI-powered) 
        conflicts = await self._detect_conflicts(finding, analysis, poc)
        if conflicts:
            report = VulnerabilityReport(
                title=finding.get("title", UNKNOWN),
                issue_description=f"REVIEW — Source conflict detected: {'; '.join(conflicts[:3])}",
                decision="REVIEW",
                generated_at=now,
            )
            self.reports.append(report)
            return report

        # === BUILD REPORT — PASS-THROUGH ONLY ===

        # Title (from finding metadata)
        title = finding.get("title", UNKNOWN)

        # Issue Description — PoC (Agent 8) is highest authority
        issue_description = self._passthrough(
            poc.get("impact_demonstration", ""),
            finding.get("description", ""),
            finding.get("issue_description", ""),
        )

        # Affected URL — PoC (Agent 8) is highest authority
        affected_url = self._passthrough(
            poc.get("target", ""),
            finding.get("endpoint", ""),
            finding.get("target", ""),
            finding.get("affected_url", ""),
        )

        # Risk Rating (from analysis ONLY — direct pass-through)
        risk_rating = UNKNOWN
        if analysis:
            if isinstance(analysis, dict):
                risk_rating = analysis.get("severity",
                            analysis.get("risk_rating",
                            analysis.get("detailed", {}).get("cvss", {}).get("severity", "")))
            else:
                risk_rating = getattr(analysis, "severity",
                            getattr(analysis, "exploitability", ""))

        # CVSS 3.1 Score (from analysis ONLY — direct pass-through)
        cvss = UNKNOWN
        if analysis:
            if isinstance(analysis, dict):
                vector = analysis.get("cvss_vector",
                         analysis.get("cvss", {}).get("vector",
                         analysis.get("detailed", {}).get("cvss", {}).get("vector", "")))
                score = analysis.get("cvss_score",
                        analysis.get("cvss", {}).get("score", ""))
                if vector:
                    cvss = f"CVSS:3.1/{vector}" if not vector.startswith("CVSS:3.1") else vector
                elif score and score != "UNKNOWN":
                    cvss = f"CVSS:3.1/{score}"
            else:
                cvss_obj = getattr(analysis, "cvss", None)
                if cvss_obj:
                    if isinstance(cvss_obj, dict):
                        v = cvss_obj.get("vector", cvss_obj.get("vector_string", ""))
                        if v:
                            cvss = f"CVSS:3.1/{v}" if not v.startswith("CVSS:3.1") else v
                    else:
                        v = getattr(cvss_obj, "vector", getattr(cvss_obj, "vector_string", ""))
                        if v:
                            cvss = f"CVSS:3.1/{v}" if not v.startswith("CVSS:3.1") else v

        # Impact — ONLY confirmed impact from evidence
        impact = finding.get("impact", NOT_DEMONSTRATED)
        if impact == NOT_DEMONSTRATED and analysis:
            if isinstance(analysis, dict):
                impact = analysis.get("business_impact",
                         analysis.get("impact",
                         analysis.get("detailed", {}).get("business_impact", NOT_DEMONSTRATED)))
            else:
                impact = getattr(analysis, "business_impact",
                         getattr(analysis, "impact", NOT_DEMONSTRATED))
        if not impact:
            impact = NOT_DEMONSTRATED

        # Attack Scenario — ONLY from PoC
        attack_scenario = finding.get("attack_scenario", NOT_DEMONSTRATED)
        if attack_scenario == NOT_DEMONSTRATED:
            poc_impact = poc.get("impact_demonstration", "")
            attack_scenario = poc_impact or NOT_DEMONSTRATED

        # Steps to Reproduce — verbatim from Agent 8
        steps_to_reproduce = []
        raw_steps = poc.get("steps_to_reproduce", poc.get("steps",
                     poc.get("reproduction_steps", [])))
        if isinstance(raw_steps, list):
            for step in raw_steps:
                if isinstance(step, dict):
                    action = step.get("action", step.get("description",
                              step.get("step", "")))
                    if action:
                        steps_to_reproduce.append(str(action))
                elif isinstance(step, str):
                    steps_to_reproduce.append(step)

        # Request — ONLY from PoC evidence
        request = self._passthrough(
            poc.get("request", ""),
            finding.get("request", ""),
        )

        # Response — ONLY from PoC evidence
        response = self._passthrough(
            poc.get("response", ""),
            finding.get("response", ""),
        )

        # Screenshots — ONLY if explicitly provided
        screenshots = poc.get("screenshots", poc.get("screenshot_paths", []))
        if isinstance(screenshots, list):
            screenshots = [s for s in screenshots if s]
        else:
            screenshots = []

        # Affected Demographic — ONLY if explicitly stated
        affected_demographic = finding.get("affected_demographic",
                               finding.get("affected_users", ""))
        if not affected_demographic:
            affected_demographic = ""

        # Recommended Fix — ONLY from Analysis or remediation field
        recommended_fix = finding.get("remediation",
                          finding.get("recommended_fix", ""))
        if not recommended_fix and analysis:
            if isinstance(analysis, dict):
                recommended_fix = analysis.get("remediation_priority",
                                analysis.get("recommended_fix", ""))
            else:
                recommended_fix = getattr(analysis, "remediation_priority", "")
        if not recommended_fix:
            recommended_fix = ""

        # References — ONLY CWE + OWASP from Agent 9
        references = []
        if analysis:
            cwe = ""
            owasp = ""
            if isinstance(analysis, dict):
                cwe = analysis.get("cwe_primary",
                      analysis.get("cwe", {}).get("primary",
                      analysis.get("detailed", {}).get("cwe", {}).get("primary", "")))
                owasp = analysis.get("owasp_mapping",
                        analysis.get("owasp", {}).get("primary",
                        analysis.get("detailed", {}).get("owasp", {}).get("primary", "")))
            else:
                cwe = getattr(analysis, "cwe_primary",
                      getattr(getattr(analysis, "cwe", None), "primary", ""))
                owasp_obj = getattr(analysis, "owasp", None)
                if isinstance(owasp_obj, dict):
                    owasp = owasp_obj.get("primary", "")
                else:
                    owasp = getattr(owasp_obj, "primary", "")

            if cwe:
                references.append(f"CWE: {cwe}")
            if owasp:
                references.append(f"OWASP: {owasp}")

        # Build the report
        report = VulnerabilityReport(
            title=title,
            issue_description=issue_description or "",
            affected_url=affected_url or "",
            risk_rating=risk_rating,
            cvss=cvss,
            impact=impact,
            attack_scenario=attack_scenario,
            steps_to_reproduce=steps_to_reproduce,
            request=request or "",
            response=response or "",
            screenshots=screenshots,
            affected_demographic=affected_demographic,
            recommended_fix=recommended_fix or "",
            references=references,
            decision="GENERATE" if steps_to_reproduce else "REVIEW",
            generated_at=now,
        )

        self.reports.append(report)
        return report

    # ═══════════════════════════════════════════════════════════════════════════
    # CONFLICT DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    async def _detect_conflicts(self, finding: Dict[str, Any],
                                analysis: Dict[str, Any],
                                poc: Dict[str, Any]) -> List[str]:
        """Detect conflicts between sources using deterministic and AI-powered analysis.

        Phase 5 Deep: Uses LLM for semantic conflict detection — catching contradictions
        that keyword matching would miss.

        Truth source priority:
        1. PoC Evidence (Agent 8) → highest authority
        2. Analysis Output (Agent 9)
        3. Finding metadata

        If conflict exists → return conflict descriptions (REVIEW).
        """
        conflicts = []

        # Phase 5 Deep: Use LLM for semantic conflict detection
        if self.llm_provider and self.llm_provider.is_available:
            try:
                # Build a compact representation of all sources
                finding_summary = json.dumps({
                    "title": finding.get("title", ""),
                    "type": finding.get("type", ""),
                    "severity": finding.get("severity", ""),
                    "target": finding.get("target", ""),
                    "endpoint": finding.get("endpoint", ""),
                    "impact": (finding.get("impact", "") or "")[:200],
                    "description": (finding.get("description", "") or "")[:200],
                })[:500]
                analysis_summary = json.dumps(analysis)[:500] if analysis else "{}"
                poc_summary = json.dumps({
                    "target": poc.get("target", ""),
                    "cvss": poc.get("cvss", ""),
                    "severity": poc.get("severity", ""),
                    "impact_demonstration": (poc.get("impact_demonstration", "") or "")[:200],
                })[:500]

                prompt = (
                    f"Detect contradictions between these three information sources.\n\n"
                    f"Source 1 (Finding metadata): {finding_summary}\n\n"
                    f"Source 2 (Analysis - Agent 9): {analysis_summary}\n\n"
                    f"Source 3 (PoC - Agent 8): {poc_summary}\n\n"
                    f"Return ONLY a JSON array of strings describing each contradiction. "
                    f"Empty array [] if none. Look for: severity, target, impact, "
                    f"vulnerability type, or description contradictions."
                )
                llm_result = await self.llm_provider.reason_structured(prompt, temperature=0.1)
                if isinstance(llm_result, list):
                    for c in llm_result:
                        if isinstance(c, str) and c not in conflicts:
                            conflicts.append(f"AI DETECTED: {c}")
                elif isinstance(llm_result, dict):
                    for c in llm_result.get("contradictions", []):
                        if isinstance(c, str) and c not in conflicts:
                            conflicts.append(f"AI DETECTED: {c}")
            except Exception:
                pass

        # Also run deterministic checks
        finding_severity = str(finding.get("severity", "")).lower()
        poc_severity = str(poc.get("cvss", poc.get("severity", ""))).lower()
        analysis_severity = str(analysis.get("severity", "")).lower() if analysis else ""
        severities = [s for s in [finding_severity, poc_severity, analysis_severity] if s]
        if len(set(severities)) >= 2:
            conflicts.append(
                f"Severity conflict: finding={finding_severity}, analysis={analysis_severity}, poc={poc_severity}"
            )

        finding_target = str(finding.get("target", finding.get("endpoint", ""))).lower()
        poc_target = str(poc.get("target", "")).lower()
        targets = [t for t in [finding_target, poc_target] if t]
        if len(set(targets)) >= 2:
            conflicts.append(
                f"Target conflict: finding={finding_target} vs poc={poc_target}"
            )

        # Classification vs description contradictions
        desc = (finding.get("description", "") + " " + poc.get("impact_demonstration", "")).lower()
        vuln_type = str(finding.get("type", "")).lower()
        if vuln_type == "xss" and "sql" in desc:
            conflicts.append(
                f"Classification conflict: type={vuln_type} but description mentions SQL"
            )
        elif vuln_type == "sql_injection" and "<script>" in desc:
            conflicts.append(
                f"Classification conflict: type={vuln_type} but description mentions script tags"
            )

        return conflicts

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _passthrough(self, *values: str) -> str:
        """Return the first non-empty value, passing through as-is."""
        for v in values:
            if v:
                return v
        return ""

    def generate_executive_summary(self, reports: List[VulnerabilityReport]) -> str:
        """Generate an executive summary of all findings.

        Only includes reports that were GENERATED (passed the hard gate).
        Reviews are excluded from the summary.
        """
        generated = [r for r in reports if r.decision == "GENERATE"]
        lines = []
        lines.append("# Security Assessment Executive Summary")
        lines.append("")
        lines.append(f"**Generated:** {datetime.utcnow().isoformat()}")
        lines.append(f"**Total Findings:** {len(generated)}")
        lines.append("")

        critical = [r for r in generated if r.risk_rating == "Critical"]
        high = [r for r in generated if r.risk_rating == "High"]
        medium = [r for r in generated if r.risk_rating == "Medium"]
        low = [r for r in generated if r.risk_rating == "Low"]

        lines.append("## Severity Breakdown")
        lines.append(f"- **Critical:** {len(critical)}")
        lines.append(f"- **High:** {len(high)}")
        lines.append(f"- **Medium:** {len(medium)}")
        lines.append(f"- **Low:** {len(low)}")
        lines.append("")

        if critical:
            lines.append("## Critical Findings")
            for r in critical:
                lines.append(f"- **{r.title}** — {r.affected_url}")
                impact_preview = r.impact[:100] if r.impact and r.impact != NOT_DEMONSTRATED else "See report"
                lines.append(f"  {impact_preview}")
            lines.append("")

        if high:
            lines.append("## High Severity Findings")
            for r in high:
                lines.append(f"- **{r.title}** — {r.affected_url}")
            lines.append("")

        lines.append("## Top Recommendations")
        lines.append("- Address critical and high-severity findings immediately")
        lines.append("- Implement security controls per OWASP ASVS guidelines")
        lines.append("- Conduct regular security assessments")
        lines.append("")

        return "\n".join(lines)
