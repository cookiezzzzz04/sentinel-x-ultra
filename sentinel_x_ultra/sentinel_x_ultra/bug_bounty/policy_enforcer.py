"""
AGENT 2 — POLICY DECISION ENGINE & REPORT ELIGIBILITY AUTHORITY

The authoritative policy gatekeeper for the bug bounty pipeline.

You do NOT determine whether a vulnerability is real.
You determine whether a finding is eligible for further consideration under the bug bounty program.

Operates in STRICT FAIL-CLOSED MODE.
Accuracy is more important than throughput.
A false approval is more harmful than a false review.
"""

import asyncio
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from .url_parser import ProgramIntelligence
from .webhook import WebhookManager


# ── Enums ───────────────────────────────────────────────────────────────────

class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    REJECT = "REJECT"


class ScopeStatus(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNCLEAR = "UNCLEAR"


class AssetEligibility(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    UNCLEAR = "UNCLEAR"


class TestingCompliance(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNCLEAR = "UNCLEAR"


class VulnEligibility(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    UNCLEAR = "UNCLEAR"


class EvidenceTier(str, Enum):
    TIER_0 = "TIER_0"  # No evidence
    TIER_1 = "TIER_1"  # Single observation
    TIER_2 = "TIER_2"  # Multiple observations
    TIER_3 = "TIER_3"  # Reproducible evidence
    TIER_4 = "TIER_4"  # Direct proof


class DuplicateRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# ── Legacy Dataclasses (Backward Compatible) ────────────────────────────────

@dataclass
class PolicyRule:
    """A single policy rule for vulnerability filtering."""
    vuln_type: str
    allowed: bool  # True = accepted, False = rejected/blocked
    severity: str = "medium"
    notes: str = ""
    cwe_ids: List[str] = field(default_factory=list)


@dataclass
class PolicyEnforcementResult:
    """Result of policy enforcement check — legacy format."""
    finding_title: str
    finding_type: str
    policy_allowed: bool
    reason: str
    severity_override: Optional[str] = None
    # New fields for richer information
    decision: PolicyDecision = PolicyDecision.ALLOW
    confidence: float = 0.0
    program_compliance_score: int = 0
    detailed_output: Optional[Dict[str, Any]] = None


# ── Full Decision Output Schema ─────────────────────────────────────────────

@dataclass
class PolicyDecisionOutput:
    """Complete structured output of the Policy Decision Engine."""
    decision: PolicyDecision = PolicyDecision.ALLOW
    confidence: float = 0.0
    program_compliance_score: int = 0

    # Phase-level results
    scope_status: str = ""
    asset_eligibility: str = ""
    testing_compliance: str = ""
    vulnerability_eligibility: str = ""
    evidence_tier: str = ""
    impact_status: str = ""
    duplicate_risk: str = ""

    # Analysis details
    policy_violations: List[str] = field(default_factory=list)
    policy_citations: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)

    # Adversarial analysis
    rejection_arguments: List[str] = field(default_factory=list)
    triager_assessment: List[str] = field(default_factory=list)

    # Integrity
    uncertainties: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)

    # Final
    reasoning: List[str] = field(default_factory=list)
    recommended_next_action: str = ""


# ── Default Vulnerability Type Lists ────────────────────────────────────────

ACCEPTED_VULN_TYPES = [
    "remote_code_execution", "sql_injection", "xss", "csrf",
    "authentication_bypass", "authorization_bypass", "idor",
    "xxe", "file_upload", "path_traversal", "command_injection",
    "business_logic_flaw", "broken_encryption", "auth_issues",
    "api_vulnerabilities", "infrastructure_issues", "cloud_misconfiguration",
    "information_disclosure", "ssrf", "ssti", "nosql_injection",
    "open_redirect", "sensitive_data_exposure", "race_condition",
    "deserialization", "memory_corruption", "ci_cd_security",
]

REJECTED_VULN_TYPES = [
    "self_xss", "self_xss_without_auth_bypass",
    "self_xss_without_csrf", "theoretical_vulnerability",
    "clickjacking_without_impact", "missing_security_headers",
    "missing_http_security_headers", "information_disclosure_minor",
    "email_enumeration", "user_enumeration", "social_engineering",
    "physical_security", "denial_of_service", "brute_force",
    "automated_scanner_output", "best_practice_violation",
    "already_known_vulnerability", "third_party_service_issue",
]

# Prohibited testing methods (Phase 3)
PROHIBITED_TESTING_METHODS = [
    "denial_of_service", "credential_stuffing", "social_engineering",
    "phishing", "physical_attacks", "spam", "automated_mass_scanning",
    "attacks_against_third_parties",
]


class PolicyEnforcerAgent:
    """
    Agent 2: Policy Decision Engine & Report Eligibility Authority.

    Operates in STRICT FAIL-CLOSED MODE.
    Determines whether a finding should be ALLOW, REVIEW, or REJECT.
    Only findings that satisfy ALL policy requirements may be ALLOWed.

    12-Phase Decision Pipeline:
      1. Scope Verification
      2. Asset Eligibility
      3. Testing Restriction Compliance
      4. Vulnerability Eligibility
      5. Evidence Sufficiency
      6. Impact Sufficiency
      7. Duplicate Risk Analysis
      8. Policy Contradiction Analysis
      9. Program Compliance Score
     10. Triager Simulation
     11. Adverse Review
     12. Hallucination Prevention
    """

    def __init__(self, webhook_manager: Optional[WebhookManager] = None):
        self.accepted_types: List[str] = list(ACCEPTED_VULN_TYPES)
        self.rejected_types: List[str] = list(REJECTED_VULN_TYPES)
        self.custom_rules: List[PolicyRule] = []
        self.program_intel: Optional[ProgramIntelligence] = None
        self.webhook_manager = webhook_manager

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API (Backward Compatible)
    # ═══════════════════════════════════════════════════════════════════════════

    def load_program_policy(self, intel: ProgramIntelligence):
        """Load and parse program policy from intelligence data."""
        self.program_intel = intel
        self.custom_rules = []

        if intel.accepted_vuln_types:
            self.accepted_types = intel.accepted_vuln_types
        if intel.rejected_vuln_types:
            self.rejected_types = intel.rejected_vuln_types

        # Create filtering rules from policy
        for vt in self.accepted_types:
            self.custom_rules.append(PolicyRule(
                vuln_type=vt,
                allowed=True,
                notes="Accepted per program policy",
            ))
        for vt in self.rejected_types:
            self.custom_rules.append(PolicyRule(
                vuln_type=vt,
                allowed=False,
                notes="Rejected per program policy",
            ))

    def check_finding(self, finding: Dict[str, Any]) -> PolicyEnforcementResult:
        """Check if a finding passes policy enforcement (legacy wrapper).

        Internally runs the full 12-phase pipeline and maps the result
        back to the legacy PolicyEnforcementResult format.
        """
        output = self._run_full_pipeline(finding)
        title = finding.get("title", "Unknown Finding")
        vuln_type = finding.get("type", "").lower().replace(" ", "_")

        is_allowed = output.decision == PolicyDecision.ALLOW
        reason = self._format_reason(output)

        return PolicyEnforcementResult(
            finding_title=title,
            finding_type=vuln_type,
            policy_allowed=is_allowed,
            reason=reason,
            severity_override=None if is_allowed else "info",
            decision=output.decision,
            confidence=output.confidence,
            program_compliance_score=output.program_compliance_score,
            detailed_output=self._output_to_dict(output),
        )

    def batch_check(self, findings: List[Dict[str, Any]]) -> List[PolicyEnforcementResult]:
        """Check multiple findings against policy."""
        return [self.check_finding(f) for f in findings]

    def filter_allowed(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return only findings that pass policy (ALLOW only)."""
        results = self.batch_check(findings)
        return [f for f, r in zip(findings, results) if r.decision == PolicyDecision.ALLOW]

    def get_rejected_report(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return report of why findings were rejected or sent to review."""
        results = self.batch_check(findings)
        return [
            {
                "title": r.finding_title,
                "type": r.finding_type,
                "allowed": r.policy_allowed,
                "decision": r.decision.value,
                "reason": r.reason,
                "confidence": r.confidence,
                "compliance_score": r.program_compliance_score,
                "detailed_output": r.detailed_output,
            }
            for f, r in zip(findings, results) if r.decision != PolicyDecision.ALLOW
        ]

    def evaluate(self, finding: Dict[str, Any]) -> PolicyDecisionOutput:
        """Run the full 12-phase policy decision pipeline.

        This is the primary API for the new implementation.
        Returns the complete structured decision output.
        Fires a webhook with the decision result if configured.
        """
        output = self._run_full_pipeline(finding)

        # Fire webhook for every policy decision (non-blocking)
        if self.webhook_manager:
            try:
                # Use asyncio.create_task or ensure_future to fire without blocking
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._fire_decision_webhook(finding, output))
                else:
                    loop.run_until_complete(self._fire_decision_webhook(finding, output))
            except (RuntimeError, Exception) as e:
                # If no event loop is available, skip webhook silently
                pass

        return output

    async def _fire_decision_webhook(self, finding: Dict[str, Any], output: PolicyDecisionOutput):
        """Fire a webhook for the policy decision (async)."""
        if not self.webhook_manager:
            return
        await self.webhook_manager.fire_policy_decision(
            finding_title=finding.get("title", "Unknown Finding"),
            finding_type=finding.get("type", "unknown"),
            decision=output.decision.value,
            confidence=output.confidence,
            compliance_score=output.program_compliance_score,
            scope_status=output.scope_status,
            evidence_tier=output.evidence_tier,
            impact_status=output.impact_status,
            rejection_arguments=output.rejection_arguments,
            policy_citations=output.policy_citations,
            recommended_next_action=output.recommended_next_action,
            target=finding.get("target", ""),
            severity=finding.get("severity", "medium"),
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # FULL 12-PHASE PIPELINE
    # ═══════════════════════════════════════════════════════════════════════════

    def _run_full_pipeline(self, finding: Dict[str, Any]) -> PolicyDecisionOutput:
        """Execute all 12 phases in order. Short-circuits on REJECT."""
        output = PolicyDecisionOutput()
        phases_run = []

        # Phase 1: Scope Verification
        scope_result = self._phase1_scope(finding)
        phases_run.append("scope_verification")
        output.scope_status = scope_result.value
        if scope_result == ScopeStatus.OUT_OF_SCOPE:
            return self._finalize_reject(output, "Target is out of scope. Scope verification failed.", phases_run)
        if scope_result == ScopeStatus.UNCLEAR:
            output.uncertainties.append("Scope status is unclear — required evidence not available")

        # Phase 2: Asset Eligibility
        asset_result = self._phase2_asset(finding)
        phases_run.append("asset_eligibility")
        output.asset_eligibility = asset_result.value
        if asset_result == AssetEligibility.INELIGIBLE:
            return self._finalize_reject(output, "Asset is explicitly ineligible for reporting.", phases_run)
        if asset_result == AssetEligibility.UNCLEAR:
            output.uncertainties.append("Asset eligibility is unclear")

        # Phase 3: Testing Restriction Compliance
        testing_result = self._phase3_testing(finding)
        phases_run.append("testing_compliance")
        output.testing_compliance = testing_result.value
        if testing_result == TestingCompliance.NON_COMPLIANT:
            return self._finalize_reject(output, "Testing method violates program restrictions.", phases_run)
        if testing_result == TestingCompliance.UNCLEAR:
            output.uncertainties.append("Testing compliance is unclear")

        # Phase 4: Vulnerability Eligibility
        vuln_result = self._phase4_vulnerability(finding, output)
        phases_run.append("vulnerability_eligibility")
        output.vulnerability_eligibility = vuln_result.value
        if vuln_result == VulnEligibility.REJECTED:
            return self._finalize_reject(output, "Vulnerability class is explicitly rejected by program policy.", phases_run)
        if vuln_result == VulnEligibility.UNCLEAR:
            output.uncertainties.append("Vulnerability eligibility is unclear")

        # Phase 5: Evidence Sufficiency
        evidence_result = self._phase5_evidence(finding, output)
        phases_run.append("evidence_sufficiency")
        output.evidence_tier = evidence_result.value
        if evidence_result == EvidenceTier.TIER_0:
            return self._finalize_reject(output, "No evidence provided. Tier 0 evidence is insufficient for any finding.", phases_run)
        if evidence_result in (EvidenceTier.TIER_1, EvidenceTier.TIER_2):
            output.reasoning.append(f"Evidence is at {evidence_result.value} — needs improvement before ALLOW")
            output.uncertainties.append(f"Insufficient evidence tier: {evidence_result.value}")

        # Phase 6: Impact Sufficiency
        impact_ok = self._phase6_impact(finding)
        phases_run.append("impact_sufficiency")
        output.impact_status = "DEMONSTRATED" if impact_ok else "NOT_DEMONSTRATED"
        if not impact_ok:
            output.uncertainties.append("Impact not demonstrated — only hypothetical scenarios presented")

        # Phase 7: Duplicate Risk Analysis
        dup_result = self._phase7_duplicate(finding)
        phases_run.append("duplicate_risk")
        output.duplicate_risk = dup_result.value
        if dup_result in (DuplicateRisk.HIGH, DuplicateRisk.MEDIUM):
            output.uncertainties.append(f"Duplicate risk is {dup_result.value} — requires manual review")

        # Phase 8: Policy Contradiction Analysis
        contradictions = self._phase8_contradictions(finding, output)
        phases_run.append("policy_contradictions")
        for c in contradictions:
            output.policy_violations.append(c)
        if contradictions:
            output.reasoning.append(f"Found {len(contradictions)} policy contradiction(s) — contradictions cannot be resolved through assumptions, requiring REVIEW")
            # Per prompt: "If contradictions exist: REVIEW. Do not resolve conflicts through assumptions."
            output.uncertainties.append(f"Policy contradictions found ({len(contradictions)}) — cannot be resolved without manual review")

        # Phase 9: Program Compliance Score
        score = self._phase9_compliance_score(
            finding, scope_result, asset_result, testing_result,
            vuln_result, evidence_result, impact_ok,
        )
        phases_run.append("compliance_score")
        output.program_compliance_score = score

        # Phase 10: Triager Simulation
        triager = self._phase10_triager(finding, output)
        phases_run.append("triager_simulation")
        output.triager_assessment = triager

        # Phase 11: Adverse Review
        rejection_args = self._phase11_adverse(finding, output)
        phases_run.append("adverse_review")
        output.rejection_arguments = rejection_args

        # Phase 12: Hallucination Prevention
        hallucinations = self._phase12_hallucination(finding, output)
        phases_run.append("hallucination_prevention")
        output.assumptions = hallucinations

        # ── Final Decision ──
        output.reasoning.append("Full 12-phase pipeline completed")

        # Determine final decision based on accumulated findings
        final_decision = self._determine_final_decision(output)
        output.decision = final_decision

        # Set confidence and next action
        output.confidence = self._calculate_confidence(output)
        output.recommended_next_action = self._recommend_next_action(output)

        return output

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — SCOPE VERIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase1_scope(self, finding: Dict[str, Any]) -> ScopeStatus:
        """Verify: asset exists, asset identified, asset included in scope."""
        target = finding.get("target", finding.get("asset", "")).lower()
        endpoint = finding.get("endpoint", "").lower()

        if not target and not endpoint:
            return ScopeStatus.UNCLEAR

        # Check against program scope if available
        if self.program_intel:
            in_scope = [d.lower() for d in self.program_intel.in_scope_domains]
            out_scope = [d.lower() for d in self.program_intel.out_of_scope_domains]

            # Check if target is explicitly out of scope
            for excluded in out_scope:
                if excluded in target or target in excluded:
                    return ScopeStatus.OUT_OF_SCOPE

            # Check if target is in scope
            for included in in_scope:
                if included in target or target in included:
                    return ScopeStatus.IN_SCOPE

            # Not found in any scope list
            return ScopeStatus.UNCLEAR

        # Without program intelligence, assume in scope but flag uncertainty
        return ScopeStatus.UNCLEAR

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — ASSET ELIGIBILITY
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase2_asset(self, finding: Dict[str, Any]) -> AssetEligibility:
        """Verify: asset is reportable, eligible, not explicitly excluded."""
        target = finding.get("target", finding.get("asset", "")).lower()

        # Without specific data, default to ELIGIBLE with note
        if not target:
            return AssetEligibility.UNCLEAR

        # Check for known excluded asset types
        excluded_patterns = [
            "staging", "dev.", "localhost", "127.0.0.1",
            "internal", "admin.", "test.",
        ]
        for pattern in excluded_patterns:
            if pattern in target:
                return AssetEligibility.UNCLEAR

        return AssetEligibility.ELIGIBLE

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — TESTING RESTRICTION COMPLIANCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase3_testing(self, finding: Dict[str, Any]) -> TestingCompliance:
        """Determine whether testing violated restrictions."""
        method = finding.get("testing_method", finding.get("method", "")).lower()
        description = finding.get("description", "").lower()
        combined = f"{method} {description}"

        # Check against prohibited methods
        for prohibited in PROHIBITED_TESTING_METHODS:
            if prohibited in combined:
                return TestingCompliance.NON_COMPLIANT

        # Check program restrictions
        if self.program_intel and self.program_intel.testing_restrictions:
            for restriction in self.program_intel.testing_restrictions:
                if restriction.lower() in combined:
                    return TestingCompliance.NON_COMPLIANT

        return TestingCompliance.COMPLIANT

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4 — VULNERABILITY ELIGIBILITY
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase4_vulnerability(self, finding: Dict[str, Any], output: PolicyDecisionOutput) -> VulnEligibility:
        """Determine whether the vulnerability class is eligible.
        Also populates policy_citations per the citation requirement.
        """
        vuln_type = finding.get("type", "").lower().replace(" ", "_")

        if not vuln_type:
            return VulnEligibility.UNCLEAR

        # Check custom rules first (from program policy)
        for rule in self.custom_rules:
            if rule.vuln_type == vuln_type:
                citation = f"Policy rule for '{vuln_type}': {'accepted' if rule.allowed else 'rejected'} (notes: {rule.notes})"
                output.policy_citations.append(citation)
                return VulnEligibility.ACCEPTED if rule.allowed else VulnEligibility.REJECTED

        # Check rejected types
        if vuln_type in self.rejected_types:
            output.policy_citations.append(
                f"Vulnerability type '{vuln_type}' is in the default rejected types list (per standard bug bounty policy)"
            )
            return VulnEligibility.REJECTED

        # Check accepted types
        if vuln_type in self.accepted_types:
            output.policy_citations.append(
                f"Vulnerability type '{vuln_type}' is in the default accepted types list (per standard bug bounty policy)"
            )
            return VulnEligibility.ACCEPTED

        # Unknown type — require review
        output.policy_citations.append(
            f"Vulnerability type '{vuln_type}' is not defined in program policy — no policy support for decision"
        )
        return VulnEligibility.UNCLEAR

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5 — EVIDENCE SUFFICIENCY
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase5_evidence(self, finding: Dict[str, Any], output: PolicyDecisionOutput) -> EvidenceTier:
        """Evaluate evidence quality on a 5-tier scale.
        Populates supporting_evidence from the finding's evidence.
        """
        evidence = finding.get("evidence", finding.get("proof_of_concept", {}))
        reproduction_steps = finding.get("reproduction_steps", [])

        # Populate supporting_evidence from available data
        if isinstance(evidence, dict):
            for key, val in evidence.items():
                if val and isinstance(val, str) and len(val) > 5:
                    output.supporting_evidence.append(f"Evidence '{key}' provided: {val[:100]}{'...' if len(val) > 100 else ''}")
                elif val and isinstance(val, (int, float, bool)):
                    output.supporting_evidence.append(f"Evidence '{key}': {val}")
        if reproduction_steps:
            for i, step in enumerate(reproduction_steps):
                output.supporting_evidence.append(f"Reproduction step {i+1}: {step[:100]}{'...' if len(step) > 100 else ''}")

        # Direct proof (Tier 4)
        if isinstance(evidence, dict) and any(k in evidence for k in [
            "request", "response", "screenshot", "log", "payload", "direct_proof",
        ]):
            # Verify at least one of these has actual content
            for key in ["request", "response", "screenshot", "payload"]:
                if evidence.get(key):
                    output.supporting_evidence.append(f"Direct proof found: '{key}' contains evidence data")
                    return EvidenceTier.TIER_4

        # Reproducible evidence (Tier 3)
        if reproduction_steps and len(reproduction_steps) >= 1:
            output.supporting_evidence.append(f"Reproduction steps available ({len(reproduction_steps)} steps)")
            if isinstance(evidence, dict) and len(evidence) >= 2:
                return EvidenceTier.TIER_3
            return EvidenceTier.TIER_2

        # Multiple observations (Tier 2)
        if isinstance(evidence, (dict, list)) and len(evidence) >= 2:
            return EvidenceTier.TIER_2

        # Single observation (Tier 1)
        if evidence:
            return EvidenceTier.TIER_1

        # No evidence (Tier 0)
        output.supporting_evidence.append("No evidence provided with finding")
        return EvidenceTier.TIER_0

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6 — IMPACT SUFFICIENCY
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase6_impact(self, finding: Dict[str, Any]) -> bool:
        """Determine whether impact is demonstrated vs hypothetical."""
        impact = finding.get("impact", finding.get("business_impact", "")).lower()
        description = finding.get("description", "").lower()
        combined = f"{impact} {description}"

        # Demonstrated impact indicators
        demonstrated_indicators = [
            "unauthorized access", "privilege escalation",
            "account takeover", "sensitive data exposure",
            "unauthorized actions", "data exfiltration",
            "authentication bypass", "authorization bypass",
            "remote code execution", "arbitrary file read",
            "arbitrary file write", "sql injection demonstrated",
            "xss demonstrated", "ssrf demonstrated",
        ]

        # Hypothetical indicators
        hypothetical_indicators = [
            "could lead to", "could potentially", "might allow",
            "hypothetical", "theoretical", "speculative",
            "in theory", "assume", "if an attacker could",
        ]

        has_demonstrated = any(ind in combined for ind in demonstrated_indicators)
        has_hypothetical = any(ind in combined for ind in hypothetical_indicators)

        if has_demonstrated:
            return True
        if has_hypothetical and not has_demonstrated:
            return False

        # Default: if no impact information, flag as not demonstrated
        return False

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7 — DUPLICATE RISK ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase7_duplicate(self, finding: Dict[str, Any]) -> DuplicateRisk:
        """Assess duplicate risk based on known patterns."""
        # Check for known duplicate indicators
        description = finding.get("description", "").lower()
        vuln_type = finding.get("type", "").lower()

        common_findings = [
            "missing security headers", "version disclosure",
            "server banner", "x-powered-by", "x-frame-options",
        ]

        for common in common_findings:
            if common in description or common in vuln_type:
                return DuplicateRisk.HIGH

        # Check for well-known issue indicators
        well_known = [
            "self-xss", "clickjacking without impact",
            "email enumeration", "user enumeration",
        ]
        for wk in well_known:
            if wk in vuln_type:
                return DuplicateRisk.MEDIUM

        return DuplicateRisk.LOW

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8 — POLICY CONTRADICTION ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase8_contradictions(self, finding: Dict[str, Any], output: PolicyDecisionOutput) -> List[str]:
        """Identify scope, restriction, policy, or reward conflicts.
        Per prompt: "If contradictions exist: REVIEW. Do not resolve conflicts through assumptions."
        """
        contradictions: List[str] = []
        vuln_type = finding.get("type", "").lower().replace(" ", "_")

        # Check if vulnerability type is in both accepted and rejected lists
        if vuln_type in self.accepted_types and vuln_type in self.rejected_types:
            contradictions.append(
                f"Vulnerability type '{vuln_type}' appears in both accepted and rejected lists — this is a direct policy conflict"
            )
            output.policy_citations.append(
                f"CONTRADICTION: '{vuln_type}' is listed as both accepted and rejected — no reliable policy position"
            )

        # Check for scope conflicts
        target = finding.get("target", "").lower()
        if self.program_intel:
            in_scope = [d.lower() for d in self.program_intel.in_scope_domains]
            out_scope = [d.lower() for d in self.program_intel.out_of_scope_domains]
            for inc in in_scope:
                for exc in out_scope:
                    if inc == exc:
                        contradictions.append(
                            f"Domain '{inc}' found in both in-scope and out-of-scope lists — scope definition is contradictory"
                        )
                        output.policy_citations.append(
                            f"CONTRADICTION: '{inc}' is in both in-scope and out-of-scope lists"
                        )

        return contradictions

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 9 — PROGRAM COMPLIANCE SCORE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase9_compliance_score(
        self,
        finding: Dict[str, Any],
        scope: ScopeStatus,
        asset: AssetEligibility,
        testing: TestingCompliance,
        vuln: VulnEligibility,
        evidence: EvidenceTier,
        impact: bool,
    ) -> int:
        """Calculate compliance score 0-100."""
        score = 0.0

        # Scope compliance (25 points max)
        if scope == ScopeStatus.IN_SCOPE:
            score += 25
        elif scope == ScopeStatus.UNCLEAR:
            score += 12

        # Policy compliance (20 points max)
        if vuln == VulnEligibility.ACCEPTED:
            score += 20
        elif vuln == VulnEligibility.UNCLEAR:
            score += 10

        # Testing compliance (15 points max)
        if testing == TestingCompliance.COMPLIANT:
            score += 15
        elif testing == TestingCompliance.UNCLEAR:
            score += 7

        # Evidence quality (25 points max)
        evidence_scores = {
            EvidenceTier.TIER_4: 25,
            EvidenceTier.TIER_3: 20,
            EvidenceTier.TIER_2: 12,
            EvidenceTier.TIER_1: 5,
            EvidenceTier.TIER_0: 0,
        }
        score += evidence_scores.get(evidence, 0)

        # Impact quality (15 points max)
        if impact:
            score += 15
        else:
            score += 5

        return int(min(score, 100))

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 10 — TRIAGER SIMULATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase10_triager(self, finding: Dict[str, Any], output: PolicyDecisionOutput) -> List[str]:
        """Simulate an experienced bug bounty triager."""
        assessments: List[str] = []
        vuln_type = finding.get("type", "").lower()
        description = finding.get("description", "").lower()

        # 1. Would this likely be accepted?
        if output.program_compliance_score >= 80:
            assessments.append("Likely accepted — strong compliance with program policy")
        elif output.program_compliance_score >= 60:
            assessments.append("Possibly accepted — moderate compliance, may require clarification")
        else:
            assessments.append("Likely rejected or marked informative — weak compliance")

        # 2. Would this likely be marked informative?
        if output.evidence_tier in (EvidenceTier.TIER_0.value, EvidenceTier.TIER_1.value):
            assessments.append("High risk of 'informative' marking — insufficient evidence")
        elif output.impact_status == "NOT_DEMONSTRATED":
            assessments.append("Risk of 'informative' — impact not clearly demonstrated")

        # 3. Would this likely be marked out of scope?
        if output.scope_status == ScopeStatus.UNCLEAR.value:
            assessments.append("Scope is unclear — risk of out-of-scope rejection")

        # 4. Would this likely be marked duplicate?
        if output.duplicate_risk in (DuplicateRisk.HIGH.value, DuplicateRisk.MEDIUM.value):
            assessments.append(f"Duplicate risk is {output.duplicate_risk} — likely marked as duplicate")

        # 5. Would this likely be rejected for insufficient evidence?
        if output.evidence_tier in (EvidenceTier.TIER_0.value, EvidenceTier.TIER_1.value):
            assessments.append("High rejection risk — insufficient evidence")
        elif output.evidence_tier == EvidenceTier.TIER_2.value and output.impact_status == "NOT_DEMONSTRATED":
            assessments.append("Rejection risk — evidence exists but impact not demonstrated")

        # 6. Strongest argument against acceptance
        weakest_points = []
        if output.scope_status != ScopeStatus.IN_SCOPE.value:
            weakest_points.append("scope not confirmed as in-scope")
        if output.evidence_tier in (EvidenceTier.TIER_0.value, EvidenceTier.TIER_1.value):
            weakest_points.append("evidence is insufficient")
        if output.impact_status == "NOT_DEMONSTRATED":
            weakest_points.append("impact is not demonstrated")
        if output.duplicate_risk in (DuplicateRisk.HIGH.value, DuplicateRisk.MEDIUM.value):
            weakest_points.append(f"duplicate risk is {output.duplicate_risk}")

        if weakest_points:
            assessments.append(f"Strongest argument against acceptance: {' + '.join(weakest_points)}")
        else:
            assessments.append("No strong arguments against acceptance identified")

        return assessments

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 11 — ADVERSE REVIEW
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase11_adverse(self, finding: Dict[str, Any], output: PolicyDecisionOutput) -> List[str]:
        """Actively attempt to reject the finding. Generate rejection arguments."""
        rejection_args: List[str] = []

        # Policy violations
        if output.scope_status == ScopeStatus.UNCLEAR.value:
            rejection_args.append("Scope cannot be confirmed — asset may be out of scope")
        if output.vulnerability_eligibility == VulnEligibility.UNCLEAR.value:
            rejection_args.append(f"Vulnerability type '{finding.get('type', 'unknown')}' not explicitly covered by policy")

        # Evidence gaps
        evidence = finding.get("evidence", {})
        if not evidence:
            rejection_args.append("No evidence provided — finding cannot be validated")
        elif output.evidence_tier in (EvidenceTier.TIER_1.value, EvidenceTier.TIER_2.value):
            rejection_args.append("Evidence is insufficient for a conclusive determination")

        # Impact inflation
        description = finding.get("description", "").lower()
        if "could lead to" in description and not any(ind in description for ind in [
            "demonstrated", "proven", "confirmed", "verified",
        ]):
            rejection_args.append("Impact appears speculative — 'could lead to' without demonstration")

        # Unsupported assumptions
        if "assume" in description or "likely" in description:
            rejection_args.append("Finding relies on assumptions rather than evidence")

        return rejection_args

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 12 — HALLUCINATION PREVENTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase12_hallucination(self, finding: Dict[str, Any], output: PolicyDecisionOutput) -> List[str]:
        """Before every decision, verify evidence support for each claim."""
        assumptions: List[str] = []
        description = finding.get("description", "")

        # Check for unsupported claims
        if output.scope_status == ScopeStatus.IN_SCOPE.value and not self.program_intel:
            assumptions.append("In-scope assumption: no program scope data available to verify")

        if output.asset_eligibility == AssetEligibility.ELIGIBLE.value and not finding.get("asset"):
            assumptions.append("Asset eligibility: no asset identifier provided")

        if output.impact_status == "DEMONSTRATED":
            impact_text = finding.get("impact", "").lower()
            if not impact_text:
                assumptions.append("Impact assumption: labeled as demonstrated but no impact description found")

        # Evidence overrides assumptions
        evidence = finding.get("evidence", {})
        if evidence and output.evidence_tier == EvidenceTier.TIER_0:
            assumptions.append("Evidence contradiction: evidence object exists but was classified as Tier 0")

        # Policy overrides preferences
        vuln_type = finding.get("type", "").lower().replace(" ", "_")
        if vuln_type and vuln_type not in self.accepted_types and vuln_type not in self.rejected_types:
            assumptions.append(f"Policy gap: vulnerability type '{vuln_type}' not defined in program policy")

        return assumptions

    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL DECISION DETERMINATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _determine_final_decision(self, output: PolicyDecisionOutput) -> PolicyDecision:
        """Determine final ALLOW / REVIEW / REJECT based on all phases."""
        # If any rejection arguments couldn't be disproven → REVIEW
        if output.rejection_arguments and not self._can_disprove_rejection_arguments(output):
            return PolicyDecision.REVIEW

        # If there are any uncertainties → REVIEW (fail-closed)
        if output.uncertainties:
            return PolicyDecision.REVIEW

        # If evidence is insufficient → REVIEW
        if output.evidence_tier in (EvidenceTier.TIER_1.value, EvidenceTier.TIER_2.value):
            return PolicyDecision.REVIEW

        # If impact not demonstrated → REVIEW
        if output.impact_status == "NOT_DEMONSTRATED":
            return PolicyDecision.REVIEW

        # If duplicate risk is high → REVIEW
        if output.duplicate_risk in (DuplicateRisk.HIGH.value, DuplicateRisk.MEDIUM.value):
            return PolicyDecision.REVIEW

        # If compliance score is below threshold → REVIEW
        if output.program_compliance_score < 70:
            return PolicyDecision.REVIEW

        # All checks passed → ALLOW
        if (output.scope_status == ScopeStatus.IN_SCOPE.value
                and output.vulnerability_eligibility == VulnEligibility.ACCEPTED.value
                and output.evidence_tier in (EvidenceTier.TIER_3.value, EvidenceTier.TIER_4.value)
                and output.impact_status == "DEMONSTRATED"
                and output.program_compliance_score >= 80):
            return PolicyDecision.ALLOW

        # Default: REVIEW (fail-closed)
        return PolicyDecision.REVIEW

    def _can_disprove_rejection_arguments(self, output: PolicyDecisionOutput) -> bool:
        """Check if there's strong enough evidence to override rejection arguments."""
        # Only ALLOW if evidence is Tier 4 AND impact is demonstrated
        if (output.evidence_tier == EvidenceTier.TIER_4.value
                and output.impact_status == "DEMONSTRATED"
                and output.program_compliance_score >= 90):
            return True
        return False

    def _calculate_confidence(self, output: PolicyDecisionOutput) -> float:
        """Calculate overall confidence score 0.0-1.0."""
        base = 0.0

        # Base from compliance score
        base += (output.program_compliance_score / 100) * 0.4

        # Evidence quality contribution
        evidence_weights = {
            EvidenceTier.TIER_4.value: 0.3,
            EvidenceTier.TIER_3.value: 0.25,
            EvidenceTier.TIER_2.value: 0.15,
            EvidenceTier.TIER_1.value: 0.05,
            EvidenceTier.TIER_0.value: 0.0,
        }
        base += evidence_weights.get(output.evidence_tier, 0.0)

        # Impact contribution
        if output.impact_status == "DEMONSTRATED":
            base += 0.2

        # Uncertainty penalty
        uncertainty_penalty = len(output.uncertainties) * 0.05
        base = max(0.0, base - uncertainty_penalty)

        # Rejection argument penalty
        rejection_penalty = len(output.rejection_arguments) * 0.05
        base = max(0.0, base - rejection_penalty)

        return round(min(base, 1.0), 2)

    def _recommend_next_action(self, output: PolicyDecisionOutput) -> str:
        """Generate a recommended next action based on the decision."""
        if output.decision == PolicyDecision.ALLOW:
            return "PROCEED_TO_VALIDATION — Finding is eligible for further validation"

        if output.decision == PolicyDecision.REJECT:
            strongest_reason = ""
            if output.scope_status == ScopeStatus.OUT_OF_SCOPE.value:
                strongest_reason = "out-of-scope target"
            elif output.vulnerability_eligibility == VulnEligibility.REJECTED.value:
                strongest_reason = "rejected vulnerability class"
            elif output.evidence_tier == EvidenceTier.TIER_0.value:
                strongest_reason = "no evidence provided"
            return f"DO_NOT_REPORT — Rejected due to {strongest_reason}"

        # REVIEW case — identify what needs improvement
        improvements = []
        if output.scope_status != ScopeStatus.IN_SCOPE.value:
            improvements.append("confirm target is in scope")
        if output.evidence_tier in (EvidenceTier.TIER_1.value, EvidenceTier.TIER_2.value, EvidenceTier.TIER_0.value):
            improvements.append("provide stronger evidence (requests, responses, reproduction steps)")
        if output.impact_status == "NOT_DEMONSTRATED":
            improvements.append("demonstrate actual impact with evidence")
        if output.duplicate_risk in (DuplicateRisk.HIGH.value, DuplicateRisk.MEDIUM.value):
            improvements.append("check for and address duplicate indicators")

        if improvements:
            return f"REQUIRES_MANUAL_REVIEW — Collect more information: {'; '.join(improvements)}"
        return "REQUIRES_MANUAL_REVIEW — Insufficient information for automated decision"

    def _finalize_reject(
        self, output: PolicyDecisionOutput, reason: str, phases_run: List[str]
    ) -> PolicyDecisionOutput:
        """Short-circuit and return a REJECT decision with proportional confidence."""
        output.decision = PolicyDecision.REJECT
        output.reasoning.append(reason)
        output.recommended_next_action = f"DO_NOT_REPORT — {reason}"

        # Calculate proportional confidence based on rejection cause
        if "out of scope" in reason.lower() or "rejected vulnerability" in reason.lower():
            # Clear policy-based rejection — highest confidence
            output.confidence = 0.95
        elif "no evidence" in reason.lower() or "tier 0" in reason.lower():
            # Clear evidence failure — high confidence
            output.confidence = 0.90
        elif "ineligible" in reason.lower():
            # Asset eligibility — high confidence
            output.confidence = 0.85
        elif "testing method" in reason.lower() or "violates" in reason.lower():
            # Testing restriction violation — high confidence
            output.confidence = 0.90
        else:
            # Default high confidence for rejection
            output.confidence = 0.85

        return output

    def _format_reason(self, output: PolicyDecisionOutput) -> str:
        """Format the decision output into a human-readable reason string."""
        reasons = []
        if output.decision == PolicyDecision.ALLOW:
            reasons.append(f"Finding ALLOWed (confidence: {output.confidence}, compliance: {output.program_compliance_score})")
        elif output.decision == PolicyDecision.REJECT:
            reasons.append(f"Finding REJECTed (confidence: {output.confidence})")
            if output.policy_violations:
                reasons.append(f"Violations: {'; '.join(output.policy_violations[:3])}")
        else:
            reasons.append(f"Finding requires REVIEW (confidence: {output.confidence})")
            uncertainties = output.uncertainties[:3]
            if uncertainties:
                reasons.append(f"Uncertainties: {'; '.join(uncertainties)}")

        return " — ".join(reasons)

    def _output_to_dict(self, output: PolicyDecisionOutput) -> Dict[str, Any]:
        """Convert PolicyDecisionOutput to a serializable dict."""
        return {
            "decision": output.decision.value,
            "confidence": output.confidence,
            "program_compliance_score": output.program_compliance_score,
            "scope_status": output.scope_status,
            "asset_eligibility": output.asset_eligibility,
            "testing_compliance": output.testing_compliance,
            "vulnerability_eligibility": output.vulnerability_eligibility,
            "evidence_tier": output.evidence_tier,
            "impact_status": output.impact_status,
            "duplicate_risk": output.duplicate_risk,
            "policy_violations": output.policy_violations,
            "policy_citations": output.policy_citations,
            "supporting_evidence": output.supporting_evidence,
            "rejection_arguments": output.rejection_arguments,
            "triager_assessment": output.triager_assessment,
            "uncertainties": output.uncertainties,
            "assumptions": output.assumptions,
            "reasoning": output.reasoning,
            "recommended_next_action": output.recommended_next_action,
        }
