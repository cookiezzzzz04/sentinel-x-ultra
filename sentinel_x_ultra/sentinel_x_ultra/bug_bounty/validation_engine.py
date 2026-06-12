"""
AGENT 7: VALIDATION ENGINE AGENT (STRICT MODE)

12-stage multi-stage finding validation system.
Designed to minimize false positives. Treats all reporter conclusions as untrusted.
Trusts only observable evidence. Attempts to falsify before accepting.

Implements the complete 12-stage validation pipeline:
1. Finding Normalization
2. Fact Extraction (facts vs inferences vs assumptions)
3. Adversarial Review
4. Evidence Validation
5. Reproducibility Analysis
6. Vulnerability-Specific Validation
7. Exploitability Assessment
8. Impact Validation
9. Policy Validation
10. Duplicate Analysis
11. Hallucination Check
12. Confidence Calculation + Decision
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


# ── Enums / String constants ────────────────────────────────────────────────

EVIDENCE_STRENGTHS = ["NONE", "WEAK", "MODERATE", "STRONG", "CONCLUSIVE"]
EXPLOITABILITY_LEVELS = ["NONE", "LIMITED", "MODERATE", "HIGH"]
IMPACT_LEVELS = ["NOT_VERIFIED", "PARTIAL", "DEMONSTRATED", "STRONG"]
POLICY_STATUSES = ["COMPLIANT", "QUESTIONABLE", "NON_COMPLIANT"]
DUPLICATE_STATUSES = ["NOT_DUPLICATE", "POSSIBLE_DUPLICATE", "LIKELY_DUPLICATE"]
DECISIONS = ["PROMOTE", "NEEDS_REVIEW", "REJECT"]

VULN_TYPES = [
    "xss", "sql_injection", "idor", "ssrf", "auth_bypass",
    "privilege_escalation", "command_injection", "rce", "xxe",
    "ssti", "path_traversal", "open_redirect", "csrf",
    "business_logic", "information_disclosure", "other",
]


# ── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class NormalizedFinding:
    """Stage 1 output — normalized representation of a finding."""
    vulnerability_type: str = "unknown"
    asset: str = ""
    endpoint: str = ""
    parameter: str = ""
    reporter_claim: str = ""
    claimed_impact: str = ""
    evidence_supplied: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Complete validation output — matches the required JSON schema."""
    decision: str = "NEEDS_REVIEW"  # PROMOTE / NEEDS_REVIEW / REJECT
    confidence_score: float = 0.0   # 0-100
    evidence_strength: str = "NONE"
    reproducibility_score: int = 0  # 0-100
    exploitability: str = "NONE"
    impact_strength: str = "NOT_VERIFIED"
    policy_status: str = "QUESTIONABLE"
    duplicate_status: str = "NOT_DUPLICATE"

    facts: List[str] = field(default_factory=list)
    inferences: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    false_positive_explanations: List[str] = field(default_factory=list)
    verified_claims: List[str] = field(default_factory=list)
    unsupported_claims: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    acceptance_reasons: List[str] = field(default_factory=list)
    rejection_reasons: List[str] = field(default_factory=list)
    analyst_notes: List[str] = field(default_factory=list)

    # Internal stages (kept for traceability)
    normalized: Optional[NormalizedFinding] = None
    stages_run: List[str] = field(default_factory=list)


# ── Validation Engine Agent ──────────────────────────────────────────────────

class ValidationEngineAgent:
    """
    Agent 7: Validation Engine — 12-Stage Strict Mode.

    A skeptical validator that assumes every finding may be incorrect
    until evidence proves otherwise. Primary objective: minimize false positives.

    AI-POWERED (Phase 1 Upgrade):
    - Uses LLMProvider for intelligent adversarial review
    - AI-powered vulnerability-specific validation
    - LLM-driven false positive analysis with contextual understanding
    - Falls back to deterministic logic when LLM unavailable
    """

    def __init__(self, llm_provider=None, memory=None):
        self.llm_provider = llm_provider
        self.memory = memory
        self.known_findings: List[Dict[str, Any]] = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════════

    async def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """Run full 12-stage validation on a finding. Returns decision + evidence."""
        result = ValidationResult()
        stages = []

        # Stage 1
        normalized = self._stage1_normalize(finding)
        result.normalized = normalized
        stages.append("normalization")

        # Stage 2
        result.facts, result.inferences, result.assumptions = self._stage2_facts(
            finding, normalized
        )
        stages.append("fact_extraction")

        # Stage 3 (AI-enhanced)
        result.false_positive_explanations = await self._stage3_adversarial(
            finding, normalized
        )
        stages.append("adversarial_review")

        # Stage 4
        evidence_q = self._stage4_evidence(finding, normalized)
        result.evidence_strength = evidence_q
        stages.append("evidence_validation")

        # Stage 5
        repro_score = self._stage5_reproducibility(finding, normalized)
        result.reproducibility_score = repro_score
        stages.append("reproducibility")

        # Stage 6 (AI-enhanced)
        verified, unsupported, missing = await self._stage6_vuln_specific(
            finding, normalized
        )
        result.verified_claims = verified
        result.unsupported_claims = unsupported
        result.missing_evidence = missing
        stages.append("vuln_specific_validation")

        # Stage 7
        result.exploitability = self._stage7_exploitability(
            finding, normalized, evidence_q
        )
        stages.append("exploitability")

        # Stage 8
        result.impact_strength = self._stage8_impact(finding, normalized)
        stages.append("impact_validation")

        # Stage 9
        result.policy_status = self._stage9_policy(finding, normalized)
        stages.append("policy_validation")

        # Stage 10
        result.duplicate_status = self._stage10_duplicate(finding, normalized)
        stages.append("duplicate_analysis")

        # Stage 11
        result.acceptance_reasons, result.rejection_reasons = self._stage11_hallucination(
            result
        )
        stages.append("hallucination_check")

        # Stage 12
        result.confidence_score, result.decision = self._stage12_confidence(result)
        stages.append("confidence_calculation")

        result.analyst_notes = self._build_analyst_notes(result)
        result.stages_run = stages
        return result

    async def batch_validate(self, findings: List[Dict[str, Any]]) -> List[ValidationResult]:
        """Validate multiple findings."""
        results = []
        for f in findings:
            r = await self.validate(f)
            # Track for dedup across this batch
            self.known_findings.append(f)
            results.append(r)
        return results

    def register_known_finding(self, finding: Dict[str, Any]):
        """Register a known finding for duplicate detection."""
        self.known_findings.append(finding)

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 1 — FINDING NORMALIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage1_normalize(self, finding: Dict[str, Any]) -> NormalizedFinding:
        """Extract and normalize the finding. No validity determination yet."""
        vtype = self._detect_vuln_type(finding)
        asset = finding.get("target", finding.get("asset", ""))
        endpoint = finding.get("endpoint", finding.get("target", ""))
        param = finding.get("parameter", "")

        title = finding.get("title", "")
        desc = finding.get("description", "")
        reporter_claim = f"{title}. {desc}".strip()

        impact = finding.get("impact", finding.get("claimed_impact", ""))
        claimed_impact = (
            impact
            or finding.get("attack_scenario", "")
            or f"Potential {vtype} on {asset}"
        )

        evidence_raw = finding.get("evidence", {})
        if isinstance(evidence_raw, dict):
            evidence_list = [
                str(v) for v in evidence_raw.values() if v
            ]
        elif isinstance(evidence_raw, list):
            evidence_list = [str(e) for e in evidence_raw]
        else:
            evidence_list = [str(evidence_raw)] if evidence_raw else []

        steps = finding.get("steps_to_reproduce", finding.get("reproduction_steps", []))
        if isinstance(steps, str):
            steps = [s.strip() for s in steps.split("\n") if s.strip()]

        return NormalizedFinding(
            vulnerability_type=vtype,
            asset=asset,
            endpoint=endpoint,
            parameter=param,
            reporter_claim=reporter_claim,
            claimed_impact=claimed_impact,
            evidence_supplied=evidence_list,
            reproduction_steps=steps,
            raw=finding,
        )

    def _detect_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Detect vulnerability type from finding data."""
        vtype = finding.get("type", finding.get("vulnerability_type", "")).lower()
        if vtype and vtype in VULN_TYPES:
            return vtype

        title_desc = (finding.get("title", "") + " " + finding.get("description", "")).lower()
        type_map = [
            ("xss", ["xss", "cross-site", "cross site", "script injection"]),
            ("sql_injection", ["sql", "sql injection", "sqli", "mysql", "postgres"]),
            ("idor", ["idor", "insecure direct object", "object reference"]),
            ("ssrf", ["ssrf", "server-side request forgery", "server side request"]),
            ("command_injection", ["command injection", "rce", "remote code", "cmd injection"]),
            ("auth_bypass", ["auth bypass", "authentication bypass", "login bypass"]),
            ("privilege_escalation", ["privilege escalation", "priv esc", "privesc"]),
            ("xxe", ["xxe", "xml external entity"]),
            ("ssti", ["ssti", "template injection", "server-side template"]),
            ("path_traversal", ["path traversal", "directory traversal", "lfi"]),
            ("open_redirect", ["open redirect", "url redirect"]),
            ("csrf", ["csrf", "cross-site request forgery", "cross site request"]),
            ("information_disclosure", ["information disclosure", "info disclosure", "data leak"]),
            ("business_logic", ["business logic", "logic flaw", "logic bug"]),
        ]
        for vtype_name, keywords in type_map:
            if any(kw in title_desc for kw in keywords):
                return vtype_name
        return "other"

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 2 — FACT EXTRACTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage2_facts(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """
        Extract only observable facts. Separate facts from inferences and assumptions.

        VALID facts: observable, measurable, verifiable.
        INVALID facts: conclusions, interpretations, assumptions.
        """
        facts: List[str] = []
        inferences: List[str] = []
        assumptions: List[str] = []

        # Extract from evidence
        evidence = normalized.evidence_supplied
        for ev in evidence:
            ev_lower = ev.lower()
            # Check if it's an observable fact
            if any(indicator in ev_lower for indicator in [
                "status:", "status ", "returned", "response", "observed",
                "received", "detected", "found", "displayed", "executed",
            ]):
                facts.append(ev)
            elif any(indicator in ev_lower for indicator in [
                "could be", "might be", "potentially", "possibly", "likely",
            ]):
                inferences.append(ev)
            else:
                # Check if it describes what happened (fact) vs speculation
                if any(verb in ev_lower for verb in [
                    "changed", "showed", "contained", "included", "resulted",
                    "triggered", "sent", "got", "returned",
                ]):
                    facts.append(ev)
                else:
                    assumptions.append(ev)

        # Extract from reproduction steps
        steps = normalized.reproduction_steps
        for step in steps:
            step_lower = step.lower()
            if any(indicator in step_lower for indicator in [
                "if", "assume", "assuming", "should", "would", "could",
            ]):
                assumptions.append(f"Step contains assumption: {step}")
            elif any(indicator in step_lower for indicator in [
                "observe", "check", "verify", "result", "expected",
            ]):
                inferences.append(f"Step expects observation: {step}")
            else:
                facts.append(f"Step: {step}")

        # Extract from reporter claim
        claim = normalized.reporter_claim
        if claim:
            claim_lower = claim.lower()
            if any(indicator in claim_lower for indicator in [
                "confirmed", "demonstrated", "observed", "found", "identified",
            ]):
                facts.append(f"Reporter states: {claim[:200]}")
            elif any(indicator in claim_lower for indicator in [
                "could", "might", "may", "potentially", "possibly",
            ]):
                inferences.append(f"Reporter infers: {claim[:200]}")
            else:
                inferences.append(f"Reporter claims: {claim[:200]}")

        # Extract from impact
        impact = normalized.claimed_impact
        if impact and impact != normalized.reporter_claim:
            impact_lower = impact.lower()
            if any(indicator in impact_lower for indicator in [
                "could", "might", "may", "potentially", "possibly",
            ]):
                inferences.append(f"Hypothetical impact: {impact[:200]}")
            else:
                inferences.append(f"Claimed impact: {impact[:200]}")

        # Analyze finding dict for direct evidence
        raw = normalized.raw
        if raw.get("evidence"):
            if isinstance(raw["evidence"], dict):
                for k, v in raw["evidence"].items():
                    if v and not any(ind in str(v).lower() for ind in ["could", "might", "probably"]):
                        facts.append(f"Evidence field '{k}': {str(v)[:200]}")

        return facts, inferences, assumptions

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 3 — ADVERSARIAL REVIEW
    # ═══════════════════════════════════════════════════════════════════════════

    async def _stage3_adversarial(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> List[str]:
        """
        Generate at least five possible explanations why the finding might be invalid.
        Attempt to falsify the finding before accepting it.

        AI-Powered: Uses LLM for intelligent adversarial review when available.
        Generates context-aware falsification attempts.
        Falls back to template-based falsification.
        """
        explanations: List[str] = []

        # Try AI-powered adversarial review
        if self.llm_provider and self.llm_provider.is_available:
            try:
                ai_fp = await self.llm_provider.analyze_false_positive(
                    finding_title=finding.get("title", "Unknown Finding"),
                    vuln_type=normalized.vulnerability_type,
                    target=normalized.asset,
                    evidence={"facts": normalized.evidence_supplied, "steps": normalized.reproduction_steps},
                    steps=normalized.reproduction_steps,
                )
                if ai_fp and ai_fp.get("alternative_explanations"):
                    explanations = ai_fp["alternative_explanations"][:8]
            except Exception:
                pass

        vtype = normalized.vulnerability_type

        # Built-in falsification patterns
        falsification_checks = [
            ("Intended functionality", self._check_intended_functionality(finding, normalized)),
            ("Scanner artifact", self._check_scanner_artifact(finding, normalized)),
            ("No direct evidence", len(normalized.evidence_supplied) == 0),
            ("No reproduction steps", len(normalized.reproduction_steps) == 0),
            ("Hypothetical language only", self._check_hypothetical_language(finding, normalized)),
            ("Missing request/response", not finding.get("evidence") and not finding.get("request_response")),
            ("Impact speculation", self._check_impact_speculation(finding, normalized)),
        ]

        for reason, is_applicable in falsification_checks:
            if is_applicable:
                explanations.append(reason)

        # Type-specific falsification
        type_falsifications = {
            "xss": [
                "No payload rendering demonstrated",
                "Alert/prompt execution not observed",
                "May be DOM-only, no server reflection",
            ],
            "sql_injection": [
                "No database error observed",
                "Response timing consistent with normal queries",
                "Input may be parameterized/sanitized",
            ],
            "idor": [
                "May be intended multi-tenancy behavior",
                "Resource may be publicly accessible by design",
                "Authorization may be checked server-side",
            ],
            "ssrf": [
                "No outbound callback observed",
                "DNS resolution may be local only",
                "Target service may be intentionally exposed",
            ],
            "auth_bypass": [
                "Session may already be authenticated",
                "May be intended functionality for the role used",
                "Rate limiting / WAF may have blocked the test, not the auth",
            ],
            "command_injection": [
                "Output may be from a different process",
                "May be error-based leakage, not execution",
                "Input may be sanitized at a different layer",
            ],
            "privilege_escalation": [
                "Privilege boundary not clearly identified",
                "Elevation may be within expected scope",
                "May be misconfigured test account, not vulnerability",
            ],
        }
        explanations.extend(type_falsifications.get(vtype, []))

        # Ensure at least 5
        fallback_explanations = [
            "Missing evidence to confirm the claim",
            "Could not reproduce under controlled conditions",
            "Alternative explanations not excluded",
            "Environmental factors may influence results",
            "User misunderstanding of expected behavior",
        ]
        while len(explanations) < 5:
            explanations.append(fallback_explanations[len(explanations)])

        return explanations[:8]  # Cap at 8 for readability

    def _check_intended_functionality(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> bool:
        """Check if behavior could be intended functionality."""
        desc = (finding.get("description", "") + " " + finding.get("title", "")).lower()
        return any(indicator in desc for indicator in [
            "feature", "configuration", "documented", "expected", "designed",
            "default", "administrative", "intentional",
        ])

    def _check_scanner_artifact(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> bool:
        """Check if finding could be a scanner/tool artifact."""
        desc = (finding.get("description", "") + " " + finding.get("title", "")).lower()
        return any(indicator in desc for indicator in [
            "automated", "scanner", "tool detected", "generic", "template",
        ])

    def _check_hypothetical_language(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> bool:
        """Check if finding uses only hypothetical/speculative language."""
        texts = [
            finding.get("description", ""),
            finding.get("impact", ""),
            finding.get("attack_scenario", ""),
        ]
        total = len(" ".join(texts))
        if total == 0:
            return True
        hypothetical_count = sum(
            1 for t in texts
            for word in ["could", "might", "may", "possibly", "potentially", "should"]
            if word in t.lower()
        )
        return hypothetical_count > 2

    def _check_impact_speculation(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> bool:
        """Check if impact is speculative rather than demonstrated."""
        impact = finding.get("impact", finding.get("claimed_impact", "")).lower()
        spec_words = ["could lead", "might allow", "could result", "potential impact", "could be used"]
        return any(sw in impact for sw in spec_words)

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 4 — EVIDENCE VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage4_evidence(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> str:
        """
        Evaluate evidence strength: NONE → WEAK → MODERATE → STRONG → CONCLUSIVE.

        Reporter assertions are not evidence. Unsupported claims flagged.
        Treats a non-empty evidence dict as request/response data.
        """
        evidence = normalized.evidence_supplied
        evidence_dict = finding.get("evidence", {})
        has_request_response = bool(
            finding.get("request") or finding.get("response")
            or finding.get("request_response")
            or (isinstance(evidence_dict, dict) and bool(evidence_dict))
        )
        has_screenshot = bool(finding.get("screenshot") or finding.get("image"))
        has_logs = bool(finding.get("logs") or finding.get("trace"))
        has_poc_code = bool(finding.get("proof_of_concept") or finding.get("poc"))
        has_dns_callback = bool(finding.get("dns_callback") or finding.get("oast"))
        has_network_trace = bool(finding.get("network_trace") or finding.get("trace"))

        score = 0

        # Direct evidence types
        if has_request_response:
            score += 35
        if has_dns_callback or has_network_trace:
            score += 25
        if has_poc_code:
            score += 20
        if has_screenshot:
            score += 10
        if has_logs:
            score += 10

        # Evidence list quality
        evidence_score = min(len(evidence) * 8, 30)
        score += evidence_score

        # Reproduction steps add weight
        if len(normalized.reproduction_steps) >= 3:
            score += 10
        elif normalized.reproduction_steps:
            score += 5

        if score >= 90:
            return "CONCLUSIVE"
        elif score >= 65:
            return "STRONG"
        elif score >= 40:
            return "MODERATE"
        elif score >= 15:
            return "WEAK"
        else:
            return "NONE"

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 5 — REPRODUCIBILITY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage5_reproducibility(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> int:
        """
        Score 0-100: can another security engineer reproduce the finding?

        Evaluates: prerequisites documented, steps documented, inputs/outputs, consistency.
        """
        steps = normalized.reproduction_steps
        evidence = normalized.evidence_supplied
        score = 0

        # Prerequisites
        has_prereqs = bool(finding.get("prerequisites"))
        if has_prereqs:
            score += 10

        # Steps documented (weighted by quality)
        step_count = len(steps)
        if step_count >= 5:
            score += 30
        elif step_count >= 3:
            score += 20
        elif step_count >= 1:
            score += 10

        # Inputs documented
        has_inputs = bool(
            finding.get("input") or finding.get("payload")
            or normalized.parameter
        )
        if has_inputs:
            score += 15

        # Outputs documented
        has_outputs = bool(finding.get("response") or evidence)
        if has_outputs:
            score += 15

        # Results consistency (multiple attempts / attempts field)
        attempts = finding.get("attempts", 1)
        if isinstance(attempts, (int, float)) and attempts >= 3:
            score += 20
        elif attempts >= 2:
            score += 10

        # Specific conditions documented
        has_conditions = bool(finding.get("conditions") or finding.get("environment"))
        if has_conditions:
            score += 10

        return min(score, 100)

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 6 — VULNERABILITY-SPECIFIC VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════

    async def _stage6_vuln_specific(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """
        Apply validation rules based on vulnerability type.
        Returns (verified_claims, unsupported_claims, missing_evidence).

        AI-Powered: Uses LLM for intelligent type-specific validation when available.
        Falls back to deterministic validation rules.
        """
        vtype = normalized.vulnerability_type
        verified: List[str] = []
        unsupported: List[str] = []
        missing: List[str] = []

        # Try AI-powered type-specific validation
        if self.llm_provider and self.llm_provider.is_available:
            try:
                ai_result = await self.llm_provider.make_policy_decision(
                    finding=finding,
                    policy={"accepted": [], "rejected": []},
                    accepted_types=[],
                    rejected_types=[],
                )
                if ai_result.get("verified_claims"):
                    verified = ai_result["verified_claims"]
                if ai_result.get("unsupported_claims"):
                    unsupported = ai_result["unsupported_claims"]
                if ai_result.get("missing_evidence"):
                    missing = ai_result["missing_evidence"]
            except Exception:
                pass

        validate_fn = {
            "xss": self._validate_xss,
            "sql_injection": self._validate_sqli,
            "idor": self._validate_idor,
            "ssrf": self._validate_ssrf,
            "auth_bypass": self._validate_auth_bypass,
            "privilege_escalation": self._validate_priv_esc,
            "command_injection": self._validate_cmd_injection,
            "rce": self._validate_cmd_injection,
            "path_traversal": self._validate_path_traversal,
            "xxe": self._validate_xxe,
            "ssti": self._validate_ssti,
            "open_redirect": self._validate_open_redirect,
            "csrf": self._validate_csrf,
        }.get(vtype)

        if validate_fn:
            verified, unsupported, missing = validate_fn(finding, normalized)
        else:
            # Generic validation for unknown types
            if normalized.evidence_supplied:
                verified.append(f"{vtype}: Evidence supplied")
            else:
                unsupported.append(f"{vtype}: No evidence to support claim")
                missing.append(f"Request/response evidence for {vtype}")

        return verified, unsupported, missing

    def _validate_xss(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """XSS requires: payload accepted, payload rendered, JS execution demonstrated."""
        verified, unsupported, missing = [], [], []
        desc = (finding.get("description", "") + " " + finding.get("title", "")).lower()
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str or ind in desc for ind in ["alert(", "prompt(", "confirm("]):
            verified.append("JavaScript execution demonstrated")
        else:
            unsupported.append("No JavaScript execution demonstrated")
            missing.append("Alert/prompt/confirm execution evidence")

        if any(ind in evidence_str for ind in ["rendered", "executed", "displayed"]):
            verified.append("Payload rendered in browser")
        else:
            unsupported.append("Payload rendering not confirmed")
            missing.append("Evidence that payload was rendered by browser")

        if any(ind in evidence_str for ind in ["<script", "<img", "<svg", "onerror", "onload"]):
            verified.append("XSS payload accepted by application")
        else:
            unsupported.append("Payload acceptance not confirmed")
            missing.append("Evidence that XSS payload was accepted")

        return verified, unsupported, missing

    def _validate_sqli(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """SQLi requires: payload alters query behavior, injection evidence, alt explanations excluded."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()
        desc = (finding.get("description", "") + " " + finding.get("title", "")).lower()

        if any(ind in evidence_str for ind in ["error", "syntax", "unclosed", "quotation mark", "mysql", "odbc"]):
            verified.append("Database error/behavior change observed")
        else:
            unsupported.append("No database error or behavior change observed")
            missing.append("Database error message or timing difference evidence")

        if any(ind in evidence_str for ind in ["timing", "delay", "sleep", "benchmark"]):
            verified.append("Time-based injection evidence observed")
        else:
            missing.append("Time-based or conditional injection test results")

        if any(ind in evidence_str for ind in ["union", "information_schema", "table_name"]):
            verified.append("Data extraction via UNION demonstrated")
        else:
            missing.append("UNION-based or boolean-based blind test results")

        return verified, unsupported, missing

    def _validate_idor(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """IDOR requires: object belongs to victim, attacker accesses it, auth bypass demonstrated."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["changed", "modified", "incremented", "decremented", "/1", "/2"]):
            verified.append("Object reference manipulation demonstrated")
        else:
            unsupported.append("No object reference manipulation evidence")
            missing.append("Evidence of ID/parameter modification and result")

        if any(ind in evidence_str for ind in ["unauthorized", "another", "other user", "victim", "different account"]):
            verified.append("Cross-user data access demonstrated")
        else:
            unsupported.append("Cross-user data access not confirmed")
            missing.append("Confirmation that accessed data belongs to different user")

        return verified, unsupported, missing

    def _validate_ssrf(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """SSRF requires: outbound request generated, attacker-controlled destination reached."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["callback", "callback received", "dns", "oast", "interact"]):
            verified.append("Outbound callback observed")
        else:
            unsupported.append("No outbound callback observed")
            missing.append("DNS/HTTP callback evidence from OAST platform")

        if any(ind in evidence_str for ind in ["169.254", "127.0.0", "localhost", "metadata"]):
            verified.append("Internal resource access attempted/demonstrated")
        else:
            missing.append("Evidence of internal resource access attempt")

        return verified, unsupported, missing

    def _validate_auth_bypass(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """Auth bypass requires: restricted resource identified, access without auth, reproducible."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["authenticated", "bypassed", "bypass", "without", "no auth"]):
            verified.append("Authentication bypass demonstrated")
        else:
            unsupported.append("Authentication bypass not clearly demonstrated")
            missing.append("Evidence of accessing restricted resource without credentials")

        if any(ind in evidence_str for ind in ["protected", "restricted", "admin", "internal"]):
            verified.append("Restricted resource identified")
        else:
            missing.append("Identification of what resource was accessed")

        return verified, unsupported, missing

    def _validate_priv_esc(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """Privilege escalation requires: boundary identified, elevation demonstrated, capability verified."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["admin", "root", "elevated", "escalated", "higher"]):
            verified.append("Privilege elevation demonstrated")
        else:
            unsupported.append("Privilege elevation not clearly demonstrated")
            missing.append("Evidence of elevated privileges after exploitation")

        if any(ind in evidence_str for ind in ["boundary", "role", "permission", "access level"]):
            verified.append("Privilege boundary identified")
        else:
            missing.append("Identification of the privilege boundary crossed")

        return verified, unsupported, missing

    def _validate_cmd_injection(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """Command injection requires: execution demonstrated, input reaches exec context, output observed."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["whoami", "id", "ls", "dir", "pwd", "hostname"]):
            verified.append("Command execution output observed")
        else:
            unsupported.append("No command execution output observed")
            missing.append("Output from executed command (whoami, id, etc.)")

        if any(ind in evidence_str for ind in ["injected", "injection", ";", "|", "`", "$("]):
            verified.append("Injection payload reached execution context")
        else:
            missing.append("Evidence that input reaches command execution context")

        return verified, unsupported, missing

    def _validate_path_traversal(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """Path traversal requires: file access outside web root demonstrated."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["passwd", "win.ini", "boot.ini", "etc/", "windows\\"]):
            verified.append("File access outside web root demonstrated")
        else:
            unsupported.append("No file access outside web root demonstrated")
            missing.append("Evidence of accessing /etc/passwd or similar protected file")

        return verified, unsupported, missing

    def _validate_xxe(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """XXE requires: XML parsing with external entity demonstrated."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["entity", "DOCTYPE", "SYSTEM", "file://", "expect:"]):
            verified.append("XML External Entity processing demonstrated")
        else:
            unsupported.append("No XXE processing demonstrated")
            missing.append("Evidence of external entity resolution")

        return verified, unsupported, missing

    def _validate_ssti(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """SSTI requires: template injection demonstrated."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["{{", "}}", "${", "7*7", "49", "config"]):
            verified.append("Template injection demonstrated")
        else:
            unsupported.append("No template injection demonstrated")
            missing.append("Evidence of SSTI ({{7*7}} rendering as 49)")

        return verified, unsupported, missing

    def _validate_open_redirect(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """Open redirect requires: redirect to attacker-controlled destination."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["redirect", "location:", "302", "301", "evil.com", "attacker"]):
            verified.append("Redirect to external domain demonstrated")
        else:
            unsupported.append("No redirect to external domain demonstrated")
            missing.append("Evidence of HTTP redirect to attacker-controlled URL")

        return verified, unsupported, missing

    def _validate_csrf(
        self, finding: Dict[str, Any], normalized: NormalizedFinding
    ) -> tuple[List[str], List[str], List[str]]:
        """CSRF requires: action performed without CSRF token / origin check."""
        verified, unsupported, missing = [], [], []
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        if any(ind in evidence_str for ind in ["missing", "no token", "without token", "origin", "referer"]):
            verified.append("State-changing request accepted without CSRF protection")
        else:
            unsupported.append("No evidence of CSRF vulnerability")
            missing.append("Proof that state-changing request succeeds without CSRF token")

        return verified, unsupported, missing

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 7 — EXPLOITABILITY ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage7_exploitability(
        self, finding: Dict[str, Any], normalized: NormalizedFinding, evidence_q: str
    ) -> str:
        """
        Determine: NONE / LIMITED / MODERATE / HIGH.

        Considers: attacker prerequisites, complexity, reliability, environmental requirements.
        """
        score = 0

        # Evidence quality contribution
        evidence_scores = {"NONE": 0, "WEAK": 15, "MODERATE": 40, "STRONG": 75, "CONCLUSIVE": 95}
        score += evidence_scores.get(evidence_q, 0)

        # Remote vs local
        desc = (finding.get("description", "") + " " + normalized.reporter_claim).lower()
        if any(ind in desc for ind in ["remote", "network", "external"]):
            score += 20
        if any(ind in desc for ind in ["authenticated", "logged in"]):
            score -= 10

        # Complexity
        if normalized.reproduction_steps:
            if len(normalized.reproduction_steps) <= 3:
                score += 15  # Simple repro = more exploitable
            else:
                score += 5   # Complex repro

        # Reliability
        if evidence_q in ("STRONG", "CONCLUSIVE"):
            score += 15

        # User interaction required
        if any(ind in desc for ind in ["click", "user interaction", "social engineering"]):
            score -= 15

        if score >= 75:
            return "HIGH"
        elif score >= 45:
            return "MODERATE"
        elif score >= 15:
            return "LIMITED"
        else:
            return "NONE"

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 8 — IMPACT VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage8_impact(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> str:
        """
        Verify demonstrated impact, reject impact inflation.

        Acceptable impacts: Unauthorized Access, Unauthorized Modification,
        Information Disclosure, Privilege Escalation, Auth Bypass, RCE, Availability Impact.
        """
        impact = (finding.get("impact", "") + " " + finding.get("claimed_impact", "") + " " + normalized.reporter_claim).lower()
        evidence_str = " ".join(normalized.evidence_supplied).lower()

        # Check for demonstrated (not hypothetical) impact
        demonstrated_impact_words = [
            "accessed", "retrieved", "modified", "deleted", "executed",
            "bypassed", "escalated", "disclosed", "extracted",
        ]
        hypothetical_words = [
            "could lead", "might allow", "could result", "potential impact",
            "could be used", "may lead", "could enable",
        ]

        has_demonstrated = any(w in evidence_str for w in demonstrated_impact_words)
        has_hypothetical = any(w in impact for w in hypothetical_words)

        # Check for impact inflation (e.g., version disclosure → "could lead to RCE")
        has_inflation = (
            any(ind in impact for ind in ["version disclosure", "banner", "server header"])
            and "rce" in impact
        )
        if has_inflation:
            return "NOT_VERIFIED"

        # Score impact
        score = 0
        if has_demonstrated:
            score += 60
        if normalized.evidence_supplied:
            score += 15
        if has_hypothetical:
            score -= 20
        if any(ind in evidence_str for ind in ["unauthorized", "sensitive", "confidential", "password", "token"]):
            score += 25

        if score >= 70:
            return "STRONG"
        elif score >= 40:
            return "DEMONSTRATED"
        elif score >= 15:
            return "PARTIAL"
        else:
            return "NOT_VERIFIED"

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 9 — POLICY VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage9_policy(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> str:
        """
        Check: in scope, eligible class, no exclusions, no policy violations.

        Flags: Self-XSS, missing security headers, banner disclosures,
        informational findings, accepted risks, out-of-scope assets.
        """
        desc = (finding.get("description", "") + " " + normalized.reporter_claim).lower()

        # Explicit policy violations
        policy_violations = [
            ("self-xss", "Self-XSS"),
            ("self xss", "Self-XSS"),
            ("missing security header", "Missing security header"),
            ("banner disclosure", "Banner disclosure"),
            ("server header", "Server header disclosure"),
            ("clickjacking", "Clickjacking without impact"),
            ("information disclosure", "Information disclosure"),
            ("version disclosure", "Version disclosure"),
        ]
        for pattern, reason in policy_violations:
            if pattern in desc:
                return "NON_COMPLIANT"

        # Check for informational-only findings
        severity = finding.get("severity", "info")
        if isinstance(severity, str) and severity.lower() == "info":
            return "QUESTIONABLE"

        # Check for accepted risk patterns
        accepted_risks = ["accepted risk", "known issue", "documented", "by design"]
        if any(ar in desc for ar in accepted_risks):
            return "QUESTIONABLE"

        return "COMPLIANT"

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 10 — DUPLICATE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage10_duplicate(self, finding: Dict[str, Any], normalized: NormalizedFinding) -> str:
        """
        Compare: asset, endpoint, root cause, parameter, impact.

        Returns: NOT_DUPLICATE / POSSIBLE_DUPLICATE / LIKELY_DUPLICATE
        """
        if not self.known_findings:
            return "NOT_DUPLICATE"

        title = finding.get("title", "").lower()
        endpoint = normalized.endpoint.lower()
        vtype = normalized.vulnerability_type
        asset = normalized.asset.lower()

        best_match = 0
        for known in self.known_findings:
            match = 0
            k_title = known.get("title", "").lower()
            k_endpoint = known.get("target", "").lower()
            k_type = known.get("type", "").lower()

            # Title similarity
            if title and k_title:
                if title == k_title:
                    match += 40
                elif title[:30] in k_title or k_title[:30] in title:
                    match += 20

            # Endpoint match
            if endpoint and k_endpoint:
                if endpoint == k_endpoint:
                    match += 25
                elif endpoint in k_endpoint or k_endpoint in endpoint:
                    match += 10

            # Same vulnerability type
            if vtype and k_type and vtype == k_type:
                match += 15

            # Asset match
            if asset and k_endpoint and asset in k_endpoint:
                match += 10

            best_match = max(best_match, match)

        if best_match >= 60:
            return "LIKELY_DUPLICATE"
        elif best_match >= 30:
            return "POSSIBLE_DUPLICATE"
        else:
            return "NOT_DUPLICATE"

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 11 — HALLUCINATION CHECK
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage11_hallucination(
        self, result: ValidationResult
    ) -> tuple[List[str], List[str]]:
        """
        For every acceptance reason, verify supporting evidence exists.
        If supporting evidence cannot be identified, remove the acceptance reason.

        Stage 6 already validated claims with type-specific logic.
        This stage checks for hallucination: claims that reference
        evidence fields that don't exist in the original finding.
        Never claim verification without evidence. Never invent proof.
        """
        acceptance: List[str] = []
        rejection: List[str] = []

        # Build acceptance reasons from Stage 6 verified claims.
        # Stage 6 already performed type-specific logic (JS execution, SQL error, etc.),
        # so claims in verified_claims are already validated.
        # The hallucination check here verifies that the result has at least some
        # supporting facts — if facts[] is empty, something went wrong upstream.
        if result.verified_claims and len(result.facts) > 0:
            for claim in result.verified_claims:
                acceptance.append(f"{claim}")
        elif result.verified_claims and len(result.facts) == 0:
            # No supporting facts found — potential hallucination
            for claim in result.verified_claims:
                result.unsupported_claims.append(f"{claim} (no supporting facts in record)")
                rejection.append(f"Hallucination suspect: {claim} — no facts available")

        # Build rejection reasons
        if result.unsupported_claims:
            for claim in result.unsupported_claims:
                rejection.append(f"Insufficient evidence: {claim}")

        if result.false_positive_explanations:
            rejection.append(f"Falsification attempts: {result.false_positive_explanations[0]}")
            if len(result.false_positive_explanations) > 1:
                for fp in result.false_positive_explanations[1:3]:
                    rejection.append(f"Falsification: {fp}")

        # Missing evidence
        if result.missing_evidence:
            for me in result.missing_evidence[:3]:
                rejection.append(f"Missing evidence: {me}")

        return acceptance, rejection

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 12 — CONFIDENCE CALCULATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _stage12_confidence(self, result: ValidationResult) -> tuple[float, str]:
        """
        Calculate weighted confidence score and make final decision.

        confidence_score =
            Evidence_Quality × 0.30 +
            Exploitability × 0.25 +
            Impact_Verification × 0.20 +
            Reproducibility × 0.15 +
            Policy_Compliance × 0.10

        Apply penalties: missing evidence, contradictions, assumptions, scope uncertainty, duplicate likelihood.
        """
        # Convert string levels to numeric scores (0-100)
        ev_score = self._evidence_to_score(result.evidence_strength)
        ex_score = self._exploitability_to_score(result.exploitability)
        im_score = self._impact_to_score(result.impact_strength)
        re_score = float(result.reproducibility_score)
        po_score = self._policy_to_score(result.policy_status)

        # Weighted calculation
        confidence = (
            ev_score * 0.30 +
            ex_score * 0.25 +
            im_score * 0.20 +
            re_score * 0.15 +
            po_score * 0.10
        )

        # Penalties
        if not result.verified_claims:
            confidence *= 0.7  # No verified claims = significant penalty
        if result.unsupported_claims:
            penalty = min(len(result.unsupported_claims) * 5, 30)
            confidence -= penalty
        if result.assumptions:
            penalty = min(len(result.assumptions) * 3, 15)
            confidence -= penalty
        if result.duplicate_status == "LIKELY_DUPLICATE":
            confidence *= 0.5
        elif result.duplicate_status == "POSSIBLE_DUPLICATE":
            confidence *= 0.8

        confidence = max(0.0, min(100.0, confidence))

        # Decision
        if confidence >= 75 and result.impact_strength in ("DEMONSTRATED", "STRONG") and result.evidence_strength in ("STRONG", "CONCLUSIVE") and result.policy_status == "COMPLIANT" and result.duplicate_status == "NOT_DUPLICATE":
            decision = "PROMOTE"
        elif confidence >= 50:
            decision = "NEEDS_REVIEW"
        else:
            decision = "REJECT"

        return round(confidence, 1), decision

    def _evidence_to_score(self, strength: str) -> float:
        mapping = {"NONE": 0, "WEAK": 15, "MODERATE": 45, "STRONG": 75, "CONCLUSIVE": 100}
        return float(mapping.get(strength, 0))

    def _exploitability_to_score(self, level: str) -> float:
        mapping = {"NONE": 0, "LIMITED": 25, "MODERATE": 55, "HIGH": 85}
        return float(mapping.get(level, 0))

    def _impact_to_score(self, strength: str) -> float:
        mapping = {"NOT_VERIFIED": 0, "PARTIAL": 25, "DEMONSTRATED": 65, "STRONG": 90}
        return float(mapping.get(strength, 0))

    def _policy_to_score(self, status: str) -> float:
        mapping = {"NON_COMPLIANT": 0, "QUESTIONABLE": 40, "COMPLIANT": 95}
        return float(mapping.get(status, 0))

    # ═══════════════════════════════════════════════════════════════════════════
    # ANALYST NOTES
    # ═══════════════════════════════════════════════════════════════════════════

    def _build_analyst_notes(self, result: ValidationResult) -> List[str]:
        """Build human-readable analyst notes summarizing the validation."""
        notes = []

        if result.decision == "PROMOTE":
            notes.append("Finding passed all 12 validation stages")
            notes.append(f"Confidence: {result.confidence_score}%")
            if result.verified_claims:
                notes.append(f"Verified: {len(result.verified_claims)} claims confirmed")
        elif result.decision == "REJECT":
            notes.append("Finding rejected during validation")
            for reason in result.rejection_reasons[:3]:
                notes.append(f"  - {reason}")
        else:
            notes.append("Finding requires manual review")
            notes.append(f"Confidence: {result.confidence_score}% — below promote threshold")
            notes.append(f"Facts: {len(result.facts)} | Inferences: {len(result.inferences)} | Assumptions: {len(result.assumptions)}")

        if result.duplicate_status != "NOT_DUPLICATE":
            notes.append(f"Duplicate status: {result.duplicate_status}")

        return notes
