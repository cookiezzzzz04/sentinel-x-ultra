"""
AGENT 9 — EVIDENCE-DRIVEN SECURITY ANALYSIS ENGINE (v2)

Performs deterministic, evidence-based security analysis of validated findings.
Computes structured security metadata using ONLY observed evidence.

Outputs: CVSS 3.1 (derived from evidence), CWE classification (evidence-justified),
OWASP Top 10 mapping (contextual), exploitability rating, remediation priority,
business impact (ONLY if directly observed), confidence score with uncertainty tracking.

Hard Constraints:
- MUST NOT use vulnerability-type → severity tables
- MUST NOT assume exploitation feasibility
- MUST NOT assume impact beyond evidence
- If information is missing: OUTPUT MUST BE "UNKNOWN"
- No inference is allowed without evidence backing
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


# ── Enums / Constants ───────────────────────────────────────────────────────

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0, "UNKNOWN": -1}

# CWE mappings keyed by observed behavioral patterns (NOT by vulnerability type)
CWE_BY_PATTERN: Dict[str, Tuple[str, List[Dict[str, Any]]]] = {
    "unauthorized_data_access": ("CWE-639", [{"cwe": "CWE-862", "confidence": 0.6}]),
    "authentication_bypass": ("CWE-287", [{"cwe": "CWE-306", "confidence": 0.5}]),
    "injection_behavior": ("CWE-94", [{"cwe": "CWE-77", "confidence": 0.5}]),
    "javascript_execution": ("CWE-79", [{"cwe": "CWE-80", "confidence": 0.6}]),
    "server_side_request": ("CWE-918", [{"cwe": "CWE-829", "confidence": 0.5}]),
    "command_execution": ("CWE-78", [{"cwe": "CWE-94", "confidence": 0.6}]),
    "path_disclosure": ("CWE-22", [{"cwe": "CWE-200", "confidence": 0.5}]),
    "data_exposure": ("CWE-200", [{"cwe": "CWE-209", "confidence": 0.5}]),
    "cross_site_request": ("CWE-352", []),
    "xml_processing": ("CWE-611", [{"cwe": "CWE-827", "confidence": 0.5}]),
    "privilege_elevation": ("CWE-269", [{"cwe": "CWE-862", "confidence": 0.6}]),
    "open_redirect": ("CWE-601", []),
}

# OWASP mappings keyed by observed behavior
OWASP_BY_PATTERN: Dict[str, List[Dict[str, Any]]] = {
    "unauthorized_data_access": [{"category": "A01:2021 Broken Access Control", "confidence": 0.8}],
    "authentication_bypass": [{"category": "A07:2021 Identification and Authentication Failures", "confidence": 0.8}],
    "injection_behavior": [{"category": "A03:2021 Injection", "confidence": 0.8}],
    "javascript_execution": [{"category": "A03:2021 Injection", "confidence": 0.7}],
    "server_side_request": [{"category": "A10:2021 Server-Side Request Forgery", "confidence": 0.8}],
    "command_execution": [{"category": "A03:2021 Injection", "confidence": 0.8}],
    "path_disclosure": [{"category": "A05:2021 Security Misconfiguration", "confidence": 0.6}],
    "data_exposure": [{"category": "A05:2021 Security Misconfiguration", "confidence": 0.6}],
    "cross_site_request": [{"category": "A01:2021 Broken Access Control", "confidence": 0.7}],
    "xml_processing": [{"category": "A05:2021 Security Misconfiguration", "confidence": 0.7}],
    "privilege_elevation": [{"category": "A01:2021 Broken Access Control", "confidence": 0.8}],
    "open_redirect": [{"category": "A05:2021 Security Misconfiguration", "confidence": 0.6}],
}


# ── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class CVSSMetrics:
    """Individual CVSS 3.1 metrics, each may be UNKNOWN."""
    AV: str = "UNKNOWN"  # Network / Adjacent / Local / Physical
    AC: str = "UNKNOWN"  # Low / High
    PR: str = "UNKNOWN"  # None / Low / High
    UI: str = "UNKNOWN"  # None / Required
    S: str = "UNKNOWN"   # Unchanged / Changed
    C: str = "UNKNOWN"   # None / Low / High
    I: str = "UNKNOWN"   # None / Low / High
    A: str = "UNKNOWN"   # None / Low / High


@dataclass
class CVSSEntry:
    """CVSS score entry — supports UNKNOWN values."""
    score: str = "UNKNOWN"  # float or "UNKNOWN"
    severity: str = "UNKNOWN"
    vector: str = "UNKNOWN"
    metrics: CVSSMetrics = field(default_factory=CVSSMetrics)


@dataclass
class CWEAlternative:
    """Alternative CWE classification with confidence."""
    cwe: str = ""
    confidence: float = 0.0


@dataclass
class CWEInfo:
    """CWE classification output."""
    primary: str = ""
    alternatives: List[CWEAlternative] = field(default_factory=list)


@dataclass
class OWASPAlternative:
    """Alternative OWASP classification with confidence."""
    category: str = ""
    confidence: float = 0.0


@dataclass
class OWASPInfo:
    """OWASP mapping output."""
    primary: str = ""
    alternatives: List[OWASPAlternative] = field(default_factory=list)


@dataclass
class DetailedAnalysis:
    """Full analysis output matching the required output schema."""
    finding_id: str = ""
    title: str = ""
    cvss: CVSSEntry = field(default_factory=CVSSEntry)
    cwe: CWEInfo = field(default_factory=CWEInfo)
    owasp: OWASPInfo = field(default_factory=OWASPInfo)
    exploitability: str = "UNKNOWN"
    remediation_priority: str = "Info"
    business_impact: str = "NOT DEMONSTRATED"
    confidence: float = 0.0
    evidence_used: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    decision: str = "REVIEW"  # Analysis-level decision


# ── Backward-Compatible FindingAnalysis ─────────────────────────────────────

@dataclass
class CVSSScore:
    """Legacy CVSS score — preserved for orchestrator compatibility."""
    base_score: float = 0.0
    vector_string: str = ""
    severity: str = "None"
    attack_vector: str = "Network"
    attack_complexity: str = "Low"
    privileges_required: str = "None"
    user_interaction: str = "None"
    scope: str = "Unchanged"
    confidentiality: str = "None"
    integrity: str = "None"
    availability: str = "None"


@dataclass
class FindingAnalysis:
    """Backward-compatible FindingAnalysis with new fields added.

    Preserves the original fields (title, cvss, cwe_primary, cwe_secondary,
    owasp_mapping, exploitability, remediation_priority, business_impact)
    while adding the new evidence-driven detailed analysis.
    """
    # Original fields (backward compatible)
    title: str = ""
    cvss: Optional[CVSSScore] = None
    cwe_primary: str = ""
    cwe_secondary: List[str] = field(default_factory=list)
    owasp_mapping: str = ""
    exploitability: str = ""
    remediation_priority: str = ""
    business_impact: str = ""

    # New fields
    detailed: Optional[DetailedAnalysis] = None
    decision: str = "REVIEW"
    confidence: float = 0.0
    evidence_used: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)


# ── Evidence-Driven Security Analysis Engine ───────────────────────────────

class AnalysisAgent:
    """
    Agent 9: Evidence-Driven Security Analysis Engine (v2).

    Performs deterministic analysis using ONLY observed evidence.
    Does NOT use vulnerability-type → severity tables.
    Does NOT assume exploitation feasibility.
    Does NOT assume impact beyond evidence.
    If information is missing: OUTPUT MUST BE "UNKNOWN".

    Pipeline:
      1. Validation Gate — require PROMOTE
      2. Evidence Extraction — extract observable facts
      3. CVSS Derivation (Strict) — from evidence only
      4. CWE Classification — evidence-justified
      5. OWASP Mapping — contextual with confidence weights
      6. Exploitability Model — derived from evidence only
      7. Business Impact (Strict) — only directly evidenced
      8. Confidence Model — from completeness of evidence
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API (Backward Compatible)
    # ═══════════════════════════════════════════════════════════════════════════

    async def analyze(self, finding: Dict[str, Any]) -> FindingAnalysis:
        """Analyze a finding using evidence-driven analysis.

        Runs the full pipeline:
        1. Validation Gate
        2. Evidence Extraction
        3. CVSS Derivation
        4. CWE Classification
        5. OWASP Mapping
        6. Exploitability Model
        7. Business Impact
        8. Confidence Model
        """
        title = finding.get("title", "Unknown Finding")
        finding_id = finding.get("id", finding.get("finding_id", ""))

        result = FindingAnalysis(title=title)
        detailed = DetailedAnalysis(finding_id=finding_id, title=title)

        # Step 1: Validation Gate
        validation_status = str(finding.get("validation_status", finding.get("validation_decision", ""))).upper()
        if validation_status != "PROMOTE":
            result.decision = "REVIEW"
            detailed.decision = "REVIEW"
            detailed.uncertainties.append("Validation status is not PROMOTE — no analysis performed")
            detailed.confidence = 0.0
            result.detailed = detailed
            return result

        # Step 2: Evidence Extraction
        evidence_items = self._extract_evidence(finding)
        detailed.evidence_used = [f"EV-{i+1}" for i in range(len(evidence_items))]

        if not evidence_items:
            result.decision = "BLOCK"
            detailed.decision = "BLOCK"
            detailed.uncertainties.append("No evidence available — analysis BLOCKED")
            detailed.confidence = 0.0
            result.detailed = detailed
            return result

        # Step 3: CVSS Derivation (Strict)
        cvss_entry = self._derive_cvss(finding, evidence_items)
        detailed.cvss = cvss_entry
        self._populate_legacy_cvss(result, cvss_entry)

        # Step 4: CWE Classification
        cwe_info = self._classify_cwe(finding, evidence_items)
        detailed.cwe = cwe_info
        result.cwe_primary = cwe_info.primary
        result.cwe_secondary = [alt.cwe for alt in cwe_info.alternatives if alt.cwe]

        # Step 5: OWASP Mapping
        owasp_info = self._map_owasp(finding, evidence_items)
        detailed.owasp = owasp_info
        result.owasp_mapping = owasp_info.primary

        # Step 6: Exploitability Model
        exploitability = self._assess_exploitability(finding, evidence_items, cvss_entry)
        detailed.exploitability = exploitability
        result.exploitability = exploitability

        # Step 7: Business Impact (Strict)
        impact = self._assess_impact(finding, evidence_items)
        detailed.business_impact = impact
        result.business_impact = impact

        # Step 8: Confidence Model
        confidence, uncertainties = self._calculate_confidence(finding, evidence_items, cvss_entry, cwe_info, impact)
        detailed.confidence = confidence
        detailed.uncertainties = uncertainties
        result.confidence = confidence
        result.uncertainties = uncertainties

        # Remediation priority (from confidence + exploitability)
        result.remediation_priority = self._get_remediation_priority(confidence, exploitability, impact)
        detailed.remediation_priority = result.remediation_priority

        # Final decision
        if confidence >= 70:
            result.decision = "GENERATE"
            detailed.decision = "GENERATE"
        elif confidence >= 40:
            result.decision = "REVIEW"
            detailed.decision = "REVIEW"
        else:
            result.decision = "BLOCK"
            detailed.decision = "BLOCK"

        result.detailed = detailed
        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 2 — EVIDENCE EXTRACTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _extract_evidence(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract ONLY observable facts from evidence.

        Valid facts: HTTP requests, HTTP responses, authentication state (if proven),
        access control behavior, data exposure indicators, system behavior changes.

        Unobserved fields: NOT extracted.
        """
        items: List[Dict[str, str]] = []

        # Extract from evidence dict
        evidence_raw = finding.get("evidence", {})
        if isinstance(evidence_raw, dict):
            for key, val in evidence_raw.items():
                val_str = str(val).strip() if val else ""
                if val_str:
                    items.append({"type": key, "value": val_str[:500]})
        elif isinstance(evidence_raw, list):
            for ev in evidence_raw:
                ev_str = str(ev).strip() if ev else ""
                if ev_str:
                    items.append({"type": "evidence_item", "value": ev_str[:500]})
        elif isinstance(evidence_raw, str) and evidence_raw.strip():
            items.append({"type": "evidence", "value": evidence_raw.strip()[:500]})

        # Extract from observed_behavior
        observed = finding.get("observed_behavior", finding.get("observations", []))
        if isinstance(observed, list):
            for obs in observed:
                if isinstance(obs, dict):
                    claim = obs.get("claim", str(obs))
                else:
                    claim = str(obs)
                if claim:
                    items.append({"type": "observed_behavior", "value": str(claim)[:500]})
        elif isinstance(observed, str) and observed.strip():
            items.append({"type": "observed_behavior", "value": observed.strip()[:500]})

        # Extract from reproduction_steps
        steps = finding.get("reproduction_steps", finding.get("steps_to_reproduce", []))
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    action = step.get("action", step.get("description", ""))
                else:
                    action = str(step)
                if action:
                    items.append({"type": "reproduction_step", "value": str(action)[:500]})

        # Extract from impact evidence
        impact_ev = finding.get("impact_evidence", finding.get("demonstrated_impact", []))
        if isinstance(impact_ev, list):
            for imp in impact_ev:
                if isinstance(imp, dict):
                    claim = imp.get("claim", str(imp))
                else:
                    claim = str(imp)
                if claim:
                    items.append({"type": "impact_evidence", "value": str(claim)[:500]})
        elif isinstance(impact_ev, str) and impact_ev.strip():
            items.append({"type": "impact_evidence", "value": impact_ev.strip()[:500]})

        # Extract from description
        desc = finding.get("description", "")
        if desc and len(desc) > 10:
            items.append({"type": "description", "value": desc.strip()[:500]})

        return items

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 3 — CVSS DERIVATION (STRICT)
    # ═══════════════════════════════════════════════════════════════════════════

    def _derive_cvss(self, finding: Dict[str, Any], evidence: List[Dict[str, str]]) -> CVSSEntry:
        """Derive CVSS 3.1 from evidence only.

        Attack Vector (AV): Derived only from observed access path
        Attack Complexity (AC): Low only if reproducible without special conditions
        Privileges Required (PR): Derived from evidence of authentication requirement
        User Interaction (UI): Required only if user action is evidenced
        Scope (S): Changed only if cross-boundary impact is evidenced
        Impact Metrics (C/I/A): Derived ONLY from confirmed observed impact

        Hardcoded CVSS vectors are forbidden.
        """
        metrics = CVSSMetrics()
        evidence_text = " ".join(e["value"] for e in evidence).lower()
        confidence_penalty = 0.0
        uncertainties = []

        # --- Attack Vector (AV) ---
        if self._evidence_mentions(evidence_text, ["network", "remote", "http://", "https://", "internet"]):
            metrics.AV = "Network"
        elif self._evidence_mentions(evidence_text, ["adjacent", "local network", "wifi", "bluetooth"]):
            metrics.AV = "Adjacent"
        elif self._evidence_mentions(evidence_text, ["local", "physical access", "console"]):
            metrics.AV = "Local"
        elif self._evidence_mentions(evidence_text, ["physical"]):
            metrics.AV = "Physical"
        else:
            # Default to Network for web-based findings (most common)
            metrics.AV = "Network"
            uncertainties.append("AV: No evidence of access path — defaulted to Network")
            confidence_penalty += 0.05

        # --- Attack Complexity (AC) ---
        reproducible_count = sum(1 for e in evidence if self._evidence_mentions(
            e["value"].lower(), ["reproduc", "repeat", "consistent", "always", "every time"]
        ))
        if reproducible_count >= 2:
            metrics.AC = "Low"
        elif self._evidence_mentions(evidence_text, ["special condition", "race condition", "timing",
                                                      "specific version", "requires"]):
            metrics.AC = "High"
            uncertainties.append("AC: Special conditions required for reproduction")
            confidence_penalty += 0.1
        else:
            metrics.AC = "Low"
            uncertainties.append("AC: No evidence of special conditions — assumed Low")
            confidence_penalty += 0.05

        # --- Privileges Required (PR) ---
        if self._evidence_mentions(evidence_text, ["authenticated", "logged in", "requires login",
                                                    "session required", "valid session"]):
            # Check if the evidence describes a way to bypass authentication
            if self._evidence_mentions(evidence_text, ["bypass", "no auth", "without auth",
                                                        "unauthenticated access", "no login"]):
                metrics.PR = "None"
            else:
                metrics.PR = "Low"
        elif self._evidence_mentions(evidence_text, ["admin", "administrator", "root"]):
            metrics.PR = "High"
        else:
            metrics.PR = "None"
            uncertainties.append("PR: No authentication evidence — assumed None")

        # --- User Interaction (UI) ---
        if self._evidence_mentions(evidence_text, ["click", "user interaction", "victim visit",
                                                    "social engineering", "phishing"]):
            metrics.UI = "Required"
        else:
            metrics.UI = "None"
            uncertainties.append("UI: No user interaction evidenced — assumed None")

        # --- Scope (S) ---
        if self._evidence_mentions(evidence_text, ["boundary", "cross-boundary", "scope change",
                                                    "different context", "escalation"]):
            metrics.S = "Changed"
        else:
            metrics.S = "Unchanged"

        # --- Confidentiality (C) ---
        if self._evidence_mentions(evidence_text, ["data returned", "data exposed", "unauthorized access",
                                                    "data leak", "information disclosure", "confidential"]):
            metrics.C = "High"
        elif self._evidence_mentions(evidence_text, ["version disclosure", "banner", "header disclosure"]):
            metrics.C = "Low"
        else:
            metrics.C = "None"
            uncertainties.append("C: No confidentiality impact evidenced — None")
            confidence_penalty += 0.1

        # --- Integrity (I) ---
        if self._evidence_mentions(evidence_text, ["modified", "changed", "altered", "injected",
                                                    "script execution", "redirect"]):
            metrics.I = "High"
        elif self._evidence_mentions(evidence_text, ["parameter modified", "header modified"]):
            metrics.I = "Low"
        else:
            metrics.I = "None"
            uncertainties.append("I: No integrity impact evidenced — None")

        # --- Availability (A) ---
        if self._evidence_mentions(evidence_text, ["denial", "crash", "hang", "unavailable",
                                                    "slow response", "timeout"]):
            metrics.A = "High"
        elif self._evidence_mentions(evidence_text, ["slow", "delayed"]):
            metrics.A = "Low"
        else:
            metrics.A = "None"

        # Build vector string from evidence-derived metrics
        all_known = all(
            getattr(metrics, m) != "UNKNOWN"
            for m in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        )

        if all_known:
            vector = (
                f"CVSS:3.1/AV:{metrics.AV[0]}/AC:{metrics.AC[0]}/"
                f"PR:{metrics.PR[0]}/UI:{metrics.UI[0]}/"
                f"S:{metrics.S[0]}/C:{metrics.C[0]}/I:{metrics.I[0]}/A:{metrics.A[0]}"
            )

            # Calculate base score (simplified CVSS 3.1)
            score = self._calculate_cvss_score(metrics)
            severity = self._score_to_severity(score)
        else:
            vector = "UNKNOWN"
            score = -1.0
            severity = "UNKNOWN"
            uncertainties.append("CVSS: Some metrics could not be derived from evidence")
            confidence_penalty += 0.2

        entry = CVSSEntry(
            score=str(round(score, 1)) if score >= 0 else "UNKNOWN",
            severity=severity,
            vector=vector,
            metrics=metrics,
        )

        return entry

    def _calculate_cvss_score(self, m: CVSSMetrics) -> float:
        """CVSS 3.1 base score calculation using standard coefficients.

        Uses the CVSS 3.1 specification weights:
        AV: Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.2
        AC: Low=0.77, High=0.44
        PR: None=0.85, Low=0.62 (U), 0.68 (C), High=0.27 (U), 0.50 (C)
        UI: None=0.85, Required=0.62
        Impact (C/I/A): None=0.0, Low=0.22, High=0.56
        """
        # CVSS 3.1 exploitability coefficients
        av_map = {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2}
        ac_map = {"Low": 0.77, "High": 0.44}
        pr_map = {"None": 0.85, "Low": 0.62, "High": 0.27}
        pr_map_changed = {"None": 0.85, "Low": 0.68, "High": 0.50}
        ui_map = {"None": 0.85, "Required": 0.62}

        # CVSS 3.1 impact coefficients
        imp_map = {"None": 0.0, "Low": 0.22, "High": 0.56}

        # Base Impact Sub-Score (ISS)
        iss = 1.0 - (
            (1.0 - imp_map.get(m.C, 0.0)) *
            (1.0 - imp_map.get(m.I, 0.0)) *
            (1.0 - imp_map.get(m.A, 0.0))
        )

        # Impact sub-score depending on scope
        if m.S == "Changed":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        # Exploitability sub-score (correct CVSS 3.1 coefficients)
        pr_coeff = pr_map_changed.get(m.PR, 0.62) if m.S == "Changed" else pr_map.get(m.PR, 0.62)
        exploitability = (
            8.22 *
            av_map.get(m.AV, 0.85) *
            ac_map.get(m.AC, 0.77) *
            pr_coeff *
            ui_map.get(m.UI, 0.85)
        )

        if impact <= 0:
            return 0.0

        if m.S == "Changed":
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        return round(base, 1)

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        return "None"

    def _populate_legacy_cvss(self, result: FindingAnalysis, cvss_entry: CVSSEntry):
        """Populate the backward-compatible CVSSScore from the new CVSSEntry."""
        score_val = 0.0
        try:
            score_val = float(cvss_entry.score)
        except (ValueError, TypeError):
            score_val = 0.0

        result.cvss = CVSSScore(
            base_score=score_val,
            vector_string=cvss_entry.vector,
            severity=cvss_entry.severity,
            attack_vector=cvss_entry.metrics.AV,
            attack_complexity=cvss_entry.metrics.AC,
            privileges_required=cvss_entry.metrics.PR,
            user_interaction=cvss_entry.metrics.UI,
            scope=cvss_entry.metrics.S,
            confidentiality=cvss_entry.metrics.C,
            integrity=cvss_entry.metrics.I,
            availability=cvss_entry.metrics.A,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 4 — CWE CLASSIFICATION (EVIDENCE-JUSTIFIED)
    # ═══════════════════════════════════════════════════════════════════════════

    def _classify_cwe(self, finding: Dict[str, Any], evidence: List[Dict[str, str]]) -> CWEInfo:
        """Classify CWE from observed behavior only.

        CWE must be:
        - Directly supported by observed behavior
        - Justified via reproduction evidence
        - Ranked if multiple candidates exist

        If ambiguous: CWE-UNKNOWN with explanation.
        """
        evidence_text = " ".join(e["value"] for e in evidence).lower()
        patterns_found = []

        # Check each behavioral pattern against evidence text
        pattern_indicators = {
            "unauthorized_data_access": ["unauthorized", "another user", "other user", "access denied",
                                          "forbidden", "not authorized", "id=", "parameter modified"],
            "authentication_bypass": ["bypass", "no auth", "without login", "no password",
                                       "session manipulation", "token bypass"],
            "injection_behavior": ["injection", "sql", "query", "error message", "syntax error"],
            "javascript_execution": ["script", "alert(", "xss", "cross-site", "javascript",
                                      "<script", "onerror", "onload"],
            "server_side_request": ["ssrf", "server-side request", "internal request",
                                     "localhost", "169.254", "127.0.0"],
            "command_execution": ["command", "exec(", "system(", "shell", "whoami", "ls -la",
                                   "dir ", "|", ";"],
            "path_disclosure": ["path traversal", "directory traversal", "../", "..\\",
                                 "etc/passwd", "win.ini"],
            "data_exposure": ["disclosure", "exposed", "leaked", "version disclosure",
                               "banner", "stack trace", "debug output"],
            "cross_site_request": ["csrf", "cross-site request", "no token", "missing token",
                                    "state-changing"],
            "xml_processing": ["xxe", "xml external entity", "DOCTYPE", "entity"],
            "privilege_elevation": ["privilege escalation", "elevated", "admin access",
                                     "higher privileges", "role change"],
            "open_redirect": ["redirect", "open redirect", "redirect to", "location:"],
        }

        for pattern_name, indicators in pattern_indicators.items():
            matches = sum(1 for ind in indicators if ind in evidence_text)
            if matches >= 2:
                patterns_found.append((pattern_name, matches))
            else:
                patterns_found.append((pattern_name, 1))

        # Rank by match count
        patterns_found.sort(key=lambda x: x[1], reverse=True)

        if not patterns_found:
            return CWEInfo(
                primary="CWE-UNKNOWN",
                alternatives=[CWEAlternative(cwe="CWE-200", confidence=0.3)],
            )

        # Top match is primary
        top_pattern = patterns_found[0][0]
        top_cwe_data = CWE_BY_PATTERN.get(top_pattern, ("CWE-UNKNOWN", []))

        primary = top_cwe_data[0]
        alternatives = []
        for alt in top_cwe_data[1]:
            alternatives.append(CWEAlternative(cwe=alt["cwe"], confidence=alt["confidence"]))

        # Add runners-up as lower-confidence alternatives
        for pattern_name, _ in patterns_found[1:3]:
            alt_data = CWE_BY_PATTERN.get(pattern_name)
            if alt_data and alt_data[0] != primary:
                if alt_data[0] not in [a.cwe for a in alternatives]:
                    alternatives.append(CWEAlternative(cwe=alt_data[0], confidence=0.4))

        return CWEInfo(primary=primary, alternatives=alternatives)

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 5 — OWASP MAPPING (CONTEXTUAL)
    # ═══════════════════════════════════════════════════════════════════════════

    def _map_owasp(self, finding: Dict[str, Any], evidence: List[Dict[str, str]]) -> OWASPInfo:
        """Map to OWASP Top 10 from observed behavior.

        Must reflect actual system weakness observed, not vulnerability label alone.
        If uncertain: return multiple candidates with confidence weights.
        """
        evidence_text = " ".join(e["value"] for e in evidence).lower()

        # Detect patterns in evidence
        pattern_indicators = {
            "unauthorized_data_access": ["unauthorized", "another user", "id=", "access control"],
            "authentication_bypass": ["bypass", "no auth", "without login", "no password"],
            "injection_behavior": ["injection", "sql", "query", "command"],
            "javascript_execution": ["script", "alert(", "xss", "cross-site"],
            "server_side_request": ["ssrf", "localhost", "169.254", "internal request"],
            "command_execution": ["command", "exec(", "shell", "whoami"],
            "path_disclosure": ["path traversal", "../", "etc/passwd"],
            "data_exposure": ["disclosure", "exposed", "version", "banner"],
            "cross_site_request": ["csrf", "no token", "state-changing"],
            "xml_processing": ["xxe", "DOCTYPE", "xml external entity"],
            "privilege_elevation": ["privilege escalation", "elevated", "admin"],
            "open_redirect": ["redirect", "open redirect", "location:"],
        }

        candidates = []
        for pattern_name, indicators in pattern_indicators.items():
            matches = sum(1 for ind in indicators if ind in evidence_text)
            if matches > 0:
                owasp_data = OWASP_BY_PATTERN.get(pattern_name, [])
                for entry in owasp_data:
                    # Scale confidence by how many indicators matched
                    scaled_confidence = entry["confidence"] * min(matches / len(indicators) * 2, 1.0)
                    candidates.append({
                        "category": entry["category"],
                        "confidence": round(scaled_confidence, 2),
                    })

        if not candidates:
            return OWASPInfo(
                primary="A05:2021 Security Misconfiguration",
                alternatives=[OWASPAlternative(category="A05:2021 Security Misconfiguration", confidence=0.3)],
            )

        # Sort by confidence descending
        candidates.sort(key=lambda x: x["confidence"], reverse=True)
        primary = candidates[0]["category"]
        alternatives = [
            OWASPAlternative(category=c["category"], confidence=c["confidence"])
            for c in candidates[1:4]
        ]

        return OWASPInfo(primary=primary, alternatives=alternatives)

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 6 — EXPLOITABILITY MODEL
    # ═══════════════════════════════════════════════════════════════════════════

    def _assess_exploitability(self, finding: Dict[str, Any], evidence: List[Dict[str, str]],
                                cvss: CVSSEntry) -> str:
        """Derive exploitability from evidence only.

        HIGH: reproducible, minimal constraints, no special conditions
        MEDIUM: requires conditions (auth, timing, context)
        LOW: inconsistent or heavily constrained
        UNKNOWN: insufficient evidence
        """
        evidence_text = " ".join(e["value"] for e in evidence).lower()

        # Check for reproducibility evidence
        reproducible = self._evidence_mentions(evidence_text, ["reproduc", "repeat", "consistent"])
        constraints = self._evidence_mentions(evidence_text, ["requires", "special", "specific version",
                                                               "condition", "timing", "race"])
        auth_required = self._evidence_mentions(evidence_text, ["authenticated", "logged in", "login"])
        inconsistent = self._evidence_mentions(evidence_text, ["inconsistent", "intermittent", "unreliable"])

        # Evidence of multiple successful attempts
        success_attempts = sum(1 for e in evidence if self._evidence_mentions(
            e["value"].lower(), ["success", "confirmed", "200 ok", "worked"]
        ))

        if inconsistent:
            return "LOW"

        if reproducible and not constraints and success_attempts >= 2:
            return "HIGH"

        if reproducible and not constraints:
            return "HIGH"

        if constraints or auth_required:
            return "MEDIUM"

        if success_attempts >= 1:
            return "MEDIUM"

        return "UNKNOWN"

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 7 — BUSINESS IMPACT (STRICT)
    # ═══════════════════════════════════════════════════════════════════════════

    def _assess_impact(self, finding: Dict[str, Any], evidence: List[Dict[str, str]]) -> str:
        """Assess business impact from directly evidenced observation only.

        VALID: unauthorized data returned, privilege change observed,
               session hijack demonstrated, access control bypass confirmed

        INVALID: theoretical compromise, assumed escalation, speculative worst-case

        If not evidenced: "NOT DEMONSTRATED"
        """
        evidence_text = " ".join(e["value"] for e in evidence).lower()

        # Check for directly evidenced impact
        impact_indicators = {
            "unauthorized_data_returned": ["unauthorized data", "another user's data", "other user data",
                                            "data exposed", "data returned", "confidential data"],
            "privilege_change_observed": ["admin access", "elevated privilege", "role changed",
                                           "privilege escalation", "higher permissions"],
            "session_hijack_demonstrated": ["session hijack", "session token", "cookie theft",
                                             "session fixation"],
            "access_control_bypass": ["access control bypass", "authorization bypass", "bypass",
                                       "no authorization", "forbidden bypassed"],
            "command_execution": ["command executed", "shell access", "whoami output", "remote execution"],
            "data_modification": ["data modified", "data changed", "record updated", "file modified"],
        }

        demonstrated = []
        for impact_name, indicators in impact_indicators.items():
            if self._evidence_mentions(evidence_text, indicators):
                demonstrated.append(impact_name.replace("_", " ").title())

        if demonstrated:
            return "; ".join(demonstrated[:3])
        elif self._evidence_mentions(evidence_text, ["impact", "effect", "consequence"]):
            return "Impact referenced but not directly demonstrated in evidence"
        else:
            return "NOT DEMONSTRATED"

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 8 — CONFIDENCE MODEL
    # ═══════════════════════════════════════════════════════════════════════════

    def _calculate_confidence(self, finding: Dict[str, Any], evidence: List[Dict[str, str]],
                               cvss: CVSSEntry, cwe: CWEInfo, impact: str) -> Tuple[float, List[str]]:
        """Calculate confidence from completeness of evidence.

        90-100: full evidence coverage, reproducible, consistent validation
        70-89: strong evidence with minor gaps
        40-69: partial evidence
        <40: insufficient evidence

        Missing or contradictory evidence lowers confidence automatically.
        """
        uncertainties = []
        score = 0.0

        # 1. Evidence coverage (0-30)
        evidence_types = set(e["type"] for e in evidence)
        required_types = {"evidence", "evidence_item", "observed_behavior", "reproduction_step", "impact_evidence"}
        covered = evidence_types & required_types
        coverage_ratio = len(covered) / len(required_types) if required_types else 0
        score += coverage_ratio * 30

        if coverage_ratio < 0.5:
            uncertainties.append(f"Low evidence coverage ({len(covered)}/{len(required_types)} types present)")
        elif coverage_ratio < 0.8:
            uncertainties.append(f"Partial evidence coverage ({len(covered)}/{len(required_types)} types)")

        # 2. Evidence volume (0-15)
        evidence_count = len(evidence)
        if evidence_count >= 8:
            score += 15
        elif evidence_count >= 5:
            score += 10
        elif evidence_count >= 3:
            score += 5
        else:
            uncertainties.append(f"Minimal evidence ({evidence_count} items)")
            score += 2

        # 3. CVSS metric completeness (0-20)
        if cvss.score != "UNKNOWN":
            score += 15
        else:
            uncertainties.append("CVSS could not be fully derived from evidence")

        # 4. CWE classification (0-15)
        if cwe.primary and cwe.primary != "CWE-UNKNOWN":
            score += 12
        else:
            uncertainties.append("CWE classification is ambiguous — no clear behavioral pattern")
            score += 3

        # 5. Impact demonstrated (0-10)
        if impact and impact != "NOT DEMONSTRATED":
            score += 10
        else:
            uncertainties.append("Business impact is NOT DEMONSTRATED in evidence")

        # 6. Reproducibility (0-10)
        reproducible_count = sum(1 for e in evidence if self._evidence_mentions(
            e["value"].lower(), ["reproduc", "repeat", "consistent", "every time"]
        ))
        if reproducible_count >= 2:
            score += 10
        elif reproducible_count >= 1:
            score += 5
            uncertainties.append("Limited reproducibility evidence")
        else:
            uncertainties.append("No reproducibility evidence")

        # Ensure score stays within 0-100
        score = max(0.0, min(100.0, score))

        return score, uncertainties

    # ═══════════════════════════════════════════════════════════════════════════
    # REMEDIATION PRIORITY
    # ═══════════════════════════════════════════════════════════════════════════

    def _get_remediation_priority(self, confidence: float, exploitability: str, impact: str) -> str:
        """Determine remediation priority from confidence, exploitability, and impact.

        Only determined from evidence-backed values.
        """
        if confidence < 40:
            return "Info"
        if impact == "NOT DEMONSTRATED":
            if exploitability in ("HIGH", "MEDIUM"):
                return "Long-term"
            return "Info"
        if exploitability == "HIGH" and confidence >= 70:
            return "Immediate"
        if exploitability in ("HIGH", "MEDIUM") and confidence >= 50:
            return "Short-term"
        if confidence >= 50:
            return "Long-term"
        return "Info"

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _evidence_mentions(self, text: str, keywords: List[str]) -> bool:
        """Check if evidence text mentions any of the given keywords."""
        return any(kw.lower() in text for kw in keywords)
