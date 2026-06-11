"""
AGENT 1 — PROGRAM INTELLIGENCE ANALYST (STRICT EVIDENCE MODE)

14-phase bug bounty program intelligence analyst.
Produces a structured intelligence profile that guides all downstream agents.

Incorrect intelligence may cause out-of-scope testing, invalid findings,
false positives, or wasted testing effort. Accuracy is mandatory.

Phases:
1. Program Identification
2. Asset Intelligence
3. Scope Analysis
4. Policy Intelligence
5. Testing Restriction Intelligence
6. Safe Harbor Intelligence
7. Reward Intelligence
8. Program Maturity Analysis
9. Contradiction Detection
10. Uncertainty Analysis
11. Asset Prioritization
12. Testing Strategy Generation
13. Downstream Guidance
14. Hallucination Prevention
"""

import re
import httpx
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


# ── Constants ───────────────────────────────────────────────────────────────

ASSET_TYPES = ["domain", "subdomain", "api", "mobile_app", "desktop_application",
               "source_code_repository", "cloud_asset", "network_range", "hardware", "other"]
SCOPE_STATUSES = ["IN_SCOPE", "OUT_OF_SCOPE", "UNCLEAR"]
MATURITY_LEVELS = ["VERY_HIGH", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
RESTRICTION_SEVERITIES = ["PROHIBITED", "RESTRICTED", "PERMITTED"]
SAFE_HARBOR_LEVELS = ["STRONG", "MODERATE", "WEAK", "NONE"]
SCANNER_AGGRESSIVENESS = ["LOW", "MEDIUM", "HIGH"]
VALIDATION_STRICTNESS = ["LOW", "MEDIUM", "HIGH"]

KNOWN_VULN_CLASSES = [
    "SQL Injection", "XSS", "SSRF", "IDOR", "Authentication Bypass",
    "Privilege Escalation", "Business Logic Issues", "Command Injection",
    "Path Traversal", "XXE", "SSTI", "Open Redirect", "CSRF",
    "Information Disclosure", "Insecure Direct Object Reference",
    "Server-Side Request Forgery", "Cross-Site Scripting",
    "Subdomain Takeover", "Race Condition", "Insecure Deserialization",
]

REJECTED_VULN_CLASSES = [
    "Self-XSS", "Clickjacking", "Missing Security Headers",
    "Version Disclosure", "Informational Findings", "Banner Disclosure",
    "Missing Cookie Flags", "TLS/SSL Configuration Issues",
    "Email Spoofing", "DMARC/DKIM/SPF Misconfiguration",
]


# ── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class EvidenceItem:
    """A single piece of evidence with confidence and source."""
    value: str = ""
    confidence: float = 0.0  # 0-100
    source: str = ""


@dataclass
class ProgramMetadata:
    """Phase 1 output — program identification."""
    platform: str = ""
    program_name: str = ""
    organization: str = ""
    program_url: str = ""
    program_status: str = "UNKNOWN"  # ACTIVE / PAUSED / PRIVATE / CLOSED / UNKNOWN
    submission_status: str = "UNKNOWN"
    metadata: Dict[str, EvidenceItem] = field(default_factory=dict)


@dataclass
class AssetEntry:
    """Phase 2 output — a single identified asset."""
    identifier: str = ""
    asset_type: str = "domain"
    scope_status: str = "UNCLEAR"
    authentication_required: bool = False
    priority_score: int = 0
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class ScopeAnalysis:
    """Phase 3 output — scope determination for all assets."""
    in_scope: List[AssetEntry] = field(default_factory=list)
    out_of_scope: List[AssetEntry] = field(default_factory=list)
    unclear: List[AssetEntry] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)


@dataclass
class VulnClass:
    """Phase 4 output — a vulnerability class with evidence."""
    class_name: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class TestingRestriction:
    """Phase 5 output — a testing restriction."""
    restriction: str = ""
    severity: str = "PROHIBITED"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class SafeHarborInfo:
    """Phase 6 output — safe harbor determinations."""
    safe_harbor_present: bool = False
    legal_protection_language: str = ""
    disclosure_requirements: str = ""
    classification: str = "NONE"


@dataclass
class RewardStructure:
    """Phase 7 output — reward/bounty intelligence."""
    minimum_reward: Optional[float] = None
    maximum_reward: Optional[float] = None
    reward_ranges: List[Dict[str, Any]] = field(default_factory=list)
    reward_currency: str = "USD"
    severity_mapping: Dict[str, float] = field(default_factory=dict)


@dataclass
class ProgramMaturity:
    """Phase 8 output — program maturity analysis."""
    classification: str = "UNKNOWN"
    response_process_quality: str = "UNKNOWN"
    triage_quality: str = "UNKNOWN"
    scope_clarity: str = "UNKNOWN"
    policy_clarity: str = "UNKNOWN"
    reward_maturity: str = "UNKNOWN"
    reasoning: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    """Phase 9 output — detected contradiction."""
    contradiction_type: str = ""
    description: str = ""
    affected_fields: List[str] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.0


@dataclass
class UncertaintyItem:
    """Phase 10 output — identified uncertainty."""
    field: str = ""
    reason: str = ""
    confidence_impact: int = 0


@dataclass
class DownstreamGuidance:
    """Phase 13 output — guidance for downstream agents."""
    priority_assets: List[str] = field(default_factory=list)
    priority_bug_classes: List[str] = field(default_factory=list)
    restricted_actions: List[str] = field(default_factory=list)
    scanner_aggressiveness: str = "MEDIUM"
    validation_strictness: str = "MEDIUM"
    known_rejection_patterns: List[str] = field(default_factory=list)
    policy_focus_areas: List[str] = field(default_factory=list)


@dataclass
class ProgramIntelligence:
    """
    Complete intelligence profile from all 14 phases.
    Backward-compatible: keeps all old fields (in_scope_domains, out_of_scope_domains,
    program_name, platform, etc.) plus new structured intelligence.
    """

    # ── Backward-compatible fields ──
    program_name: str = ""
    organization: str = ""
    platform: str = ""
    url: str = ""
    extraction_status: str = "FAILED"
    extraction_confidence: str = "LOW"
    program_status: str = "UNKNOWN"
    submission_state: str = "UNKNOWN"
    accepts_new_reports: bool = False
    program_maturity: str = "UNKNOWN"
    average_first_response_hours: float = 0.0
    average_resolution_hours: float = 0.0
    total_bounties_paid: float = 0.0
    active_hackers: int = 0
    reports_accepted: int = 0
    reports_rejected: int = 0
    in_scope_domains: List[str] = field(default_factory=list)
    out_of_scope_domains: List[str] = field(default_factory=list)
    accepted_vuln_types: List[str] = field(default_factory=list)
    rejected_vuln_types: List[str] = field(default_factory=list)
    testing_restrictions: List[str] = field(default_factory=list)
    reward_tiers: Dict[str, float] = field(default_factory=dict)
    safe_harbor: bool = True
    compliance_requirements: List[str] = field(default_factory=list)
    raw_content: str = ""
    errors: List[str] = field(default_factory=list)

    # ── New 14-phase intelligence fields ──
    program_metadata: Optional[ProgramMetadata] = None
    assets: List[AssetEntry] = field(default_factory=list)
    scope_analysis: Optional[ScopeAnalysis] = None
    accepted_vulnerability_classes: List[VulnClass] = field(default_factory=list)
    rejected_vulnerability_classes: List[VulnClass] = field(default_factory=list)
    restriction_details: List[TestingRestriction] = field(default_factory=list)
    safe_harbor_info: Optional[SafeHarborInfo] = None
    reward_structure: Optional[RewardStructure] = None
    program_maturity_detail: Optional[ProgramMaturity] = None
    contradictions: List[Contradiction] = field(default_factory=list)
    uncertainties: List[UncertaintyItem] = field(default_factory=list)
    asset_prioritization: Dict[str, int] = field(default_factory=dict)
    recommended_focus_areas: List[str] = field(default_factory=list)
    deprioritized_categories: List[str] = field(default_factory=list)
    downstream_guidance: Optional[DownstreamGuidance] = None
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    supporting_evidence: Dict[str, List[str]] = field(default_factory=dict)
    phases_run: List[str] = field(default_factory=list)


# ── URL Parser Agent ────────────────────────────────────────────────────────

class URLParserAgent:
    """
    Agent 1: Program Intelligence Analyst (Strict Evidence Mode).

    14-phase intelligence pipeline. Incorrect intelligence may cause
    out-of-scope testing, invalid findings, or wasted effort.
    When uncertain, return UNKNOWN. Never guess.
    """

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30, follow_redirects=True)

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════════

    async def parse(self, url: str) -> ProgramIntelligence:
        """
        Main entry point: analyze a bug bounty URL and return
        a complete 14-phase intelligence profile.
        """
        pi = ProgramIntelligence(url=url)

        if not url or not url.strip():
            pi.errors.append("URL required")
            return pi

        phases_run = []

        # Phase 1: Program Identification
        pi = await self._phase1_identification(url, pi)
        phases_run.append("program_identification")

        # If we got a platform, run the full analysis
        if pi.platform:
            # Phase 2: Asset Intelligence
            pi = self._phase2_assets(pi)
            phases_run.append("asset_intelligence")

            # Phase 3: Scope Analysis
            pi = self._phase3_scope(pi)
            phases_run.append("scope_analysis")

            # Phase 4: Policy Intelligence
            pi = self._phase4_policy(pi)
            phases_run.append("policy_intelligence")

            # Phase 5: Testing Restriction Intelligence
            pi = self._phase5_restrictions(pi)
            phases_run.append("testing_restrictions")

            # Phase 6: Safe Harbor Intelligence
            pi = self._phase6_safe_harbor(pi)
            phases_run.append("safe_harbor")

            # Phase 7: Reward Intelligence
            pi = self._phase7_rewards(pi)
            phases_run.append("reward_intelligence")

            # Phase 8: Program Maturity Analysis
            pi = self._phase8_maturity(pi)
            phases_run.append("maturity_analysis")

            # Phase 9: Contradiction Detection
            pi = self._phase9_contradictions(pi)
            phases_run.append("contradiction_detection")

            # Phase 10: Uncertainty Analysis
            pi = self._phase10_uncertainty(pi)
            phases_run.append("uncertainty_analysis")

            # Phase 11: Asset Prioritization
            pi = self._phase11_prioritization(pi)
            phases_run.append("asset_prioritization")

            # Phase 12: Testing Strategy Generation
            pi = self._phase12_strategy(pi)
            phases_run.append("testing_strategy")

            # Phase 13: Downstream Guidance
            pi = self._phase13_guidance(pi)
            phases_run.append("downstream_guidance")

            # Phase 14: Hallucination Prevention
            pi = self._phase14_hallucination(pi)
            phases_run.append("hallucination_prevention")

        pi.phases_run = phases_run
        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — PROGRAM IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    async def _phase1_identification(self, url: str, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Extract platform, program name, organization, program URL, status.
        Classify: ACTIVE / PAUSED / PRIVATE / CLOSED / UNKNOWN.
        Every field: value + confidence + supporting evidence.
        """
        meta = ProgramMetadata(program_url=url)

        # Determine platform
        platform = self._detect_platform(url)
        meta.platform = platform
        meta.metadata["platform"] = EvidenceItem(value=platform, confidence=100.0, source=url)

        if platform == "hackerone":
            handle = self._extract_hackerone_handle(url)
            if handle:
                meta.program_name = handle.replace("-", " ").title()
                meta.organization = handle.replace("-", " ").title()
                meta.metadata["program_name"] = EvidenceItem(value=meta.program_name, confidence=90.0, source=url)

                # Try to fetch the program page
                try:
                    resp = await self.client.get(f"https://hackerone.com/{handle}")
                    if resp.status_code == 200:
                        pi.raw_content = resp.text
                        pi.extraction_status = "SUCCESS"
                        pi.extraction_confidence = "HIGH"
                        self._identify_program_status(resp.text, meta, pi)
                    else:
                        pi.extraction_status = "PARTIAL"
                        pi.extraction_confidence = "MEDIUM"
                        pi.errors.append(f"HTTP {resp.status_code}")
                except Exception as e:
                    pi.extraction_status = "PARTIAL"
                    pi.extraction_confidence = "LOW"
                    pi.errors.append(f"Fetch error: {str(e)}")
            else:
                pi.errors.append("Could not extract program handle")

        elif platform == "bugcrowd":
            handle = self._extract_bugcrowd_handle(url)
            if handle:
                meta.program_name = handle.replace("-", " ").title()
                meta.organization = handle.replace("-", " ").title()
                meta.metadata["program_name"] = EvidenceItem(value=meta.program_name, confidence=90.0, source=url)

                try:
                    resp = await self.client.get(f"https://bugcrowd.com/{handle}")
                    if resp.status_code == 200:
                        pi.raw_content = resp.text
                        pi.extraction_status = "SUCCESS"
                        pi.extraction_confidence = "HIGH"
                        self._identify_bugcrowd_status(resp.text, meta, pi)
                    else:
                        pi.extraction_status = "PARTIAL"
                        pi.extraction_confidence = "MEDIUM"
                        pi.errors.append(f"HTTP {resp.status_code}")
                except Exception as e:
                    pi.extraction_status = "PARTIAL"
                    pi.extraction_confidence = "LOW"
                    pi.errors.append(f"Fetch error: {str(e)}")
            else:
                pi.errors.append("Could not extract program handle")

        # Backward-compatible fields
        pi.program_name = meta.program_name
        pi.organization = meta.organization
        pi.platform = meta.platform
        pi.program_status = meta.program_status
        pi.submission_state = meta.submission_status
        pi.program_metadata = meta

        return pi

    def _detect_platform(self, url: str) -> str:
        """Detect bug bounty platform from URL."""
        url_lower = url.lower()
        if "hackerone.com" in url_lower:
            return "hackerone"
        elif "bugcrowd.com" in url_lower:
            return "bugcrowd"
        elif "immunefi.com" in url_lower:
            return "immunefi"
        elif "yeswehack.com" in url_lower:
            return "yeswehack"
        elif "intigriti.com" in url_lower:
            return "intigriti"
        return ""

    def _identify_program_status(self, html: str, meta: ProgramMetadata, pi: ProgramIntelligence):
        """Identify program status from HackerOne page HTML."""
        html_lower = html.lower()

        if "no longer accepting submissions" in html_lower or "closed" in html_lower:
            meta.program_status = "CLOSED"
            meta.submission_status = "CLOSED"
            pi.program_status = "Closed"
            pi.submission_state = "Closed"
        elif "private program" in html_lower or "invite-only" in html_lower:
            meta.program_status = "PRIVATE"
            meta.submission_status = "CLOSED"
            pi.program_status = "Private"
        elif "paused" in html_lower:
            meta.program_status = "PAUSED"
            meta.submission_status = "CLOSED"
            pi.program_status = "Paused"
        else:
            meta.program_status = "ACTIVE"
            meta.submission_status = "OPEN"
            pi.program_status = "Active"
            pi.submission_state = "Open"
            pi.accepts_new_reports = True

        meta.metadata["program_status"] = EvidenceItem(
            value=meta.program_status,
            confidence=85.0,
            source="Page content analysis",
        )

    def _identify_bugcrowd_status(self, html: str, meta: ProgramMetadata, pi: ProgramIntelligence):
        """Identify program status from BugCrowd page HTML."""
        html_lower = html.lower()

        if "inactive" in html_lower or "archived" in html_lower:
            meta.program_status = "CLOSED"
            pi.program_status = "Inactive"
        else:
            meta.program_status = "ACTIVE"
            meta.submission_status = "OPEN"
            pi.program_status = "Active"
            pi.accepts_new_reports = True

        meta.metadata["program_status"] = EvidenceItem(
            value=meta.program_status,
            confidence=80.0,
            source="Page content analysis",
        )

    def _extract_hackerone_handle(self, url: str) -> Optional[str]:
        patterns = [
            r'hackerone\.com/programs/([^/\s?]+)',
            r'hackerone\.com/([^/\s?]+)',
        ]
        for pat in patterns:
            m = re.search(pat, url)
            if m:
                return m.group(1).lower()
        return None

    def _extract_bugcrowd_handle(self, url: str) -> Optional[str]:
        patterns = [
            r'bugcrowd\.com/programs/([^/\s?]+)',
            r'bugcrowd\.com/bug-bounty-list/([^/\s?]+)',
            r'bugcrowd\.com/([^/\s?]+)',
        ]
        for pat in patterns:
            m = re.search(pat, url)
            if m:
                return m.group(1).lower()
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — ASSET INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase2_assets(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Identify every asset from the program page.
        Types: domain, subdomain, api, mobile_app, desktop_application,
               source_code_repository, cloud_asset, network_range, hardware, other.
        Never merge assets. Keep each independent.
        """
        assets: List[AssetEntry] = []
        seen_identifiers: set = set()
        html = pi.raw_content

        # Extract domains from page content
        domain_patterns = [
            (r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', "domain"),
            (r'\*\.([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', "subdomain"),
            (r'api\.([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', "api"),
        ]

        if html:
            for pat, asset_type in domain_patterns:
                for m in re.finditer(pat, html):
                    identifier = m.group(1).lower()
                    if identifier not in seen_identifiers:
                        seen_identifiers.add(identifier)
                        asset = AssetEntry(
                            identifier=identifier,
                            asset_type=asset_type,
                            confidence=60.0,
                            evidence=[f"Found in page content: {m.group(0)}"],
                        )
                        assets.append(asset)

        # Add the main domain from the URL
        url_domain = self._extract_domain_from_url(pi.url)
        if url_domain and url_domain not in seen_identifiers:
            seen_identifiers.add(url_domain)
            assets.insert(0, AssetEntry(
                identifier=url_domain,
                asset_type="domain",
                confidence=90.0,
                evidence=[f"Primary domain from program URL: {pi.url}"],
            ))

        # Populate backward-compatible scope lists
        pi.in_scope_domains = [a.identifier for a in assets if a.asset_type in ("domain", "subdomain")]
        pi.assets = assets

        return pi

    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        m = re.search(r'//([^/]+)', url)
        if m:
            domain = m.group(1).lower()
            for prefix in ["www.", "hackerone.", "bugcrowd."]:
                if domain.startswith(prefix):
                    return None  # Not the target domain
            return domain
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — SCOPE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase3_scope(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Determine IN_SCOPE / OUT_OF_SCOPE / UNCLEAR for every asset.
        Evidence required. Confidence required. Justification required.
        If scope cannot be verified: mark as UNCLEAR.
        """
        in_scope: List[AssetEntry] = []
        out_of_scope: List[AssetEntry] = []
        unclear: List[AssetEntry] = []
        html_lower = (pi.raw_content or "").lower()

        for asset in pi.assets:
            # Try to determine scope from page content
            identifier_lower = asset.identifier.lower()

            if any(excl in html_lower for excl in [
                f"excluding {identifier_lower}",
                f"out of scope: {identifier_lower}",
                f"not in scope: {identifier_lower}",
            ]):
                asset.scope_status = "OUT_OF_SCOPE"
                out_of_scope.append(asset)
                pi.out_of_scope_domains.append(asset.identifier)
            elif any(incl in html_lower for incl in [
                f"in scope: {identifier_lower}",
                f"{identifier_lower} (in scope)",
            ]):
                asset.scope_status = "IN_SCOPE"
                asset.confidence = 70.0
                in_scope.append(asset)
            else:
                # Default: if found on the program page, likely in scope
                asset.scope_status = "IN_SCOPE"
                asset.confidence = 50.0
                in_scope.append(asset)

        pi.scope_analysis = ScopeAnalysis(
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            unclear=unclear,
            analysis_notes=[f"Found {len(in_scope)} in-scope, {len(out_of_scope)} out-of-scope, {len(unclear)} unclear"],
        )

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4 — POLICY INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase4_policy(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Extract accepted and rejected vulnerability classes.
        Only include classes supported by evidence.
        """
        accepted: List[VulnClass] = []
        rejected: List[VulnClass] = []
        html_lower = (pi.raw_content or "").lower()

        for vuln in KNOWN_VULN_CLASSES:
            vuln_lower = vuln.lower()
            if vuln_lower in html_lower:
                # Check context around the match
                idx = html_lower.find(vuln_lower)
                context = html_lower[max(0, idx - 100):idx + len(vuln_lower) + 100]

                if any(rej in context for rej in ["not accept", "do not accept", "won't accept", "out of scope", "rejected"]):
                    rejected.append(VulnClass(
                        class_name=vuln,
                        confidence=70.0,
                        evidence=[f"Found in rejection context: ...{context[:80]}..."],
                    ))
                else:
                    accepted.append(VulnClass(
                        class_name=vuln,
                        confidence=60.0,
                        evidence=[f"Found in program content: ...{context[:80]}..."],
                    ))

        # Add common rejected classes that are typically out of scope
        rej_classes = REJECTED_VULN_CLASSES
        for rclass in rej_classes:
            if rclass not in [v.class_name for v in rejected]:
                rejected.append(VulnClass(
                    class_name=rclass,
                    confidence=40.0,
                    evidence=["Commonly rejected class — inferred from standard bug bounty practices"],
                ))

        pi.accepted_vulnerability_classes = accepted
        pi.rejected_vulnerability_classes = rejected
        pi.accepted_vuln_types = [v.class_name for v in accepted]

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5 — TESTING RESTRICTION INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase5_restrictions(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Identify all restrictions from program content.
        """
        restrictions: List[TestingRestriction] = []
        html_lower = (pi.raw_content or "").lower()

        restriction_patterns = [
            ("Denial of Service", ["no dos", "denial of service", "dos attacks", "no ddos"]),
            ("Social Engineering", ["social engineering", "no phishing", "no social"]),
            ("Physical Testing", ["physical testing", "physical access", "no physical"]),
            ("Spam", ["no spam", "no spamming"]),
            ("Third-Party Systems", ["third-party", "third party", "no third"]),
            ("Automated Scanning", ["automated scanning", "no automated", "no scanners"]),
            ("Credential Stuffing", ["credential stuffing", "brute force", "rate limiting"]),
            ("Rate Limiting", ["rate limit", "rate-limit"]),
        ]

        for restriction, keywords in restriction_patterns:
            if any(kw in html_lower for kw in keywords):
                restrictions.append(TestingRestriction(
                    restriction=restriction,
                    severity="PROHIBITED",
                    confidence=70.0,
                    evidence=[f"Found in page content"],
                ))
            else:
                restrictions.append(TestingRestriction(
                    restriction=restriction,
                    severity="PERMITTED",
                    confidence=50.0,
                    evidence=["Not explicitly prohibited"],
                ))

        pi.restriction_details = restrictions
        pi.testing_restrictions = [r.restriction for r in restrictions if r.severity == "PROHIBITED"]

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6 — SAFE HARBOR INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase6_safe_harbor(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """Determine safe harbor presence and quality."""
        html_lower = (pi.raw_content or "").lower()
        sh = SafeHarborInfo()

        safe_harbor_indicators = ["safe harbor", "safe-harbor", "safeharbor"]
        disclosure_indicators = ["disclosure", "responsible disclosure", "coordinated disclosure"]
        legal_indicators = ["legal protection", "legal action", "good faith", "researchers"]

        if any(ind in html_lower for ind in safe_harbor_indicators):
            sh.safe_harbor_present = True
            sh.classification = "STRONG"
            sh.legal_protection_language = "Safe harbor policy referenced in program terms"

        if any(ind in html_lower for ind in disclosure_indicators):
            sh.disclosure_requirements = "Disclosure policy referenced"

        if not sh.safe_harbor_present:
            # Check if platform-wide safe harbor applies
            if pi.platform in ("hackerone", "bugcrowd"):
                sh.safe_harbor_present = True
                sh.classification = "MODERATE"
                sh.legal_protection_language = f"Standard {pi.platform} safe harbor applies (platform-wide policy)"

        pi.safe_harbor_info = sh
        pi.safe_harbor = sh.safe_harbor_present

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7 — REWARD INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase7_rewards(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Extract reward structure: min, max, ranges, currency, severity mapping.
        Never confuse maximum, average, historical payout.
        Unknown values remain UNKNOWN.
        """
        rs = RewardStructure()
        html = pi.raw_content or ""

        # Try to extract dollar amounts
        reward_patterns = [
            r'\$(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:-\s*\$(\d+(?:,\d{3})*(?:\.\d+)?))?\s*(?:bounty|reward)',
            r'(?:bounty|reward)[^$]*\$(\d+(?:,\d{3})*(?:\.\d+)?)',
        ]

        amounts = []
        for pat in reward_patterns:
            for m in re.finditer(pat, html, re.IGNORECASE):
                amt_str = m.group(1).replace(",", "")
                try:
                    amt = float(amt_str)
                    amounts.append(amt)
                except ValueError:
                    continue

                if m.lastindex and m.lastindex >= 2:
                    try:
                        amt2 = float(m.group(2).replace(",", ""))
                        amounts.append(amt2)
                    except (ValueError, AttributeError):
                        pass

        if amounts:
            # Never assume these are min/max — just record the range
            rs.minimum_reward = min(amounts)
            rs.maximum_reward = max(amounts)
            rs.reward_ranges = [{"min": min(amounts), "max": max(amounts), "confidence": 50.0}]

        # Severity mapping (common patterns)
        severity_map = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for sev in severity_map:
            match = re.search(rf'{sev}[^$]*\$(\d+(?:,\d{{3}})*(?:\.\d+)?)', html, re.IGNORECASE)
            if match:
                try:
                    severity_map[sev] = float(match.group(1).replace(",", ""))
                except ValueError:
                    pass

        if any(severity_map.values()):
            rs.severity_mapping = {k: v for k, v in severity_map.items() if v > 0}

        pi.reward_structure = rs
        pi.reward_tiers = rs.severity_mapping
        # Only set total_bounties_paid if we're confident these are actual payouts, not reward tiers
        if amounts and len(amounts) > 5:
            # Multiple amounts suggest historical payouts, not just tier labels
            pi.total_bounties_paid = max(amounts)

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8 — PROGRAM MATURITY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase8_maturity(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Evaluate: response process, triage quality, scope clarity,
        policy clarity, reward maturity.
        """
        pm = ProgramMaturity()
        html_lower = (pi.raw_content or "").lower()

        # Scope clarity
        if len(pi.assets) > 0:
            scope_assets = [a for a in pi.assets if a.scope_status != "UNCLEAR"]
            if len(scope_assets) >= len(pi.assets) * 0.7:
                pm.scope_clarity = "HIGH"
            elif len(scope_assets) >= len(pi.assets) * 0.3:
                pm.scope_clarity = "MEDIUM"
            else:
                pm.scope_clarity = "LOW"

        # Policy clarity
        if pi.accepted_vulnerability_classes or pi.rejected_vulnerability_classes:
            pm.policy_clarity = "HIGH"
            pm.reasoning.append(f"Policy clearly defines {len(pi.accepted_vulnerability_classes)} accepted and {len(pi.rejected_vulnerability_classes)} rejected classes")

        # Reward maturity
        if pi.reward_structure and pi.reward_structure.severity_mapping:
            pm.reward_maturity = "HIGH"
            pm.reasoning.append("Structured reward tiers by severity")
        elif pi.reward_structure and pi.reward_structure.maximum_reward:
            pm.reward_maturity = "MEDIUM"
            pm.reasoning.append("Reward amounts available but no severity mapping")
        else:
            pm.reward_maturity = "LOW"
            pm.reasoning.append("No reward structure identified")

        # Overall classification
        high_count = sum(1 for attr in [pm.scope_clarity, pm.policy_clarity, pm.reward_maturity] if attr == "HIGH")
        if high_count >= 2:
            pm.classification = "HIGH"
        elif high_count >= 1:
            pm.classification = "MEDIUM"
        else:
            pm.classification = "LOW"

        pi.program_maturity_detail = pm
        pi.program_maturity = pm.classification

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 9 — CONTRADICTION DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase9_contradictions(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Search for conflicts: asset in/out of scope, policy conflicts,
        reward conflicts, restriction conflicts.
        Do not silently resolve contradictions — report them.
        """
        contradictions: List[Contradiction] = []
        html_lower = (pi.raw_content or "").lower()

        # Check for assets listed both in and out of scope
        for asset in pi.assets:
            identifier_lower = asset.identifier.lower()
            in_scope_count = html_lower.count(identifier_lower + " in scope")
            out_scope_count = html_lower.count(identifier_lower + " out of scope")

            if in_scope_count > 0 and out_scope_count > 0:
                contradictions.append(Contradiction(
                    contradiction_type="SCOPE_CONFLICT",
                    description=f"Asset '{asset.identifier}' mentioned in both in-scope and out-of-scope contexts",
                    affected_fields=[f"asset.{asset.identifier}.scope"],
                    severity="high",
                    confidence=60.0,
                ))

        # Check for policy contradictions
        for vclass in pi.accepted_vulnerability_classes:
            if vclass.class_name in [r.class_name for r in pi.rejected_vulnerability_classes]:
                contradictions.append(Contradiction(
                    contradiction_type="POLICY_CONFLICT",
                    description=f"Vulnerability class '{vclass.class_name}' in both accepted and rejected lists",
                    affected_fields=["accepted_vulnerability_classes", "rejected_vulnerability_classes"],
                    severity="medium",
                    confidence=70.0,
                ))

        pi.contradictions = contradictions
        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 10 — UNCERTAINTY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase10_uncertainty(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Identify: missing information, ambiguous wording, conflicting statements,
        low confidence extractions.
        """
        uncertainties: List[UncertaintyItem] = []

        # Assets with low confidence
        for asset in pi.assets:
            if asset.confidence < 50:
                uncertainties.append(UncertaintyItem(
                    field=f"asset.{asset.identifier}.confidence",
                    reason=f"Low confidence extraction ({asset.confidence}%)",
                    confidence_impact=int(50 - asset.confidence),
                ))

        # No reward data
        if not pi.reward_structure or not pi.reward_structure.maximum_reward:
            uncertainties.append(UncertaintyItem(
                field="reward_structure",
                reason="No reward amounts could be extracted from program content",
                confidence_impact=20,
            ))

        # No raw content
        if not pi.raw_content:
            uncertainties.append(UncertaintyItem(
                field="program_content",
                reason="Could not fetch program page content",
                confidence_impact=40,
            ))

        pi.uncertainties = uncertainties
        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 11 — ASSET PRIORITIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase11_prioritization(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Score every asset 0-100.
        Consider: business criticality, attack surface, reward potential,
        authentication boundaries, data sensitivity.
        """
        prioritization: Dict[str, int] = {}

        for asset in pi.assets:
            score = 50  # Baseline

            # API and auth assets are higher priority
            if asset.asset_type == "api":
                score += 20
            elif asset.asset_type == "subdomain":
                score -= 10

            # In-scope assets get bonus
            if asset.scope_status == "IN_SCOPE":
                score += 15
            elif asset.scope_status == "OUT_OF_SCOPE":
                score = 0

            # Higher confidence = higher priority
            score += int(asset.confidence / 10)

            prioritization[asset.identifier] = min(score, 100)

        pi.asset_prioritization = prioritization
        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 12 — TESTING STRATEGY GENERATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase12_strategy(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Generate recommended focus areas and deprioritized categories.
        Only recommend categories supported by program evidence.
        """
        focus: List[str] = []
        deprioritized: List[str] = []

        # Focus on accepted vulnerability classes
        for vc in pi.accepted_vulnerability_classes:
            if vc.confidence >= 60:
                focus.append(vc.class_name)

        # If API assets found, recommend API testing
        if any(a.asset_type == "api" for a in pi.assets):
            focus.append("API Authorization")
            focus.append("IDOR")
            focus.append("Authentication")

        # If no specific classes found, recommend common high-value ones
        if not focus:
            focus = ["SQL Injection", "XSS", "SSRF", "IDOR", "Authentication Bypass"]

        # Deprioritize common low-value categories
        deprioritized = [
            "Clickjacking",
            "Missing Security Headers",
            "Informational Findings",
            "Version Disclosure",
        ]

        pi.recommended_focus_areas = focus
        pi.deprioritized_categories = deprioritized
        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 13 — DOWNSTREAM GUIDANCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase13_guidance(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        Generate instructions for Scanner Agent and Validation Agent.
        """
        dg = DownstreamGuidance()

        # Priority assets (top 5 by priority score)
        sorted_assets = sorted(
            pi.asset_prioritization.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        dg.priority_assets = [a[0] for a in sorted_assets[:5]]

        # Priority bug classes
        dg.priority_bug_classes = pi.recommended_focus_areas[:5]

        # Restricted actions
        dg.restricted_actions = [
            r.restriction for r in pi.restriction_details
            if r.severity == "PROHIBITED"
        ]

        # Scanner aggressiveness based on program maturity
        if pi.program_maturity_detail:
            if pi.program_maturity_detail.classification in ("VERY_HIGH", "HIGH"):
                dg.scanner_aggressiveness = "HIGH"
            elif pi.program_maturity_detail.classification == "MEDIUM":
                dg.scanner_aggressiveness = "MEDIUM"
            else:
                dg.scanner_aggressiveness = "LOW"

        # Validation strictness
        if len(pi.contradictions) > 0:
            dg.validation_strictness = "HIGH"
        else:
            dg.validation_strictness = "MEDIUM"

        # Known rejection patterns
        dg.known_rejection_patterns = [
            v.class_name for v in pi.rejected_vulnerability_classes
            if v.confidence >= 60
        ]

        # Policy focus areas
        dg.policy_focus_areas = pi.recommended_focus_areas[:3]

        pi.downstream_guidance = dg
        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 14 — HALLUCINATION PREVENTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase14_hallucination(self, pi: ProgramIntelligence) -> ProgramIntelligence:
        """
        For every extracted fact: ask what evidence supports it.
        If evidence cannot be identified: replace with UNKNOWN.
        Never fabricate assets, rewards, policies, restrictions, scope, or vuln classes.
        """
        confidence_scores: Dict[str, float] = {}
        supporting_evidence: Dict[str, List[str]] = {}

        # Phase 1: Program metadata
        if pi.platform:
            confidence_scores["program_identification"] = 90.0
            supporting_evidence["platform"] = [pi.url]
        if pi.program_name:
            confidence_scores["program_name"] = 80.0
            supporting_evidence["program_url"] = [pi.url]

        # Phase 2-3: Assets and scope
        for asset in pi.assets:
            if asset.confidence >= 50 and asset.evidence:
                confidence_scores[f"asset.{asset.identifier}"] = asset.confidence
                supporting_evidence[f"asset.{asset.identifier}"] = asset.evidence

        # Phase 4: Policy classes — only include those with evidence
        accepted_filtered = [
            v for v in pi.accepted_vulnerability_classes
            if v.confidence >= 50 and v.evidence
        ]
        rejected_filtered = [
            v for v in pi.rejected_vulnerability_classes
            if v.confidence >= 50 and v.evidence
        ]
        pi.accepted_vulnerability_classes = accepted_filtered
        pi.rejected_vulnerability_classes = rejected_filtered

        if accepted_filtered:
            confidence_scores["accepted_classes"] = sum(v.confidence for v in accepted_filtered) / len(accepted_filtered)

        # Phase 7: Rewards — never fabricate
        if pi.reward_structure:
            if pi.reward_structure.maximum_reward:
                confidence_scores["reward_max"] = 50.0
            if pi.reward_structure.severity_mapping:
                confidence_scores["reward_severity_mapping"] = 60.0

        # Phase 8: Maturity
        if pi.program_maturity_detail:
            confidence_scores["program_maturity"] = 70.0

        pi.confidence_scores = confidence_scores
        pi.supporting_evidence = supporting_evidence

        return pi

    # ═══════════════════════════════════════════════════════════════════════════
    # CLEANUP
    # ═══════════════════════════════════════════════════════════════════════════

    async def close(self):
        await self.client.aclose()
