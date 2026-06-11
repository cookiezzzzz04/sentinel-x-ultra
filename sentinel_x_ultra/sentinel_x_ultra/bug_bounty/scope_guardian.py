"""
AGENT 3 — SCOPE GUARDIAN & AUTHORIZATION ENGINE

You are the authoritative source of scope enforcement and target authorization.
Your purpose is to ensure NO action is performed against assets that are not
explicitly authorized by the bug bounty program.

Scope is law.
If authorization cannot be proven, authorization does not exist.
Default behavior is DENY / BLOCK.

12-Phase Pipeline:
  1. Ownership Verification
  2. Explicit Out-of-Scope Rules
  3. Explicit In-Scope Rules
  4. Asset Classification
  5. Path Restrictions
  6. Subdomain Authorization
  7. Network Authorization
  8. Testing Authorization
  9. Program Policy Overrides
 10. Risk of Misauthorization
 11. Contradiction Detection
 12. Hallucination Prevention
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


# ── Enums ───────────────────────────────────────────────────────────────────

class AuthorizationState(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class OwnershipStatus(str, Enum):
    VERIFIED = "VERIFIED"
    LIKELY = "LIKELY"
    UNKNOWN = "UNKNOWN"
    THIRD_PARTY = "THIRD_PARTY"


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    URL = "URL"
    API = "API"
    WEB_APPLICATION = "WEB_APPLICATION"
    MOBILE_APP = "MOBILE_APP"
    DESKTOP_APP = "DESKTOP_APP"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    IP_ADDRESS = "IP_ADDRESS"
    CIDR_RANGE = "CIDR_RANGE"
    REPOSITORY = "REPOSITORY"
    OTHER = "OTHER"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AuthorizationAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


# ── Legacy Dataclass (Backward Compatible) ──────────────────────────────────

@dataclass
class ScopeCheckResult:
    """Result of a scope check on a target (legacy format)."""
    target: str
    in_scope: bool
    reason: str
    matched_rule: str = ""
    severity: str = "info"  # info, warning, block


# ── New Authorization Output Schema ─────────────────────────────────────────

@dataclass
class ScopeAuthorization:
    """Complete structured output of the Scope Guardian & Authorization Engine."""
    # Final decision
    decision: AuthorizationState = AuthorizationState.BLOCK
    authorization_confidence: float = 0.0
    authorized: bool = False

    # Phase-level results
    ownership_status: str = ""
    scope_status: str = ""
    asset_type: str = ""
    matched_scope_rule: str = ""
    matched_policy_rule: str = ""
    risk_of_misauthorization: str = ""

    # Action categories
    allowed_actions: List[str] = field(default_factory=list)
    restricted_actions: List[str] = field(default_factory=list)
    prohibited_actions: List[str] = field(default_factory=list)

    # Restrictions and evidence
    path_restrictions: List[str] = field(default_factory=list)
    policy_restrictions: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)

    # Reasoning
    reasoning: List[str] = field(default_factory=list)
    recommended_next_action: str = ""


# ── Default Action Categories ───────────────────────────────────────────────

ALLOWED_ACTIONS_DEFAULT = [
    "passive_reconnaissance",
    "authenticated_testing",
    "vulnerability_validation",
]

RESTRICTED_ACTIONS_DEFAULT = [
    "automated_scanning",
    "fuzzing",
    "brute_forcing",
]

PROHIBITED_ACTIONS_DEFAULT = [
    "denial_of_service",
    "credential_stuffing",
    "social_engineering",
    "phishing",
    "physical_attacks",
    "spam",
    "attacks_against_third_parties",
]


# ── Asset Classification Helpers ────────────────────────────────────────────

def classify_asset(target: str) -> Tuple[AssetType, float]:
    """Classify a target into an asset type with confidence score."""
    target = target.strip().lower()

    # IP address
    try:
        ipaddress.IPv4Address(target)
        return AssetType.IP_ADDRESS, 1.0
    except (ValueError, ipaddress.AddressValueError):
        pass

    # CIDR range
    if "/" in target:
        try:
            ipaddress.IPv4Network(target, strict=False)
            return AssetType.CIDR_RANGE, 1.0
        except ValueError:
            pass

    # URL with path
    if target.startswith("http"):
        parsed = urlparse(target)
        path = parsed.path.strip("/")
        if path:
            if "/api/" in target or "/rest/" in target or "/graphql" in target:
                return AssetType.API, 0.9
            return AssetType.URL, 0.8
        return AssetType.DOMAIN, 0.7

    # Check for known patterns
    if target.startswith("*."):
        return AssetType.DOMAIN, 0.6  # Wildcard domain
    if "github.com/" in target or "gitlab.com/" in target:
        return AssetType.REPOSITORY, 0.9
    if "s3.amazonaws.com" in target or "storage.googleapis.com" in target:
        return AssetType.CLOUD_RESOURCE, 0.8

    # Count dots to estimate domain vs subdomain
    dot_count = target.count(".")
    if dot_count <= 1:
        return AssetType.DOMAIN, 0.7
    elif dot_count >= 2:
        return AssetType.SUBDOMAIN, 0.6

    return AssetType.OTHER, 0.3


# ── Domain Matching Helpers ─────────────────────────────────────────────────

def domain_matches(domain: str, pattern: str) -> bool:
    """Check if a domain matches a pattern (exact or suffix)."""
    return domain == pattern or domain.endswith(f".{pattern}")


def wildcard_matches(domain: str, wildcard_domain: str) -> bool:
    """Check if a domain matches a wildcard pattern like *.example.com.
    Delegates to domain_matches since the matching logic is identical.
    """
    return domain_matches(domain, wildcard_domain)


def url_matches_url(target_url: str, scope_url: str) -> bool:
    """Check if a target URL starts with a scope URL pattern."""
    return target_url.startswith(scope_url)


# ── Scope Guardian Agent ────────────────────────────────────────────────────

class ScopeGuardianAgent:
    """
    Agent 3: Scope Guardian & Authorization Engine.

    The authoritative source of scope enforcement and target authorization.
    Operates on the principle: if authorization cannot be proven, it does not exist.

    12-Phase Pipeline:
      1. Ownership Verification
      2. Explicit Out-of-Scope Rules
      3. Explicit In-Scope Rules
      4. Asset Classification
      5. Path Restrictions
      6. Subdomain Authorization
      7. Network Authorization
      8. Testing Authorization
      9. Program Policy Overrides
     10. Risk of Misauthorization
     11. Contradiction Detection
     12. Hallucination Prevention

    Default behavior: BLOCK (DENY).
    When uncertain: REVIEW.
    When authorized: ALLOW.
    """

    def __init__(self):
        # Scope lists
        self.in_scope_domains: List[str] = []
        self.in_scope_wildcards: List[str] = []
        self.out_of_scope_domains: List[str] = []
        self.in_scope_cidrs: List[ipaddress.IPv4Network] = []
        self.in_scope_urls: List[str] = []
        self.out_of_scope_urls: List[str] = []

        # Path-level restrictions
        self.path_allows: List[str] = []    # Explicitly allowed path prefixes
        self.path_blocks: List[str] = []    # Explicitly blocked path prefixes

        # Policy restrictions
        self.policy_restrictions: List[str] = []

        # Third-party / known-owned domains
        self.owned_domains: List[str] = []
        self.third_party_domains: List[str] = []

        # Testing authorization
        self.allowed_actions: List[str] = list(ALLOWED_ACTIONS_DEFAULT)
        self.restricted_actions: List[str] = list(RESTRICTED_ACTIONS_DEFAULT)
        self.prohibited_actions: List[str] = list(PROHIBITED_ACTIONS_DEFAULT)

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API (Backward Compatible)
    # ═══════════════════════════════════════════════════════════════════════════

    def set_scope(
        self,
        in_scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
    ):
        """Configure scope boundaries."""
        self._reset_scope()
        in_scope = in_scope or []
        out_of_scope = out_of_scope or []

        for item in in_scope:
            item = item.strip().lower()
            if item.startswith("*."):
                self.in_scope_wildcards.append(item[2:])
            elif "/" in item:
                try:
                    self.in_scope_cidrs.append(ipaddress.IPv4Network(item, strict=False))
                except ValueError:
                    self.in_scope_domains.append(item)
            elif item.startswith("http"):
                self.in_scope_urls.append(item)
            else:
                self.in_scope_domains.append(item)

        for item in out_of_scope:
            item = item.strip().lower()
            if item.startswith("http"):
                self.out_of_scope_urls.append(item)
            else:
                self.out_of_scope_domains.append(item)
    
    def _reset_scope(self):
        """Reset all scope lists."""
        self.in_scope_domains.clear()
        self.in_scope_wildcards.clear()
        self.out_of_scope_domains.clear()
        self.in_scope_cidrs.clear()
        self.in_scope_urls.clear()
        self.out_of_scope_urls.clear()
        self.path_allows.clear()
        self.path_blocks.clear()
        self.policy_restrictions.clear()

    def set_program_scope(
        self,
        owned_domains: Optional[List[str]] = None,
        third_party_domains: Optional[List[str]] = None,
        allowed_actions: Optional[List[str]] = None,
        restricted_actions: Optional[List[str]] = None,
        prohibited_actions: Optional[List[str]] = None,
        policy_restrictions: Optional[List[str]] = None,
    ):
        """Set additional program-level scope metadata for richer authorization."""
        if owned_domains:
            self.owned_domains = [d.strip().lower() for d in owned_domains]
        if third_party_domains:
            self.third_party_domains = [d.strip().lower() for d in third_party_domains]
        if allowed_actions:
            self.allowed_actions = allowed_actions
        if restricted_actions:
            self.restricted_actions = restricted_actions
        if prohibited_actions:
            self.prohibited_actions = prohibited_actions
        if policy_restrictions:
            self.policy_restrictions = policy_restrictions

    def check_target(self, target: str) -> ScopeCheckResult:
        """Check if a target is within authorized scope (legacy wrapper).

        Runs the full 12-phase pipeline and maps the result back to ScopeCheckResult.
        """
        auth = self._run_full_pipeline(target)
        return ScopeCheckResult(
            target=target,
            in_scope=auth.decision == AuthorizationState.ALLOW,
            reason=auth.reasoning[-1] if auth.reasoning else auth.recommended_next_action,
            matched_rule=auth.matched_scope_rule,
            severity="block" if auth.decision == AuthorizationState.BLOCK else "info",
        )

    def authorize(self, target: str) -> ScopeAuthorization:
        """Run the full 12-phase authorization pipeline.

        This is the primary API for the new implementation.
        Returns the complete structured authorization output.
        """
        return self._run_full_pipeline(target)

    def verify_subdomain(self, subdomain: str) -> ScopeCheckResult:
        """Check if a subdomain is authorized (legacy wrapper)."""
        subdomain = subdomain.strip().lower()
        auth = self._run_full_pipeline(subdomain)
        return ScopeCheckResult(
            target=subdomain,
            in_scope=auth.decision == AuthorizationState.ALLOW,
            reason=auth.reasoning[-1] if auth.reasoning else "Subdomain authorized" if auth.decision == AuthorizationState.ALLOW else "Subdomain not authorized",
            severity="info" if auth.decision == AuthorizationState.ALLOW else "block",
        )

    def batch_check(self, targets: List[str]) -> List[ScopeCheckResult]:
        """Check multiple targets against scope (legacy)."""
        return [self.check_target(t) for t in targets]

    def filter_in_scope(self, targets: List[str]) -> List[str]:
        """Return only targets that pass scope check (legacy)."""
        return [t for t in targets if self.check_target(t).in_scope]

    def filter_out_of_scope(self, targets: List[str]) -> List[str]:
        """Return only targets that fail scope check (legacy)."""
        return [t for t in targets if not self.check_target(t).in_scope]

    # ═══════════════════════════════════════════════════════════════════════════
    # FULL 12-PHASE PIPELINE
    # ═══════════════════════════════════════════════════════════════════════════

    def _run_full_pipeline(self, target: str) -> ScopeAuthorization:
        """Execute all 12 phases in order. Short-circuits on BLOCK."""
        output = ScopeAuthorization()

        # Parse target
        parsed = urlparse(target if target.startswith("http") else f"https://{target}")
        domain = parsed.hostname or target
        path = parsed.path or "/"

        # Phase 1: Ownership Verification
        ownership = self._phase1_ownership(domain, output)
        phases_run = ["ownership"]
        if ownership == OwnershipStatus.THIRD_PARTY:
            return self._finalize_block(output, f"Target {domain} is a third-party asset — no authorization possible", phases_run)
        if ownership == OwnershipStatus.UNKNOWN:
            output.uncertainties.append(f"Ownership of {domain} is unknown — cannot assume authorization")

        # Phase 2: Explicit Out-of-Scope Analysis
        oos_result = self._phase2_out_of_scope(domain, target, path, output)
        phases_run.append("out_of_scope")
        if oos_result == AuthorizationState.BLOCK:
            return self._finalize_block(output, f"Target {domain} is explicitly excluded by out-of-scope rules", phases_run)
        if oos_result == AuthorizationState.REVIEW:
            output.uncertainties.append(f"Target {domain} has unclear out-of-scope status")

        # Phase 3: Explicit In-Scope Analysis — capture match for later use
        scope_match, matched_rule = self._phase3_in_scope(domain, target, path, output)
        phases_run.append("in_scope")
        output.matched_scope_rule = matched_rule

        # Phase 4: Asset Classification
        asset_type, asset_confidence = classify_asset(target)
        phases_run.append("asset_classification")
        output.asset_type = asset_type.value
        output.supporting_evidence.append(f"Asset classified as {asset_type.value} (confidence: {asset_confidence:.0%})")
        if asset_confidence < 0.5:
            output.uncertainties.append(f"Low confidence ({asset_confidence:.0%}) in asset classification")

        # Phase 5: Path-Level Authorization
        path_result, path_restrictions = self._phase5_path(path, output)
        phases_run.append("path_authorization")
        if path_result == AuthorizationState.BLOCK:
            return self._finalize_block(output, f"Path {path} is blocked by path restriction rules", phases_run)
        output.path_restrictions = path_restrictions

        # Phase 6: Subdomain Authorization
        subdomain_result = self._phase6_subdomain(domain, output)
        phases_run.append("subdomain_authorization")
        if subdomain_result == AuthorizationState.BLOCK:
            return self._finalize_block(output, f"Subdomain {domain} is not authorized by any wildcard or exact rule", phases_run)

        # Phase 7: Network Authorization
        network_result = self._phase7_network(domain, output)
        phases_run.append("network_authorization")
        if network_result == AuthorizationState.BLOCK:
            return self._finalize_block(output, f"Network asset {domain} is outside authorized CIDR ranges", phases_run)

        # Phase 8: Testing Authorization
        allowed, restricted, prohibited = self._phase8_testing(output)
        phases_run.append("testing_authorization")
        output.allowed_actions = allowed
        output.restricted_actions = restricted
        output.prohibited_actions = prohibited

        # Phase 9: Policy Overrides
        policy_restrictions = self._phase9_policy(domain, path, output)
        phases_run.append("policy_overrides")
        output.policy_restrictions = policy_restrictions
        if policy_restrictions:
            output.reasoning.append(f"Policy restrictions apply: {len(policy_restrictions)} restriction(s) found")

        # Phase 10: Risk of Misauthorization
        risk = self._phase10_risk(domain, ownership, scope_match, output)
        phases_run.append("risk_misauthorization")
        output.risk_of_misauthorization = risk.value
        if risk == RiskLevel.HIGH:
            output.uncertainties.append(f"High risk of misauthorization for {domain} — requires manual review")

        # Phase 11: Contradiction Detection
        contradictions = self._phase11_contradictions(domain, path, output)
        phases_run.append("contradictions")
        output.contradictions = contradictions
        if contradictions:
            output.uncertainties.append(f"Contradictions found ({len(contradictions)}) — cannot be resolved without manual review")

        # Phase 12: Hallucination Prevention
        hallucinations = self._phase12_hallucination(domain, output)
        phases_run.append("hallucination_prevention")
        output.supporting_evidence.extend(hallucinations)

        # ── Final Decision ──
        output.reasoning.append("Full 12-phase authorization pipeline completed")

        # Determine final decision
        final_decision = self._determine_final_decision(output, scope_match)
        output.decision = final_decision
        output.authorized = final_decision == AuthorizationState.ALLOW

        # Set confidence
        output.authorization_confidence = self._calculate_confidence(output)
        output.recommended_next_action = self._recommend_next_action(output)

        return output

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — OWNERSHIP VERIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase1_ownership(self, domain: str, output: ScopeAuthorization) -> OwnershipStatus:
        """Determine whether the target belongs to the program."""
        # Check owned domains
        for owned in self.owned_domains:
            if domain_matches(domain, owned):
                output.supporting_evidence.append(f"Domain {domain} matches known owned domain {owned}")
                output.ownership_status = OwnershipStatus.VERIFIED.value
                return OwnershipStatus.VERIFIED

        # Check third-party domains
        for tp in self.third_party_domains:
            if domain_matches(domain, tp):
                output.supporting_evidence.append(f"Domain {domain} is recognized as third-party ({tp})")
                output.ownership_status = OwnershipStatus.THIRD_PARTY.value
                return OwnershipStatus.THIRD_PARTY

        # Check against in-scope lists as heuristic for ownership
        for scope_domain in self.in_scope_domains:
            if domain_matches(domain, scope_domain):
                output.supporting_evidence.append(f"Domain {domain} matches in-scope domain {scope_domain}")
                output.ownership_status = OwnershipStatus.LIKELY.value
                return OwnershipStatus.LIKELY

        for wild_domain in self.in_scope_wildcards:
            if wildcard_matches(domain, wild_domain):
                output.supporting_evidence.append(f"Domain {domain} matches in-scope wildcard *.{wild_domain}")
                output.ownership_status = OwnershipStatus.LIKELY.value
                return OwnershipStatus.LIKELY

        # No ownership information
        output.ownership_status = OwnershipStatus.UNKNOWN.value
        return OwnershipStatus.UNKNOWN

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — EXPLICIT OUT-OF-SCOPE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase2_out_of_scope(self, domain: str, target: str, path: str, output: ScopeAuthorization) -> AuthorizationState:
        """Search for explicit out-of-scope entries."""
        # Check excluded domains
        for oos in self.out_of_scope_domains:
            if domain_matches(domain, oos):
                output.supporting_evidence.append(f"Domain {domain} matches out-of-scope domain {oos}")
                output.scope_status = "OUT_OF_SCOPE"
                return AuthorizationState.BLOCK

        # Check excluded URLs
        for oos_url in self.out_of_scope_urls:
            if url_matches_url(target, oos_url):
                output.supporting_evidence.append(f"URL {target} matches out-of-scope URL {oos_url}")
                output.scope_status = "OUT_OF_SCOPE"
                return AuthorizationState.BLOCK

        # No explicit exclusions found
        output.scope_status = "PENDING_SCOPE_CHECK"
        return AuthorizationState.ALLOW  # Allow to proceed to in-scope check

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — EXPLICIT IN-SCOPE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase3_in_scope(self, domain: str, target: str, path: str, output: ScopeAuthorization) -> Tuple[AuthorizationState, str]:
        """Identify matching in-scope rules."""
        matched_rule = ""

        # Check wildcard domains
        for wild_domain in self.in_scope_wildcards:
            if wildcard_matches(domain, wild_domain):
                matched_rule = f"*.{wild_domain}"
                output.supporting_evidence.append(f"Domain {domain} matches wildcard scope *.{wild_domain}")
                output.scope_status = "IN_SCOPE"
                return AuthorizationState.ALLOW, matched_rule

        # Check exact domains and subdomains
        for scope_domain in self.in_scope_domains:
            if domain_matches(domain, scope_domain):
                matched_rule = scope_domain
                output.supporting_evidence.append(f"Domain {domain} matches in-scope domain {scope_domain}")
                output.scope_status = "IN_SCOPE"
                return AuthorizationState.ALLOW, matched_rule

        # Check in-scope URLs
        for scope_url in self.in_scope_urls:
            if url_matches_url(target, scope_url):
                matched_rule = scope_url
                output.supporting_evidence.append(f"URL matches in-scope pattern {scope_url}")
                output.scope_status = "IN_SCOPE"
                return AuthorizationState.ALLOW, matched_rule

        # No matching in-scope rule
        output.scope_status = "NOT_IN_SCOPE"
        output.uncertainties.append(f"No matching in-scope rule found for {domain}")
        return AuthorizationState.REVIEW, matched_rule

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5 — PATH-LEVEL AUTHORIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase5_path(self, path: str, output: ScopeAuthorization) -> Tuple[AuthorizationState, List[str]]:
        """Determine whether path restrictions exist.

        More specific path rules override broader rules.
        """
        path_restrictions = []

        # Check blocked paths first (more specific)
        for blocked in self.path_blocks:
            if path.startswith(blocked):
                path_restrictions.append(f"Path {path} blocked by rule: {blocked}")
                output.supporting_evidence.append(f"Path {path} matches blocked path rule {blocked}")
                return AuthorizationState.BLOCK, path_restrictions

        # Check allowed paths
        if self.path_allows:
            for allowed in self.path_allows:
                if path.startswith(allowed):
                    path_restrictions.append(f"Path {path} allowed by rule: {allowed}")
                    return AuthorizationState.ALLOW, path_restrictions
            # If allows exist but no match, block
            path_restrictions.append(f"Path {path} does not match any allowed path")
            return AuthorizationState.BLOCK, path_restrictions

        # No path rules defined — allow
        return AuthorizationState.ALLOW, path_restrictions

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6 — SUBDOMAIN AUTHORIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase6_subdomain(self, domain: str, output: ScopeAuthorization) -> AuthorizationState:
        """Determine whether wildcard authorization exists.

        IMPORTANT: example.com does NOT automatically authorize api.example.com
        UNLESS *.example.com exists.
        """
        dot_count = domain.count(".")
        if dot_count < 2:
            return AuthorizationState.ALLOW  # Not a subdomain, no additional check needed

        # This is a subdomain — check for wildcard authorization
        for wild_domain in self.in_scope_wildcards:
            if domain.endswith(f".{wild_domain}"):
                return AuthorizationState.ALLOW  # Authorized by wildcard

        # Check if the parent domain is explicitly in scope
        parent_domain = domain.split(".", 1)[1] if dot_count >= 2 else domain
        for scope_domain in self.in_scope_domains:
            if parent_domain == scope_domain:
                # Per prompt: "Exact domain authorization only authorizes the exact domain."
                # Unless wildcard exists, subdomains are NOT automatically authorized.
                output.supporting_evidence.append(
                    f"Subdomain {domain} requires wildcard *.{parent_domain} — exact domain {parent_domain} does not authorize subdomains"
                )
                output.uncertainties.append(
                    f"Subdomain {domain} not authorized: parent domain {parent_domain} is in scope but no wildcard *.{parent_domain} exists"
                )
                return AuthorizationState.REVIEW

        return AuthorizationState.ALLOW  # No subdomain rules, continue

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7 — NETWORK AUTHORIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase7_network(self, domain: str, output: ScopeAuthorization) -> AuthorizationState:
        """Evaluate IP addresses and CIDR ranges against scope."""
        # Only applies to IP addresses
        try:
            target_ip = ipaddress.IPv4Address(domain)
        except (ValueError, ipaddress.AddressValueError):
            return AuthorizationState.ALLOW  # Not an IP, skip

        if not self.in_scope_cidrs:
            output.uncertainties.append(f"IP {domain} cannot be verified — no CIDR ranges configured")
            return AuthorizationState.REVIEW

        for cidr in self.in_scope_cidrs:
            if target_ip in cidr:
                output.supporting_evidence.append(f"IP {domain} is within authorized CIDR {cidr}")
                output.scope_status = "IN_SCOPE"
                return AuthorizationState.ALLOW

        output.supporting_evidence.append(f"IP {domain} is outside all authorized CIDR ranges")
        return AuthorizationState.BLOCK

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8 — TESTING AUTHORIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase8_testing(self, output: ScopeAuthorization) -> Tuple[List[str], List[str], List[str]]:
        """Return allowed, restricted, and prohibited testing actions."""
        return (
            list(self.allowed_actions),
            list(self.restricted_actions),
            list(self.prohibited_actions),
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 9 — POLICY OVERRIDES
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase9_policy(self, domain: str, path: str, output: ScopeAuthorization) -> List[str]:
        """Apply policy restrictions. Policy restrictions override scope authorization."""
        restrictions = []
        target_str = f"{domain}{path}"

        for restriction in self.policy_restrictions:
            r_lower = restriction.lower()
            if r_lower in target_str or r_lower in domain:
                restrictions.append(restriction)
                output.supporting_evidence.append(f"Policy restriction applies: {restriction}")
                output.matched_policy_rule = restriction

        return restrictions

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 10 — RISK OF MISAUTHORIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase10_risk(self, domain: str, ownership: OwnershipStatus, scope_match: AuthorizationState, output: ScopeAuthorization) -> RiskLevel:
        """Evaluate how likely this target is to be unauthorized."""
        risk_score = 0

        # Ownership risk
        if ownership == OwnershipStatus.UNKNOWN:
            risk_score += 3
        elif ownership == OwnershipStatus.LIKELY:
            risk_score += 1

        # Scope match risk
        if scope_match != AuthorizationState.ALLOW:
            risk_score += 3

        # Uncertainties contribute to risk
        risk_score += len(output.uncertainties)

        # Policy restrictions
        if output.policy_restrictions:
            risk_score += 2

        if risk_score >= 5:
            return RiskLevel.HIGH
        elif risk_score >= 3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 11 — CONTRADICTION DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase11_contradictions(self, domain: str, path: str, output: ScopeAuthorization) -> List[str]:
        """Identify contradictory scope/policy rules."""
        contradictions: List[str] = []

        # Check if domain appears both in-scope and out-of-scope
        in_scope = any(domain_matches(domain, d) for d in self.in_scope_domains) or \
                   any(wildcard_matches(domain, w) for w in self.in_scope_wildcards)
        out_of_scope = any(domain_matches(domain, o) for o in self.out_of_scope_domains)

        if in_scope and out_of_scope:
            contradictions.append(f"Domain {domain} appears in both in-scope and out-of-scope lists")

        # Check for conflicting path rules
        for blocked in self.path_blocks:
            for allowed in self.path_allows:
                if blocked.startswith(allowed) or allowed.startswith(blocked):
                    contradictions.append(f"Conflicting path rules: allow '{allowed}' vs block '{blocked}'")

        # Check policy contradictions
        if output.policy_restrictions and output.scope_status == "IN_SCOPE":
            contradictions.append(f"Policy restrictions exist despite in-scope status — may create authorization conflict")

        return contradictions

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 12 — HALLUCINATION PREVENTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase12_hallucination(self, domain: str, output: ScopeAuthorization) -> List[str]:
        """Before authorizing, verify evidence support for each claim."""
        evidence_checks: List[str] = []

        # "What evidence proves authorization?"
        if output.scope_status == "IN_SCOPE" and not output.matched_scope_rule:
            evidence_checks.append("WARNING: Scope says IN_SCOPE but no matching scope rule found — possible hallucination")
        elif output.matched_scope_rule:
            evidence_checks.append(f"Authorization evidence: matched scope rule '{output.matched_scope_rule}'")

        # "What evidence proves ownership?"
        if output.ownership_status == OwnershipStatus.VERIFIED.value:
            evidence_checks.append(f"Ownership evidence: {domain} is in known owned domains")
        elif output.ownership_status == OwnershipStatus.LIKELY.value:
            evidence_checks.append(f"Ownership note: {domain} matches scope rules but not in owned domains list")
        elif output.ownership_status == OwnershipStatus.UNKNOWN.value:
            evidence_checks.append("Ownership warning: No ownership evidence available")

        # "What assumptions exist?"
        if output.uncertainties:
            evidence_checks.append(f"Assumptions: {len(output.uncertainties)} uncertainty(ies) exist — review required")

        # "Unknown information must never become authorization"
        if output.ownership_status == OwnershipStatus.UNKNOWN.value and output.scope_status != "IN_SCOPE":
            evidence_checks.append("CRITICAL: No ownership and no scope match — cannot authorize")

        return evidence_checks

    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL DECISION DETERMINATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _determine_final_decision(self, output: ScopeAuthorization, scope_match: AuthorizationState) -> AuthorizationState:
        """Determine final ALLOW / REVIEW / BLOCK based on all phases."""
        # Policy restrictions override scope authorization
        if output.policy_restrictions:
            output.reasoning.append(f"Policy restrictions override: {len(output.policy_restrictions)} restriction(s)")
            return AuthorizationState.REVIEW

        # Contradictions → REVIEW (do not guess)
        if output.contradictions:
            output.reasoning.append(f"Contradictions prevent automatic authorization ({len(output.contradictions)} found)")
            return AuthorizationState.REVIEW

        # High risk → REVIEW
        if output.risk_of_misauthorization == RiskLevel.HIGH.value:
            output.reasoning.append("High risk of misauthorization — manual review required")
            return AuthorizationState.REVIEW

        # Uncertainties → REVIEW (default is DENY/BLOCK)
        if output.uncertainties:
            output.reasoning.append(f"Uncertainties prevent automatic authorization ({len(output.uncertainties)} uncertainty(ies))")
            return AuthorizationState.REVIEW

        # Scope match determines authorization
        if scope_match == AuthorizationState.ALLOW:
            output.reasoning.append("Target is explicitly authorized by scope rules")
            return AuthorizationState.ALLOW

        # Default: BLOCK
        output.reasoning.append("No authorization without evidence — default: BLOCK")
        return AuthorizationState.BLOCK

    def _calculate_confidence(self, output: ScopeAuthorization) -> float:
        """Calculate overall authorization confidence 0.0-1.0."""
        base = 0.0

        # Ownership confidence
        if output.ownership_status == OwnershipStatus.VERIFIED.value:
            base += 0.35
        elif output.ownership_status == OwnershipStatus.LIKELY.value:
            base += 0.2
        elif output.ownership_status == OwnershipStatus.UNKNOWN.value:
            base += 0.05

        # Scope confidence
        if output.scope_status == "IN_SCOPE":
            base += 0.25
        elif output.scope_status == "NOT_IN_SCOPE":
            base += 0.0
        else:
            base += 0.1

        # Asset classification confidence — use the already-classified asset type
        # Classifications with concrete types (not OTHER) indicate better confidence
        if output.asset_type and output.asset_type != AssetType.OTHER.value:
            base += 0.1

        # Uncertainty penalty
        uncertainty_penalty = len(output.uncertainties) * 0.05
        base = max(0.0, base - uncertainty_penalty)

        # Contradiction penalty
        contradiction_penalty = len(output.contradictions) * 0.1
        base = max(0.0, base - contradiction_penalty)

        return round(min(base, 1.0), 2)

    def _recommend_next_action(self, output: ScopeAuthorization) -> str:
        """Generate a recommended next action based on the decision."""
        if output.decision == AuthorizationState.ALLOW:
            return "PROCEED — Target is authorized for testing within allowed action categories"

        if output.decision == AuthorizationState.BLOCK:
            reasons = []
            if output.scope_status in ("OUT_OF_SCOPE", "NOT_IN_SCOPE"):
                reasons.append("target not in authorized scope")
            if output.policy_restrictions:
                reasons.append(f"policy restriction: {output.policy_restrictions[0][:60]}")
            return f"DO_NOT_TEST — {'; '.join(reasons) if reasons else 'target is not authorized'}"

        # REVIEW case
        improvements = []
        if output.ownership_status in (OwnershipStatus.UNKNOWN.value, OwnershipStatus.THIRD_PARTY.value):
            improvements.append("confirm asset ownership")
        if output.scope_status != "IN_SCOPE":
            improvements.append("verify target is in authorized scope")
        if output.contradictions:
            improvements.append("resolve scope/policy contradictions")
        if output.uncertainties:
            improvements.append(f"address {len(output.uncertainties)} uncertainty(ies)")

        if improvements:
            return f"MANUAL_REVIEW_REQUIRED — {'; '.join(improvements)}"
        return "MANUAL_REVIEW_REQUIRED — Insufficient information for automatic authorization"

    def _finalize_block(self, output: ScopeAuthorization, reason: str, phases_run: List[str]) -> ScopeAuthorization:
        """Short-circuit and return a BLOCK decision with proportional confidence."""
        output.decision = AuthorizationState.BLOCK
        output.authorized = False
        output.reasoning.append(reason)
        output.recommended_next_action = "DO_NOT_TEST"

        if "out of scope" in reason.lower() or "excluded" in reason.lower():
            output.authorization_confidence = 0.95
        elif "third-party" in reason.lower():
            output.authorization_confidence = 0.98
        elif "path" in reason.lower() and "blocked" in reason.lower():
            output.authorization_confidence = 0.92
        else:
            output.authorization_confidence = 0.85

        return output
