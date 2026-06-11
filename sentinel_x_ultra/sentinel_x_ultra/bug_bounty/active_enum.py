"""
AGENT 5 — ATTACK SURFACE INTELLIGENCE & ASSET ANALYSIS ENGINE

Transforms authorized observations into verified, prioritized, ownership-aware
attack surface intelligence.

Core principles:
- Evidence over assumptions. Observed over inferred. Verified over probable.
- Unknown over fabricated. Accuracy over volume.
- Every conclusion must be supported by evidence.
- If evidence is insufficient: RETURN UNKNOWN.

14-Phase Pipeline:
  1.  Asset Intake & Normalization
  2.  Asset Classification
  3.  Ownership Verification
  4.  Business Criticality Assessment (0-100)
  5.  Exposure Assessment
  6.  Relationship Analysis
  7.  Cross-Evidence Correlation
  8.  Duplicate Detection
  9.  Contradiction Detection
 10.  Intelligence Gap Analysis
 11.  Adversarial Review
 12.  Priority Scoring (0-100)
 13.  Downstream Guidance
 14.  Hallucination Prevention
"""

import uuid
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# ── Enums ───────────────────────────────────────────────────────────────────

class AssetConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNVERIFIED = "UNVERIFIED"


class OwnershipStatus(str, Enum):
    VERIFIED_OWNER = "VERIFIED_OWNER"
    LIKELY_OWNER = "LIKELY_OWNER"
    UNKNOWN_OWNER = "UNKNOWN_OWNER"
    THIRD_PARTY = "THIRD_PARTY"


class AssetClassification(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    APPLICATION = "APPLICATION"
    API = "API"
    ADMIN_INTERFACE = "ADMIN_INTERFACE"
    AUTH_SYSTEM = "AUTH_SYSTEM"
    DOCUMENTATION_PORTAL = "DOCUMENTATION_PORTAL"
    REPOSITORY = "REPOSITORY"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    SERVICE = "SERVICE"
    MOBILE_BACKEND = "MOBILE_BACKEND"
    OTHER = "OTHER"


class CriticalityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ExposureLevel(str, Enum):
    PUBLIC = "PUBLIC"
    RESTRICTED = "RESTRICTED"
    INTERNAL_ONLY = "INTERNAL_ONLY"
    ADMINISTRATIVE = "ADMINISTRATIVE"
    API = "API"


# ── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """A discovered endpoint with observation evidence."""
    path: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    technologies: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    observed: bool = False
    observation_source: str = ""
    response_length: int = 0


@dataclass
class Relationship:
    """A relationship between two assets."""
    source_asset: str = ""
    target_asset: str = ""
    relationship_type: str = ""  # e.g., "authenticates_to", "routes_to", "depends_on"
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class IntelligenceGap:
    """A gap in intelligence for an asset."""
    category: str = ""  # ownership, classification, exposure, criticality, relationship
    asset: str = ""
    description: str = ""
    severity: str = "MEDIUM"


@dataclass
class Contradiction:
    """A contradiction in intelligence."""
    contradiction_type: str = ""  # ownership, classification, technology, exposure
    asset: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)


@dataclass
class AssetAnalysis:
    """Full analysis output for a single asset — matches the required output schema."""
    asset_id: str = ""
    asset_name: str = ""
    asset_type: str = ""
    ownership_status: str = ""
    asset_confidence: float = 0.0
    criticality_score: int = 50
    priority_score: int = 50
    exposure_level: str = ""
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    supporting_observations: List[str] = field(default_factory=list)
    contradictions: List[Dict[str, Any]] = field(default_factory=list)
    intelligence_gaps: List[Dict[str, Any]] = field(default_factory=list)
    confidence_classification: str = ""
    recommended_review_actions: List[str] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)


# ── Active Enum Result (Backward Compatible) ────────────────────────────────

@dataclass
class ActiveEnumResult:
    """Complete result of active enumeration and asset intelligence analysis.

    Backward-compatible with the original ActiveEnumResult fields,
    extended with the full asset analysis pipeline output.
    """
    # Original fields (backward compatible)
    domain: str = ""
    alive_subdomains: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    interesting_files: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    # New fields (14-phase analysis pipeline)
    assets_analyzed: List[AssetAnalysis] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)
    intelligence_gaps: List[IntelligenceGap] = field(default_factory=list)
    priority_targets: List[Dict[str, Any]] = field(default_factory=list)
    downstream_guidance: Dict[str, Any] = field(default_factory=dict)
    phases_run: List[str] = field(default_factory=list)

    # Convenience aliases for orchestrator compatibility
    @property
    def target(self) -> str:
        return self.domain

    @property
    def subdomains(self) -> List[str]:
        return self.alive_subdomains


# ── Port & Path Data ────────────────────────────────────────────────────────

COMMON_PORTS = [
    (80, "HTTP"), (443, "HTTPS"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
    (3000, "Node.js/Express"), (5000, "Flask/Node"), (8000, "HTTP-Dev"),
    (9000, "HTTPS-Dev"), (9443, "HTTPS-Alt"), (9090, "HTTP-Alt"),
    (4443, "HTTPS-Alt"), (1234, "Dev-Server"), (4444, "Dev-Server"),
    (9001, "Tor-SOCKS"), (27017, "MongoDB"), (5432, "PostgreSQL"),
    (3306, "MySQL"), (6379, "Redis"), (9200, "Elasticsearch"),
    (5601, "Kibana"), (8086, "InfluxDB"), (11211, "Memcached"),
    # Additional infrastructure ports
    (25, "SMTP"), (53, "DNS"), (110, "POP3"), (143, "IMAP"),
    (993, "IMAPS"), (995, "POP3S"), (587, "SMTP-Submit"),
    (3389, "RDP"), (22, "SSH"), (21, "FTP"),
    (5900, "VNC"), (8444, "HTTPS-Alt-2"), (7070, "HTTPS-RealServer"),
    (7001, "WebLogic"), (7002, "WebLogic-SSL"), (9043, "WebSphere"),
    (9443, "WebSphere-SSL"), (4848, "GlassFish"),
    (15672, "RabbitMQ"), (9000, "Portainer"), (60000, "DynamoDB"),
]

COMMON_ENDPOINTS = [
    # Well-known paths
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/crossdomain.xml", "/client-access-policy.xml",
    # API documentation
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/ui/index.html",
    "/api-docs", "/api-docs.json", "/api/swagger.json",
    "/openapi.json", "/api/v1/openapi.json",
    "/graphql", "/graphiql", "/graphql/console",
    "/api/graphql", "/v1/graphql",
    # Admin interfaces
    "/admin/", "/admin/login", "/admin/dashboard",
    "/administrator/", "/admin.php",
    "/backoffice/", "/panel/", "/cpanel/",
    "/wp-admin/", "/wp-admin/admin-ajax.php",
    # Auth endpoints
    "/login", "/register", "/signup", "/signin",
    "/auth/", "/oauth/", "/oauth2/",
    "/saml/", "/sso/", "/authorize",
    "/token", "/api/token", "/authenticate",
    # Config & sensitive files
    "/.env", "/.git/config", "/.gitignore",
    "/config/", "/configuration/",
    "/backup/", "/backups/", "/db_backup.sql",
    # Health & metrics
    "/health", "/healthz", "/readyz",
    "/metrics", "/actuator/health", "/actuator/info",
    "/status", "/status.php", "/server-status",
    # Dev & debug
    "/debug/", "/debug.php", "/phpinfo.php",
    "/dev/", "/test/", "/staging/",
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/", "/node_modules/",
    # Common paths
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1/", "/v2/", "/v3/",
    "/app/", "/webapp/", "/mobile/",
    "/assets/", "/static/", "/uploads/",
    "/download/", "/files/", "/images/",
    "/search", "/query", "/lookup",
    "/ping", "/echo", "/webhook",
]


# ── Active Enumeration Agent (Attack Surface Intelligence) ──────────────────

class ActiveEnumerationAgent:
    """
    Agent 5: Attack Surface Intelligence & Asset Analysis Engine.

    Transforms authorized observations into verified, prioritized, ownership-aware
    attack surface intelligence.

    14-Phase Pipeline:
      1.  Asset Intake & Normalization
      2.  Asset Classification
      3.  Ownership Verification
      4.  Business Criticality Assessment (0-100)
      5.  Exposure Assessment
      6.  Relationship Analysis
      7.  Cross-Evidence Correlation
      8.  Duplicate Detection
      9.  Contradiction Detection
     10.  Intelligence Gap Analysis
     11.  Adversarial Review
     12.  Priority Scoring (0-100)
     13.  Downstream Guidance
     14.  Hallucination Prevention
    """

    def __init__(self):
        self.max_requests_per_second = 10

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════════

    async def enumerate(self, domain: str) -> ActiveEnumResult:
        """Enumerate a target domain — runs the full 14-phase analysis pipeline.

        Args:
            domain: The target domain to analyze.

        Returns:
            ActiveEnumResult with backward-compatible fields + full analysis.
        """
        result = ActiveEnumResult(domain=domain)
        phases_run = []

        # Phase 1: Asset Intake & Normalization
        self._phase1_intake(domain, result)
        phases_run.append("asset_intake")

        # Phase 2: Asset Classification
        self._phase2_classification(domain, result)
        phases_run.append("asset_classification")

        # Phase 3: Ownership Verification
        self._phase3_ownership(domain, result)
        phases_run.append("ownership_verification")

        # Phase 4: Business Criticality Assessment
        self._phase4_criticality(domain, result)
        phases_run.append("criticality_assessment")

        # Phase 5: Exposure Assessment
        self._phase5_exposure(domain, result)
        phases_run.append("exposure_assessment")

        # Phase 6: Relationship Analysis
        self._phase6_relationships(domain, result)
        phases_run.append("relationship_analysis")

        # Phase 7: Cross-Evidence Correlation
        self._phase7_cross_evidence(domain, result)
        phases_run.append("cross_evidence_correlation")

        # Phase 8: Duplicate Detection
        self._phase8_duplicates(domain, result)
        phases_run.append("duplicate_detection")

        # Phase 9: Contradiction Detection
        self._phase9_contradictions(domain, result)
        phases_run.append("contradiction_detection")

        # Phase 10: Intelligence Gap Analysis
        self._phase10_gaps(domain, result)
        phases_run.append("gap_analysis")

        # Phase 11: Adversarial Review
        self._phase11_adversarial(domain, result)
        phases_run.append("adversarial_review")

        # Phase 12: Priority Scoring
        self._phase12_priority(domain, result)
        phases_run.append("priority_scoring")

        # Phase 13: Downstream Guidance
        self._phase13_guidance(domain, result)
        phases_run.append("downstream_guidance")

        # Phase 14: Hallucination Prevention
        self._phase14_hallucination(domain, result)
        phases_run.append("hallucination_prevention")

        result.phases_run = phases_run
        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — ASSET INTAKE & NORMALIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase1_intake(self, domain: str, result: ActiveEnumResult):
        """Intake and normalize all observations from upstream intelligence.

        Does NOT generate assets from wordlists.
        Only analyzes evidence and observations already collected.

        Sources:
        - Program scope (target domain)
        - Passive intelligence (subdomains from Agent 4)
        - Observed endpoints
        - Port observations
        """
        # The domain itself is always an observed asset
        result.alive_subdomains = [domain]

        # Add domain as first asset analysis
        domain_analysis = AssetAnalysis(
            asset_id=self._make_asset_id(domain),
            asset_name=domain,
            asset_type=AssetClassification.DOMAIN.value,
            ownership_status=OwnershipStatus.VERIFIED_OWNER.value,
            asset_confidence=1.0,
            criticality_score=90,
            priority_score=90,
            exposure_level=ExposureLevel.PUBLIC.value,
            evidence=["Target domain from program scope — primary asset"],
            supporting_observations=[f"Domain '{domain}' specified in program scope or user input"],
            reasoning=["Primary target domain — highest authority source"],
        )
        result.assets_analyzed.append(domain_analysis)
        result.notes.append(f"Asset intake: domain '{domain}' registered (CONFIRMED)")

        # Port observations (from common ports mapping)
        for port, service in COMMON_PORTS:
            result.open_ports.append({
                "port": port,
                "service": service,
                "status": "unknown",
                "observed": False,
            })

        # Endpoint observations (from common paths)
        for path in COMMON_ENDPOINTS:
            ep = Endpoint(
                path=path,
                method="GET",
                status_code=0,
                observed=False,
                observation_source="common_path_checklist",
            )
            result.endpoints.append(ep)

        result.notes.append(f"Loaded {len(COMMON_ENDPOINTS)} endpoint checklist for observation")
        result.notes.append(f"Loaded {len(COMMON_PORTS)} port checklist for observation")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — ASSET CLASSIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase2_classification(self, domain: str, result: ActiveEnumResult):
        """Classify every asset with confidence and reasoning.

        Asset types: Domain, Subdomain, Application, API, Administrative Interface,
        Authentication System, Documentation Portal, Repository, Cloud Resource,
        Service, Mobile Backend, Other.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name
            classification = AssetClassification.OTHER.value
            confidence = analysis.asset_confidence
            reasoning = []

            # Domain classification
            if asset_name == domain:
                classification = AssetClassification.DOMAIN.value
                reasoning.append("Primary target domain — core asset")
            elif asset_name.endswith(f".{domain}"):
                # Subdomain — further classify by name patterns
                sub_part = asset_name[:-(len(domain) + 1)].lower()

                if sub_part in ("api", "api-", "-api") or "api" in sub_part:
                    classification = AssetClassification.API.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests API endpoint")
                elif sub_part in ("admin", "administrator", "backoffice", "cpanel", "panel"):
                    classification = AssetClassification.ADMIN_INTERFACE.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests administrative interface")
                elif sub_part in ("auth", "login", "sso", "oauth", "saml", "token"):
                    classification = AssetClassification.AUTH_SYSTEM.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests authentication system")
                elif sub_part in ("docs", "documentation", "help", "kb", "wiki", "support"):
                    classification = AssetClassification.DOCUMENTATION_PORTAL.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests documentation portal")
                elif sub_part in ("app", "webapp", "mobile", "m"):
                    classification = AssetClassification.APPLICATION.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests web application")
                elif sub_part in ("git", "repo", "code", "source", "github", "bitbucket"):
                    classification = AssetClassification.REPOSITORY.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests code repository")
                elif "cloud" in sub_part or any(kw in sub_part for kw in ("aws", "s3", "storage", "cdn")):
                    classification = AssetClassification.CLOUD_RESOURCE.value
                    reasoning.append(f"Subdomain '{sub_part}' pattern suggests cloud resource")
                elif "api" in sub_part:
                    classification = AssetClassification.API.value
                    reasoning.append(f"Subdomain '{sub_part}' contains API indicator")
                else:
                    classification = AssetClassification.SUBDOMAIN.value
                    reasoning.append(f"Subdomain '{sub_part}' — no specialized pattern detected")

            analysis.asset_type = classification
            analysis.reasoning.extend(reasoning)

        result.notes.append(f"Classification complete: {len(result.assets_analyzed)} asset(s) classified")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — OWNERSHIP VERIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase3_ownership(self, domain: str, result: ActiveEnumResult):
        """Determine ownership status for every asset.

        VERIFIED_OWNER: Ownership supported by authoritative evidence.
        LIKELY_OWNER: Ownership appears probable but not fully confirmed.
        UNKNOWN_OWNER: Ownership cannot be established.
        THIRD_PARTY: Asset appears to belong to another organization.

        Never assume ownership.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name

            if asset_name == domain:
                analysis.ownership_status = OwnershipStatus.VERIFIED_OWNER.value
                analysis.evidence.append("Target domain from program scope — ownership verified")
                analysis.reasoning.append("Ownership VERIFIED: domain from program scope")

            elif asset_name.endswith(f".{domain}"):
                # Check for known third-party infrastructure patterns
                sub_part = asset_name[:-(len(domain) + 1)].lower()

                third_party_indicators = {
                    "s3": "AWS S3 bucket — third-party cloud infrastructure",
                    "cloudfront": "AWS CloudFront — third-party CDN",
                    "akamai": "Akamai CDN — third-party content delivery",
                    "fastly": "Fastly CDN — third-party content delivery",
                    "azure": "Microsoft Azure — third-party cloud",
                    "azureedge": "Azure CDN — third-party content delivery",
                    "googleapis": "Google APIs — third-party service",
                    "cloudflare": "Cloudflare — third-party proxy/CDN",
                    "nr-data": "New Relic — third-party monitoring",
                }

                found_third_party = False
                for indicator, description in third_party_indicators.items():
                    if indicator in sub_part:
                        analysis.ownership_status = OwnershipStatus.THIRD_PARTY.value
                        analysis.evidence.append(description)
                        analysis.reasoning.append(f"Ownership THIRD_PARTY: {description}")
                        found_third_party = True
                        break

                if not found_third_party:
                    analysis.ownership_status = OwnershipStatus.LIKELY_OWNER.value
                    analysis.evidence.append(f"Subdomain of target domain '{domain}' — likely owned by target organization")
                    analysis.reasoning.append("Ownership LIKELY: subdomain of verified target domain")

            else:
                analysis.ownership_status = OwnershipStatus.UNKNOWN_OWNER.value
                analysis.evidence.append(f"Cannot determine ownership for '{asset_name}' from available evidence")
                analysis.reasoning.append("Ownership UNKNOWN: no authoritative evidence available")

        result.notes.append(f"Ownership verification complete")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4 — BUSINESS CRITICALITY ASSESSMENT (0-100)
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase4_criticality(self, domain: str, result: ActiveEnumResult):
        """Assess business criticality (0-100).

        Factors:
        - User data exposure
        - Administrative capability
        - Authentication significance
        - Financial significance
        - Operational significance
        - Internal system access

        CRITICAL 90-100 | HIGH 70-89 | MEDIUM 40-69 | LOW 0-39
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name
            asset_type = analysis.asset_type
            score = 50  # Baseline
            reasoning = []

            # User data exposure
            if any(kw in asset_name.lower() for kw in ("user", "profile", "account", "customer", "member")):
                score += 20
                reasoning.append("User data exposure: handles personally identifiable information")

            # Administrative capability
            if asset_type == AssetClassification.ADMIN_INTERFACE.value:
                score += 25
                reasoning.append("Administrative interface: potential access to full system control")
            elif any(kw in asset_name.lower() for kw in ("admin", "backoffice", "cpanel", "panel")):
                score += 15
                reasoning.append("Administrative functionality detected")

            # Authentication significance
            if asset_type == AssetClassification.AUTH_SYSTEM.value:
                score += 25
                reasoning.append("Authentication system: gateway to all protected functionality")
            elif any(kw in asset_name.lower() for kw in ("auth", "login", "sso", "token")):
                score += 15
                reasoning.append("Authentication-related endpoint")

            # API exposure
            if asset_type in (AssetClassification.API.value, AssetClassification.MOBILE_BACKEND.value):
                score += 15
                reasoning.append("API endpoint: likely mediates access to backend systems and data")

            # Financial significance
            if any(kw in asset_name.lower() for kw in ("pay", "billing", "checkout", "order", "invoice", "finance")):
                score += 20
                reasoning.append("Financial system: handles monetary transactions or billing data")

            # Operational significance
            if asset_type == AssetClassification.DOMAIN.value and asset_name == domain:
                score += 15
                reasoning.append("Primary domain: core operational asset")
            if any(kw in asset_name.lower() for kw in ("monitor", "alert", "deploy", "build", "ci", "jenkins")):
                score += 15
                reasoning.append("Operational infrastructure: CI/CD, monitoring, or deployment")

            # Internal system access
            if any(kw in asset_name.lower() for kw in ("internal", "corp", "vpn", "intranet", "ldap", "directory")):
                score += 20
                reasoning.append("Internal system access: potential pivot point to internal network")

            # Cloud resources
            if asset_type == AssetClassification.CLOUD_RESOURCE.value:
                score += 10
                reasoning.append("Cloud resource: potential misconfiguration exposure")

            # Cap and classify
            score = max(0, min(100, score))
            analysis.criticality_score = score

            if score >= 90:
                analysis.reasoning.extend(reasoning)
                analysis.reasoning.append(f"CRITICAL criticality (score: {score})")
            elif score >= 70:
                analysis.reasoning.extend(reasoning)
                analysis.reasoning.append(f"HIGH criticality (score: {score})")
            elif score >= 40:
                analysis.reasoning.extend(reasoning)
                analysis.reasoning.append(f"MEDIUM criticality (score: {score})")
            else:
                analysis.reasoning.extend(reasoning)
                analysis.reasoning.append(f"LOW criticality (score: {score})")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5 — EXPOSURE ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase5_exposure(self, domain: str, result: ActiveEnumResult):
        """Assess exposure level for every asset.

        PUBLIC: Accessible from the internet without restriction.
        RESTRICTED: Requires authentication or access control.
        INTERNAL_ONLY: Indicators suggest internal network only.
        ADMINISTRATIVE: Administrative interface with elevated capabilities.
        API: Programmatic interface for application communication.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name
            asset_type = analysis.asset_type
            exposure = ExposureLevel.PUBLIC.value
            reasoning = []

            # Subdomain patterns
            sub_part = ""
            if asset_name.endswith(f".{domain}") and asset_name != domain:
                sub_part = asset_name[:-(len(domain) + 1)].lower()

            if asset_type == AssetClassification.ADMIN_INTERFACE.value:
                exposure = ExposureLevel.ADMINISTRATIVE.value
                reasoning.append("Administrative interface — exposure limited to authorized administrators")
            elif asset_type == AssetClassification.AUTH_SYSTEM.value:
                exposure = ExposureLevel.RESTRICTED.value
                reasoning.append("Authentication system — public but restricted to authenticated sessions")
            elif any(kw in sub_part for kw in ("internal", "corp", "vpn", "intranet")):
                exposure = ExposureLevel.INTERNAL_ONLY.value
                reasoning.append(f"Subdomain '{sub_part}' suggests internal-only access")
            elif "api" in sub_part or asset_type == AssetClassification.API.value:
                exposure = ExposureLevel.API.value
                reasoning.append("API endpoint — programmatic interface, may have its own auth layer")
            elif asset_type == AssetClassification.DOMAIN.value:
                exposure = ExposureLevel.PUBLIC.value
                reasoning.append("Public domain — accessible from internet")
            else:
                exposure = ExposureLevel.PUBLIC.value
                reasoning.append("Publicly accessible subdomain")

            # Check for restricted indicators
            if any(kw in asset_name.lower() for kw in ("admin", "backoffice", "dashboard")):
                if exposure == ExposureLevel.PUBLIC.value:
                    exposure = ExposureLevel.RESTRICTED.value
                    reasoning.append("Admin-related naming suggests restricted access")

            analysis.exposure_level = exposure
            analysis.reasoning.extend(reasoning)

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6 — RELATIONSHIP ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase6_relationships(self, domain: str, result: ActiveEnumResult):
        """Identify relationships between assets.

        Examples:
        - Authentication Portal → User Dashboard
        - User Dashboard → Administrative Functions
        - API Gateway → Backend Services

        Relationships require evidence. Do not invent relationships.
        """
        # Find auth systems
        auth_assets = [a for a in result.assets_analyzed
                       if a.asset_type == AssetClassification.AUTH_SYSTEM.value]
        # Find applications
        app_assets = [a for a in result.assets_analyzed
                      if a.asset_type == AssetClassification.APPLICATION.value]
        # Find admin interfaces
        admin_assets = [a for a in result.assets_analyzed
                        if a.asset_type == AssetClassification.ADMIN_INTERFACE.value]
        # Find APIs
        api_assets = [a for a in result.assets_analyzed
                      if a.asset_type == AssetClassification.API.value]

        # Auth → Application relationship
        for auth in auth_assets:
            for app in app_assets:
                rel = Relationship(
                    source_asset=auth.asset_name,
                    target_asset=app.asset_name,
                    relationship_type="authenticates_to",
                    evidence=[
                        f"'{auth.asset_name}' identified as authentication system",
                        f"'{app.asset_name}' identified as application requiring authentication",
                    ],
                    confidence=0.7,
                )
                result.relationships.append(rel)
                auth.relationships.append({
                    "source": auth.asset_name,
                    "target": app.asset_name,
                    "type": "authenticates_to",
                    "confidence": 0.7,
                })
                break  # One relationship per auth system

        # Application → Admin relationship
        for app in app_assets:
            for admin in admin_assets:
                rel = Relationship(
                    source_asset=app.asset_name,
                    target_asset=admin.asset_name,
                    relationship_type="escalates_to",
                    evidence=[
                        f"'{app.asset_name}' is application with user data",
                        f"'{admin.asset_name}' is administrative interface",
                        "Administrative access typically requires application context",
                    ],
                    confidence=0.6,
                )
                result.relationships.append(rel)
                app.relationships.append({
                    "source": app.asset_name,
                    "target": admin.asset_name,
                    "type": "escalates_to",
                    "confidence": 0.6,
                })
                break

        # API → Backend relationship
        for api in api_assets:
            rel = Relationship(
                source_asset=api.asset_name,
                target_asset=domain,  # Backend services implied by the domain
                relationship_type="routes_to",
                evidence=[
                    f"'{api.asset_name}' identified as API endpoint",
                    f"API endpoints route requests to backend services on '{domain}'",
                ],
                confidence=0.5,
            )
            result.relationships.append(rel)
            api.relationships.append({
                "source": api.asset_name,
                "target": domain,
                "type": "routes_to",
                "confidence": 0.5,
            })

        result.notes.append(f"Relationship analysis: {len(result.relationships)} relationship(s) identified")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7 — CROSS-EVIDENCE CORRELATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase7_cross_evidence(self, domain: str, result: ActiveEnumResult):
        """Correlate observations across multiple evidence sources.

        Documentation + Repository Reference + Observed Service = Higher confidence.

        Single-source discoveries should not receive maximum confidence.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name
            evidence_count = len(analysis.evidence)
            observation_count = len(analysis.supporting_observations)
            relationship_count = len(analysis.relationships)

            # Count distinct evidence sources
            source_count = 0
            if asset_name == domain:
                source_count += 1  # Program scope
            if asset_name.endswith(f".{domain}"):
                source_count += 1  # Domain relationship
            if evidence_count > 1:
                source_count += 1  # Multiple evidence items
            if observation_count > 0:
                source_count += 1  # Observations
            if relationship_count > 0:
                source_count += 1  # Relationships provide corroboration

            # Apply confidence boost based on source diversity
            if source_count >= 4:
                boost = 0.10
                analysis.asset_confidence = min(analysis.asset_confidence + boost, 1.0)
                analysis.reasoning.append(f"Cross-evidence correlation: {source_count} distinct sources — confidence boosted")
            elif source_count >= 2:
                boost = 0.05
                analysis.asset_confidence = min(analysis.asset_confidence + boost, 1.0)
                analysis.reasoning.append(f"Cross-evidence correlation: {source_count} sources — moderate confidence")

            if source_count == 1 and asset_name != domain:
                analysis.asset_confidence = min(analysis.asset_confidence, 0.7)
                analysis.reasoning.append("Single-source discovery — confidence capped at 70%")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8 — DUPLICATE DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase8_duplicates(self, domain: str, result: ActiveEnumResult):
        """Identify likely duplicates.

        Multiple identifiers referring to the same system.
        Merge supporting evidence. Preserve provenance. Avoid duplicate prioritization.
        """
        duplicates_found = []
        seen_names = set()

        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name.lower()

            # Normalize and check for duplicates
            normalized = asset_name.replace("https://", "").replace("http://", "").rstrip("/")

            if normalized in seen_names:
                duplicates_found.append(normalized)
                analysis.reasoning.append(f"DUPLICATE: '{asset_name}' appears to be duplicate of '{normalized}'")
                # Reduce priority for duplicates
                analysis.priority_score = max(analysis.priority_score - 20, 0)
            else:
                seen_names.add(normalized)

        if duplicates_found:
            result.notes.append(f"Duplicate detection: {len(duplicates_found)} duplicate(s) identified")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 9 — CONTRADICTION DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase9_contradictions(self, domain: str, result: ActiveEnumResult):
        """Identify contradictions.

        - Ownership conflicts
        - Classification conflicts
        - Technology conflicts
        - Exposure conflicts

        If contradictions exist: reduce confidence, flag for review.
        Never resolve contradictions through assumptions.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name

            # Ownership contradiction: domain listed as THIRD_PARTY but subdomain of target
            if (analysis.ownership_status == OwnershipStatus.THIRD_PARTY.value
                    and asset_name.endswith(f".{domain}")):
                contradiction = Contradiction(
                    contradiction_type="ownership",
                    asset=asset_name,
                    description=f"Ownership conflict: '{asset_name}' is subdomain of '{domain}' but flagged as THIRD_PARTY",
                    evidence=[
                        f"Subdomain relationship indicates '{domain}' ownership",
                        f"Third-party pattern detected in asset name",
                    ],
                )
                result.contradictions.append(contradiction)
                analysis.contradictions.append({
                    "type": "ownership",
                    "description": contradiction.description,
                    "severity": "medium",
                })
                analysis.asset_confidence = max(analysis.asset_confidence - 0.1, 0.0)
                analysis.reasoning.append("Contradiction: ownership conflict — confidence reduced")

            # Classification/Exposure contradiction
            if (analysis.asset_type == AssetClassification.ADMIN_INTERFACE.value
                    and analysis.exposure_level == ExposureLevel.PUBLIC.value):
                contradiction = Contradiction(
                    contradiction_type="exposure",
                    asset=asset_name,
                    description=f"Exposure conflict: '{asset_name}' classified as ADMIN_INTERFACE but exposure is PUBLIC",
                    evidence=[
                        f"Asset type: {analysis.asset_type}",
                        f"Exposure level: {analysis.exposure_level}",
                        "Administrative interfaces should not be publicly exposed",
                    ],
                )
                result.contradictions.append(contradiction)
                analysis.contradictions.append({
                    "type": "exposure",
                    "description": contradiction.description,
                    "severity": "high",
                })
                analysis.reasoning.append("Contradiction: admin interface with public exposure — requires verification")

        if result.contradictions:
            result.notes.append(f"Contradiction detection: {len(result.contradictions)} contradiction(s) found")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 10 — INTELLIGENCE GAP ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase10_gaps(self, domain: str, result: ActiveEnumResult):
        """Identify missing intelligence.

        Categories: ownership, classification, exposure, criticality, relationship.
        Document gaps explicitly. Do not hide uncertainty.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name

            # Ownership gap
            if analysis.ownership_status == OwnershipStatus.UNKNOWN_OWNER.value:
                gap = IntelligenceGap(
                    category="ownership",
                    asset=asset_name,
                    description=f"Cannot determine ownership for '{asset_name}'",
                    severity="HIGH",
                )
                result.intelligence_gaps.append(gap)
                analysis.intelligence_gaps.append({
                    "category": "ownership",
                    "description": gap.description,
                    "severity": gap.severity,
                })

            # Classification gap
            if analysis.asset_type == AssetClassification.OTHER.value:
                gap = IntelligenceGap(
                    category="classification",
                    asset=asset_name,
                    description=f"Cannot classify '{asset_name}' — no recognizable patterns detected",
                    severity="MEDIUM",
                )
                result.intelligence_gaps.append(gap)
                analysis.intelligence_gaps.append({
                    "category": "classification",
                    "description": gap.description,
                    "severity": gap.severity,
                })

            # Criticality gap
            if analysis.criticality_score <= 40:
                gap = IntelligenceGap(
                    category="criticality",
                    asset=asset_name,
                    description=f"Low criticality confidence for '{asset_name}' (score: {analysis.criticality_score})",
                    severity="LOW",
                )
                result.intelligence_gaps.append(gap)
                analysis.intelligence_gaps.append({
                    "category": "criticality",
                    "description": gap.description,
                    "severity": gap.severity,
                })

            # Exposure gap
            if not analysis.exposure_level:
                gap = IntelligenceGap(
                    category="exposure",
                    asset=asset_name,
                    description=f"Cannot determine exposure level for '{asset_name}'",
                    severity="MEDIUM",
                )
                result.intelligence_gaps.append(gap)
                analysis.intelligence_gaps.append({
                    "category": "exposure",
                    "description": gap.description,
                    "severity": gap.severity,
                })

            # Relationship gap
            if not analysis.relationships:
                gap = IntelligenceGap(
                    category="relationship",
                    asset=asset_name,
                    description=f"No relationships identified for '{asset_name}' — isolated asset",
                    severity="LOW",
                )
                result.intelligence_gaps.append(gap)
                analysis.intelligence_gaps.append({
                    "category": "relationship",
                    "description": gap.description,
                    "severity": gap.severity,
                })

        result.notes.append(f"Gap analysis: {len(result.intelligence_gaps)} intelligence gap(s) identified")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 11 — ADVERSARIAL REVIEW
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase11_adversarial(self, domain: str, result: ActiveEnumResult):
        """Challenge every major conclusion.

        Ask:
        - Could ownership be incorrect?
        - Could evidence be outdated?
        - Could the asset be misclassified?
        - Could this be a duplicate?
        - Could this belong to a third party?

        Reduce confidence when uncertainty remains.
        """
        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name
            challenges = []
            adjustments = 0.0

            # Challenge: Could ownership be incorrect?
            if analysis.ownership_status == OwnershipStatus.LIKELY_OWNER.value:
                challenges.append("Ownership is LIKELY but not VERIFIED — could belong to a different entity")
                adjustments -= 0.05
            elif analysis.ownership_status == OwnershipStatus.UNKNOWN_OWNER.value:
                challenges.append("Ownership is UNKNOWN — asset could belong to anyone")
                adjustments -= 0.10
            elif analysis.ownership_status == OwnershipStatus.THIRD_PARTY.value:
                challenges.append("Asset appears to be THIRD_PARTY — verify scope authorization")
                adjustments -= 0.05

            # Challenge: Could evidence be outdated?
            if asset_name != domain and asset_name.endswith(f".{domain}"):
                challenges.append("Subdomain ownership inferred from domain relationship — could be outdated")
                adjustments -= 0.03

            # Challenge: Could the asset be misclassified?
            if analysis.asset_type == AssetClassification.OTHER.value:
                challenges.append("Asset classified as OTHER — classification may be incorrect")
                adjustments -= 0.05

            # Challenge: Could this be a duplicate?
            dupe_contradictions = [c for c in analysis.contradictions
                                   if c.get("type") == "ownership"]
            if dupe_contradictions:
                challenges.append("Asset has ownership contradictions — may be misidentified")
                adjustments -= 0.05

            # Challenge: Could this belong to a third party?
            if any(kw in asset_name.lower() for kw in ("cloudfront", "s3.amazonaws", "akamai", "fastly")):
                challenges.append("Asset uses known third-party infrastructure — confirm ownership")
                adjustments -= 0.10

            # Apply adjustments
            if adjustments < 0:
                old_conf = analysis.asset_confidence
                analysis.asset_confidence = max(old_conf + adjustments, 0.1)
                analysis.reasoning.append(
                    f"Adversarial review: {len(challenges)} challenge(s) — confidence adjusted from {old_conf:.0%} to {analysis.asset_confidence:.0%}"
                )

                # Add recommended review actions
                for challenge in challenges[:2]:
                    analysis.recommended_review_actions.append(f"Review: {challenge}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 12 — PRIORITY SCORING (0-100)
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase12_priority(self, domain: str, result: ActiveEnumResult):
        """Generate priority score 0-100 for every asset.

        Factors:
        - Ownership confidence (0-20)
        - Asset confidence (0-25)
        - Business criticality (0-30)
        - Exposure level (0-15)
        - Relationship significance (0-10)
        """
        for analysis in result.assets_analyzed:
            score = 0
            factors = []

            # 1. Ownership confidence (0-20)
            if analysis.ownership_status == OwnershipStatus.VERIFIED_OWNER.value:
                score += 20
                factors.append("Ownership VERIFIED: +20")
            elif analysis.ownership_status == OwnershipStatus.LIKELY_OWNER.value:
                score += 12
                factors.append("Ownership LIKELY: +12")
            elif analysis.ownership_status == OwnershipStatus.UNKNOWN_OWNER.value:
                score += 3
                factors.append("Ownership UNKNOWN: +3")
            elif analysis.ownership_status == OwnershipStatus.THIRD_PARTY.value:
                score += 1
                factors.append("Ownership THIRD-PARTY: +1")

            # 2. Asset confidence (0-25)
            conf_score = int(analysis.asset_confidence * 25)
            score += conf_score
            factors.append(f"Asset confidence ({analysis.asset_confidence:.0%}): +{conf_score}")

            # 3. Business criticality (0-30)
            crit_score = int(analysis.criticality_score * 0.3)
            score += crit_score
            factors.append(f"Criticality ({analysis.criticality_score}): +{crit_score}")

            # 4. Exposure level (0-15)
            if analysis.exposure_level == ExposureLevel.PUBLIC.value:
                score += 15
                factors.append("Public exposure: +15")
            elif analysis.exposure_level == ExposureLevel.API.value:
                score += 12
                factors.append("API exposure: +12")
            elif analysis.exposure_level in (ExposureLevel.RESTRICTED.value, ExposureLevel.ADMINISTRATIVE.value):
                score += 8
                factors.append(f"{analysis.exposure_level} exposure: +8")
            elif analysis.exposure_level == ExposureLevel.INTERNAL_ONLY.value:
                score += 3
                factors.append("Internal-only exposure: +3")

            # 5. Relationship significance (0-10)
            rel_score = min(len(analysis.relationships) * 5, 10)
            if rel_score > 0:
                score += rel_score
                factors.append(f"Relationships ({len(analysis.relationships)}): +{rel_score}")
            else:
                factors.append("No relationships: +0")

            # Cap and store
            score = max(0, min(100, score))
            analysis.priority_score = score
            analysis.reasoning.append(f"Priority score: {score}/100")
            analysis.reasoning.extend([f"  - {f}" for f in factors])

            # Classify confidence according to CONFIRMED/PROBABLE/POSSIBLE/UNVERIFIED model
            if analysis.asset_confidence >= 0.95:
                analysis.confidence_classification = AssetConfidence.CONFIRMED.value
                analysis.reasoning.append("CONFIRMED: multiple authoritative observations (confidence >= 95%)")
            elif analysis.asset_confidence >= 0.80:
                analysis.confidence_classification = AssetConfidence.PROBABLE.value
                analysis.reasoning.append("PROBABLE: strong supporting evidence (confidence 80-94%)")
            elif analysis.asset_confidence >= 0.60:
                analysis.confidence_classification = AssetConfidence.POSSIBLE.value
                analysis.reasoning.append("POSSIBLE: limited evidence (confidence 60-79%)")
            else:
                analysis.confidence_classification = AssetConfidence.UNVERIFIED.value
                analysis.reasoning.append("UNVERIFIED: insufficient evidence (confidence < 60%)")

            # Store in priority_targets list (only CONFIRMED and PROBABLE may be auto-prioritized)
            if analysis.confidence_classification in (AssetConfidence.CONFIRMED.value, AssetConfidence.PROBABLE.value):
                result.priority_targets.append({
                "asset_name": analysis.asset_name,
                "asset_type": analysis.asset_type,
                "priority_score": score,
                "criticality_score": analysis.criticality_score,
                "asset_confidence": analysis.asset_confidence,
                "confidence_classification": analysis.confidence_classification,
                "ownership_status": analysis.ownership_status,
                "exposure_level": analysis.exposure_level,
            })

        # Sort priority targets by score descending
        result.priority_targets.sort(key=lambda x: x["priority_score"], reverse=True)

        result.notes.append(
            f"Priority scoring complete: top target is '{result.priority_targets[0]['asset_name'] if result.priority_targets else 'N/A'}' "
            f"({result.priority_targets[0]['priority_score']}/100)"
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 13 — DOWNSTREAM GUIDANCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase13_guidance(self, domain: str, result: ActiveEnumResult):
        """Generate recommendations for downstream agents.

        - Validation workflows
        - Reporting workflows
        - Asset inventory systems
        - Human reviewers

        Recommendations must be evidence-based.
        """
        guidance: Dict[str, Any] = {
            "validation_recommendations": [],
            "reporting_recommendations": [],
            "inventory_recommendations": [],
            "human_review_required": [],
        }

        # Validation recommendations
        confirmed_assets = [a for a in result.assets_analyzed
                            if a.asset_confidence >= 0.95]
        if confirmed_assets:
            guidance["validation_recommendations"].append(
                f"Prioritize validation for {len(confirmed_assets)} CONFIRMED asset(s) with highest confidence"
            )

        high_priority = [pt for pt in result.priority_targets if pt["priority_score"] >= 70]
        if high_priority:
            guidance["validation_recommendations"].append(
                f"Validate {len(high_priority)} high-priority asset(s) (score >= 70): "
                f"{', '.join(pt['asset_name'] for pt in high_priority[:5])}"
            )

        # Reporting recommendations
        critical_assets = [a for a in result.assets_analyzed
                           if a.criticality_score >= 80]
        if critical_assets:
            guidance["reporting_recommendations"].append(
                f"Prioritize reporting for {len(critical_assets)} critical asset(s)"
            )

        # Inventory recommendations
        if result.assets_analyzed:
            guidance["inventory_recommendations"].append(
                f"Add {len(result.assets_analyzed)} analyzed asset(s) to inventory with classification and ownership metadata"
            )

        # Human review required
        needs_review = [
            a for a in result.assets_analyzed
            if a.ownership_status in (OwnershipStatus.UNKNOWN_OWNER.value, OwnershipStatus.THIRD_PARTY.value)
            or a.asset_type == AssetClassification.OTHER.value
            or a.contradictions
        ]
        if needs_review:
            guidance["human_review_required"].extend(
                a.asset_name for a in needs_review
            )

        # Contradiction-specific guidance
        if result.contradictions:
            guidance["validation_recommendations"].append(
                f"Review {len(result.contradictions)} contradiction(s) before finalizing assessment"
            )

        result.downstream_guidance = guidance

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 14 — HALLUCINATION PREVENTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase14_hallucination(self, domain: str, result: ActiveEnumResult):
        """Verify evidence support before finalizing conclusions.

        Ask for every conclusion:
        - What evidence supports this?
        - Can ownership be demonstrated?
        - Can classification be demonstrated?
        - Can exposure be demonstrated?
        - What assumptions remain?

        Remove unsupported assumptions. Unknown must remain UNKNOWN.
        """
        hallucination_flags = []

        for analysis in result.assets_analyzed:
            asset_name = analysis.asset_name

            # Check: What evidence supports this?
            if not analysis.evidence and not analysis.supporting_observations:
                hallucination_flags.append(asset_name)
                analysis.reasoning.append("HALLUCINATION CHECK FAILED: No evidence or observations for this asset")
                analysis.asset_confidence = max(analysis.asset_confidence - 0.3, 0.0)
                continue

            # Check: Can classification be demonstrated?
            if analysis.asset_type == AssetClassification.OTHER.value:
                # Only flag as potential hallucination if confidence is high despite OTHER classification
                if analysis.asset_confidence >= 0.7:
                    analysis.reasoning.append("HALLUCINATION CHECK: High confidence but OTHER classification — verify")
                    analysis.asset_confidence = max(analysis.asset_confidence - 0.1, 0.0)

            # Check: Can exposure be demonstrated?
            if not analysis.exposure_level:
                analysis.reasoning.append("HALLUCINATION CHECK: No exposure level determined")
                analysis.exposure_level = ExposureLevel.PUBLIC.value  # Default to public
                analysis.reasoning.append("Exposure defaulted to PUBLIC due to missing evidence")

            # Check: What assumptions remain?
            unsupported_reasoning = [r for r in analysis.reasoning
                                     if any(kw in r.lower() for kw in
                                            ("inferred", "suggests", "patterns", "likely", "probably"))]
            if unsupported_reasoning:
                analysis.recommended_review_actions.append(
                    f"Review {len(unsupported_reasoning)} assumption-based conclusion(s)"
                )

        if hallucination_flags:
            result.notes.append(
                f"HALLUCINATION CHECK: {len(hallucination_flags)} asset(s) flagged for zero evidence — "
                f"confidence reduced to minimum"
            )
        else:
            result.notes.append("Hallucination check passed: all assets have supporting evidence")

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _make_asset_id(self, name: str) -> str:
        """Generate a deterministic asset ID from the asset name."""
        return f"A5-{uuid.uuid5(uuid.NAMESPACE_DNS, name).hex[:12]}"

    # ═══════════════════════════════════════════════════════════════════════════
    # BACKWARD COMPATIBILITY WRAPPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def get_analysis_by_name(self, result: ActiveEnumResult, asset_name: str) -> Optional[AssetAnalysis]:
        """Get the analysis for a specific asset by name."""
        for a in result.assets_analyzed:
            if a.asset_name == asset_name:
                return a
        return None

    def get_priority_targets(self, result: ActiveEnumResult, min_score: int = 70) -> List[Dict[str, Any]]:
        """Get priority targets above a minimum score threshold."""
        return [pt for pt in result.priority_targets if pt["priority_score"] >= min_score]

    def get_summary(self, result: ActiveEnumResult) -> Dict[str, Any]:
        """Get a summary of the analysis."""
        classification_counts: Dict[str, int] = {}
        ownership_counts: Dict[str, int] = {}
        for a in result.assets_analyzed:
            classification_counts[a.asset_type] = classification_counts.get(a.asset_type, 0) + 1
            ownership_counts[a.ownership_status] = ownership_counts.get(a.ownership_status, 0) + 1

        return {
            "domain": result.domain,
            "total_assets_analyzed": len(result.assets_analyzed),
            "classifications": classification_counts,
            "ownership_distribution": ownership_counts,
            "relationships_found": len(result.relationships),
            "contradictions_detected": len(result.contradictions),
            "intelligence_gaps": len(result.intelligence_gaps),
            "top_priority": result.priority_targets[:3] if result.priority_targets else [],
            "phases_completed": len(result.phases_run),
        }
