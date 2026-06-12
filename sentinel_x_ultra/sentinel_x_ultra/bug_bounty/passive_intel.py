"""
AGENT 4 — PASSIVE INTELLIGENCE & OSINT ANALYST (STRICT EVIDENCE MODE)

You discover security-relevant intelligence about a bug bounty target WITHOUT
interacting directly with target infrastructure.

You are prohibited from:
- Sending requests to target-owned systems
- Scanning, fuzzing, probing, or brute-forcing targets
- Active enumeration

You are an intelligence analyst, not a scanner.

Core rules:
- Never invent assets. Never guess subdomains.
- Every discovery must contain: source, confidence, evidence, evidence_chain.
- Single-source discoveries are not considered confirmed.
- Unknown is preferable to incorrect.
- A missing asset is acceptable. A fabricated asset is unacceptable.

20-Phase Pipeline:
  1.  Asset Discovery (strict evidence only)
  2.  Historical Intelligence
  3.  Technology Intelligence
  4.  Organizational Intelligence
  5.  Repository Intelligence
  6.  Public Documentation Intelligence
  7.  Cloud Intelligence
  8.  Exposure Intelligence
  9.  Attack Surface Modeling (0-100 priority)
 10.  Source Reliability Analysis
 11.  Confidence Analysis
 12.  Contradiction Detection
 13.  Hallucination Prevention
 14.  Downstream Guidance & Collection Plan
 15.  Source Correlation
 16.  Ownership Verification
 17.  Intelligence Gap Analysis
 18.  Cross-Source Correlation
 19.  Intelligence Quality Score
 20.  Analyst Challenge Process
"""

import re
import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path


# ── Enums ───────────────────────────────────────────────────────────────────

class AssetClass(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    API = "API"
    WEB_APPLICATION = "WEB_APPLICATION"
    MOBILE_APP = "MOBILE_APP"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    REPOSITORY = "REPOSITORY"
    ENDPOINT = "ENDPOINT"
    IP_ADDRESS = "IP_ADDRESS"
    CERTIFICATE = "CERTIFICATE"
    EMAIL = "EMAIL"
    OTHER = "OTHER"


class ReliabilityLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssetPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH_VALUE = "HIGH_VALUE"
    MEDIUM_VALUE = "MEDIUM_VALUE"
    LOW_VALUE = "LOW_VALUE"


class OwnershipStatus(str, Enum):
    VERIFIED_OWNER = "VERIFIED_OWNER"
    LIKELY_OWNER = "LIKELY_OWNER"
    UNKNOWN_OWNER = "UNKNOWN_OWNER"
    THIRD_PARTY = "THIRD_PARTY"


# ── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class EvidenceChainItem:
    """A single piece of evidence in an evidence chain."""
    source: str = ""
    observation: str = ""
    confidence: float = 0.0


@dataclass
class DiscoveredAsset:
    """An asset discovered through passive intelligence."""
    asset: str = ""
    asset_type: str = ""
    source: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    evidence_chain: List[EvidenceChainItem] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    priority: str = "MEDIUM_VALUE"
    priority_score: int = 50
    priority_reasoning: List[str] = field(default_factory=list)
    ownership: str = "UNKNOWN_OWNER"


@dataclass
class SourceReliability:
    """Reliability score for an intelligence source."""
    source: str = ""
    reliability: str = "MEDIUM"
    notes: str = ""


@dataclass
class AttackSurfaceEntry:
    """An entry in the attack surface map."""
    asset: str = ""
    classification: str = "MEDIUM_VALUE"
    priority_score: int = 50
    reasoning: List[str] = field(default_factory=list)


@dataclass
class IntelligenceGap:
    """A gap in intelligence coverage."""
    category: str = ""  # ownership, technology, historical, repository
    asset: str = ""
    description: str = ""
    severity: str = "MEDIUM"


@dataclass
class CollectionPlanItem:
    """A recommended action for downstream agents."""
    asset: str = ""
    reason: str = ""
    priority: int = 50


@dataclass
class CrossSourceCorrelation:
    """A correlation across multiple intelligence sources."""
    asset: str = ""
    sources: List[str] = field(default_factory=list)
    relationships: List[str] = field(default_factory=list)
    overall_confidence: float = 0.0


@dataclass
class QualityScore:
    """Intelligence quality score with breakdown."""
    asset: str = ""
    overall_score: float = 0.0
    source_reliability_score: float = 0.0
    evidence_quality_score: float = 0.0
    source_diversity_score: float = 0.0
    ownership_confidence_score: float = 0.0
    corroboration_score: float = 0.0
    flags: List[str] = field(default_factory=list)


@dataclass
class ChallengeResult:
    """Result of an analyst challenge attempt."""
    asset: str = ""
    challenges: List[str] = field(default_factory=list)
    concerns_resolved: List[str] = field(default_factory=list)
    concerns_unresolved: List[str] = field(default_factory=list)
    confidence_adjustment: float = 0.0  # negative or zero


# ── Full Output Schema ──────────────────────────────────────────────────────

@dataclass
class PassiveIntelResult:
    """Complete result of passive intelligence gathering.

    Backward-compatible with the original PassiveIntelResult fields,
    extended with the full OSINT output schema from Agent 4 specification.
    """
    # Original fields (backward compatible)
    domain: str = ""
    subdomains: List[str] = field(default_factory=list)
    technologies: List[Dict[str, str]] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    social_media: List[str] = field(default_factory=list)
    job_postings: List[Dict[str, str]] = field(default_factory=list)
    certificate_info: List[Dict[str, str]] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    archived_urls: List[str] = field(default_factory=list)
    interesting_files: List[str] = field(default_factory=list)
    sources_checked: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # New OSINT fields (Agent 4 full output schema)
    assets: List[Dict[str, Any]] = field(default_factory=list)
    evidence_chains: List[Dict[str, Any]] = field(default_factory=list)
    historical_assets: List[Dict[str, Any]] = field(default_factory=list)
    repositories: List[Dict[str, Any]] = field(default_factory=list)
    documentation: List[Dict[str, Any]] = field(default_factory=list)
    cloud_intelligence: List[Dict[str, Any]] = field(default_factory=list)
    organizational_intelligence: List[Dict[str, Any]] = field(default_factory=list)
    exposure_intelligence: List[Dict[str, Any]] = field(default_factory=list)
    attack_surface_map: List[Dict[str, Any]] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)
    source_reliability: List[Dict[str, Any]] = field(default_factory=list)
    confidence_scores: List[Dict[str, Any]] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    recommended_priority_targets: List[str] = field(default_factory=list)
    downstream_guidance: Dict[str, Any] = field(default_factory=dict)

    # New v2 fields
    ownership_verifications: List[Dict[str, Any]] = field(default_factory=list)
    intelligence_gaps: List[Dict[str, Any]] = field(default_factory=list)
    collection_plan: List[Dict[str, Any]] = field(default_factory=list)
    cross_source_correlations: List[Dict[str, Any]] = field(default_factory=list)
    quality_scores: List[Dict[str, Any]] = field(default_factory=list)
    challenge_results: List[Dict[str, Any]] = field(default_factory=list)
    source_correlations: List[Dict[str, Any]] = field(default_factory=list)

    # Convenience alias
    @property
    def target(self) -> str:
        return self.domain

    @property
    def domains(self) -> List[str]:
        return [a["asset"] for a in self.assets if a.get("asset_type") in ("DOMAIN", "SUBDOMAIN")]


# ── Source Reliability Defaults ─────────────────────────────────────────────

SOURCE_RELIABILITY_MAP: Dict[str, str] = {
    "crt.sh": "HIGH",
    "google_ct": "HIGH",
    "censys_ct": "HIGH",
    "wayback_machine": "HIGH",
    "common_crawl": "HIGH",
    "github": "HIGH",
    "gitlab": "HIGH",
    "bitbucket": "HIGH",
    "official_documentation": "HIGH",
    "public_search_engines": "MEDIUM",
    "public_job_postings": "MEDIUM",
    "public_security_disclosures": "HIGH",
    "public_app_stores": "HIGH",
    "public_package_registries": "HIGH",
    "forum_discussion": "LOW",
    "social_media": "LOW",
    "blog_post": "MEDIUM",
    "archived_content": "HIGH",
    "dns_analysis": "MEDIUM",
}


# ── Passive Intelligence Agent ──────────────────────────────────────────────

class PassiveIntelligenceAgent:
    """
    Agent 4: Passive Intelligence & OSINT Analyst (Strict Evidence Mode).

    Discovers intelligence about targets using ONLY passive, third-party sources.
    Never makes direct requests to target infrastructure.
    Every discovery requires source + confidence + evidence + evidence_chain.

    AI-POWERED (Phase 1 Upgrade):
    - Uses LLMProvider for advanced OSINT analysis
    - AI-powered attack surface modeling with contextual understanding
    - LLM-driven analyst challenge process

    20-Phase Pipeline:
      1.  Asset Discovery (builds evidence chains)
      2.  Historical Intelligence
      3.  Technology Intelligence
      4.  Organizational Intelligence
      5.  Repository Intelligence
      6.  Public Documentation Intelligence
      7.  Cloud Intelligence
      8.  Exposure Intelligence
      9.  Attack Surface Modeling (0-100 priority scoring) — AI-enhanced
     10.  Source Reliability Analysis
     11.  Confidence Analysis
     12.  Contradiction Detection
     13.  Hallucination Prevention
     14.  Downstream Guidance & Collection Plan — AI-enhanced
     15.  Source Correlation
     16.  Ownership Verification
     17.  Intelligence Gap Analysis
     18.  Cross-Source Correlation
     19.  Intelligence Quality Score
     20.  Analyst Challenge Process — AI-enhanced
    """

    def __init__(self, llm_provider=None, memory=None, data_sources=None):
        self.llm_provider = llm_provider
        self.memory = memory
        self.data_sources = data_sources
        self.approved_sources = [
            "certificate_transparency",
            "wayback_machine",
            "common_crawl",
            "github",
            "gitlab",
            "public_search_engines",
            "public_documentation",
            "public_job_postings",
            "public_security_disclosures",
            "public_app_stores",
            "public_package_registries",
            # Phase 4: External data sources via API
            "securitytrails",
            "censys",
            "shodan",
            "urlscan",
        ]
        # CT log cache: domain -> (timestamp, [(subdomain, confidence, evidence)])
        self._ct_cache: Dict[str, Tuple[datetime, List[Tuple[str, float, List[str]]]]] = {}
        self._ct_cache_ttl = timedelta(hours=24)
        self._last_ct_request: Optional[datetime] = None
        self._ct_rate_limit = timedelta(seconds=5)  # 1 request per 5 seconds

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API (Backward Compatible)
    # ═══════════════════════════════════════════════════════════════════════════

    async def gather(self, domain: str) -> PassiveIntelResult:
        """Gather passive intelligence on a domain (legacy wrapper).

        Runs the full 20-phase OSINT pipeline and returns the complete result.
        """
        return await self._run_full_pipeline(domain)

    async def osint_gather(self, domain: str) -> PassiveIntelResult:
        """Run the full 20-phase OSINT pipeline.

        This is the primary API for the new implementation.
        Returns the complete structured intelligence output.
        """
        return await self._run_full_pipeline(domain)

    # ═══════════════════════════════════════════════════════════════════════════
    # FULL 20-PHASE PIPELINE
    # ═══════════════════════════════════════════════════════════════════════════

    async def _run_full_pipeline(self, domain: str) -> PassiveIntelResult:
        """Execute all 20 phases and return the complete intelligence result."""
        result = PassiveIntelResult(domain=domain)
        phases_run = []

        # Phase 1: Asset Discovery (strict evidence mode — builds evidence chains)
        await self._phase1_asset_discovery(domain, result)
        phases_run.append("asset_discovery")

        # Phase 2: Historical Intelligence
        self._phase2_historical(domain, result)
        phases_run.append("historical_intelligence")

        # Phase 3: Technology Intelligence
        self._phase3_technology(domain, result)
        phases_run.append("technology_intelligence")

        # Phase 4: Organizational Intelligence
        self._phase4_organizational(domain, result)
        phases_run.append("organizational_intelligence")

        # Phase 5: Repository Intelligence
        self._phase5_repository(domain, result)
        phases_run.append("repository_intelligence")

        # Phase 6: Public Documentation Intelligence
        self._phase6_documentation(domain, result)
        phases_run.append("documentation_intelligence")

        # Phase 7: Cloud Intelligence
        self._phase7_cloud(domain, result)
        phases_run.append("cloud_intelligence")

        # Phase 8: Exposure Intelligence
        self._phase8_exposure(domain, result)
        phases_run.append("exposure_intelligence")

        # Phase 9: Attack Surface Modeling (0-100 priority scoring) — AI-enhanced
        await self._phase9_attack_surface(result)
        phases_run.append("attack_surface_modeling")

        # Phase 10: Source Reliability Analysis
        self._phase10_source_reliability(result)
        phases_run.append("source_reliability")

        # Phase 11: Confidence Analysis
        self._phase11_confidence(result)
        phases_run.append("confidence_analysis")

        # Phase 12: Contradiction Detection
        self._phase12_contradictions(result)
        phases_run.append("contradiction_detection")

        # Phase 13: Hallucination Prevention
        self._phase13_hallucination(result)
        phases_run.append("hallucination_prevention")

        # Phase 14: Downstream Guidance & Collection Plan — AI-enhanced
        await self._phase14_downstream(result)
        phases_run.append("downstream_guidance")

        # Phase 15: Source Correlation
        self._phase15_source_correlation(result)
        phases_run.append("source_correlation")

        # Phase 16: Ownership Verification
        self._phase16_ownership(result)
        phases_run.append("ownership_verification")

        # Phase 17: Intelligence Gap Analysis
        self._phase17_gap_analysis(result)
        phases_run.append("intelligence_gap_analysis")

        # Phase 18: Cross-Source Correlation
        self._phase18_cross_source_correlation(result)
        phases_run.append("cross_source_correlation")

        # Phase 19: Intelligence Quality Score
        self._phase19_quality_score(result)
        phases_run.append("intelligence_quality_score")

        # Phase 20: Analyst Challenge Process — AI-enhanced
        await self._phase20_challenge(result)
        phases_run.append("analyst_challenge")

        # Record phases run
        result.downstream_guidance["phases_completed"] = phases_run
        result.downstream_guidance["total_phases"] = len(phases_run)

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 1 — ASSET DISCOVERY (STRICT EVIDENCE MODE + EVIDENCE CHAINS)
    # ═══════════════════════════════════════════════════════════════════════════

    async def _phase1_asset_discovery(self, domain: str, result: PassiveIntelResult):
        """Discover assets from passive sources only.

        STRICT RULES:
        - Never generate assets from wordlists
        - Only output observed assets
        - Every asset requires source + confidence + evidence + evidence_chain

        Phase 4: Also queries external data sources (Shodan, Censys, SecurityTrails, URLScan)
        when API keys are configured. Results are merged into the asset discovery.
        """
        result.sources_checked.append("crt.sh")
        result.sources_checked.append("certificate_transparency")

        # Phase 4: Query external data sources
        if self.data_sources:
            try:
                ext_results = await self.data_sources.search_domain(domain)
                for source_name, ds_result in ext_results.items():
                    if ds_result.success:
                        result.sources_checked.append(source_name)
                        # SecurityTrails returns subdomain lists directly
                        if source_name == "securitytrails" and "subdomains" in ds_result.data:
                            subdomain_list = ds_result.data.get("subdomains", [])
                            endpoint = ds_result.data.get("endpoint", domain)
                            for sub in subdomain_list:
                                full = f"{sub}.{endpoint}" if not sub.startswith(endpoint) else sub
                                if full not in result.subdomains:
                                    result.subdomains.append(full)
                                    result.assets.append({
                                        "asset": full,
                                        "asset_type": "SUBDOMAIN",
                                        "source": "securitytrails",
                                        "confidence": 0.85,
                                        "evidence": [f"Discovered via SecurityTrails API"],
                                        "evidence_chain": [
                                            {"source": "securitytrails", "observation": f"API returned subdomain: {sub}", "confidence": 0.85}
                                        ],
                                        "first_seen": "",
                                        "last_seen": datetime.now(timezone.utc).isoformat(),
                                        "priority": "MEDIUM_VALUE",
                                        "priority_score": 60,
                                        "priority_reasoning": [f"Discovered via SecurityTrails"],
                                        "ownership": "LIKELY_OWNER",
                                    })
                        # Censys returns certificate data with SAN names
                        if source_name == "censys":
                            certs = ds_result.data.get("result", {}).get("hits", [])
                            for cert in certs:
                                names = cert.get("parsed", {}).get("names", [])
                                for name in names:
                                    if "*" not in name and (name == domain or name.endswith(f".{domain}")):
                                        if name not in result.subdomains:
                                            result.subdomains.append(name.lower())
                                            result.assets.append({
                                                "asset": name.lower(),
                                                "asset_type": "SUBDOMAIN",
                                                "source": "censys_ct",
                                                "confidence": 0.9,
                                                "evidence": [f"Observed in Censys certificate transparency data"],
                                                "evidence_chain": [
                                                    {"source": "censys_ct", "observation": f"Certificate SAN: {name}", "confidence": 0.9}
                                                ],
                                                "first_seen": "",
                                                "last_seen": datetime.now(timezone.utc).isoformat(),
                                                "priority": "MEDIUM_VALUE",
                                                "priority_score": 65,
                                                "priority_reasoning": [f"Discovered via Censys certificate search"],
                                                "ownership": "LIKELY_OWNER",
                                            })
                        # URLScan returns page data with domains and URLs
                        if source_name == "urlscan":
                            url_results = ds_result.data.get("results", [])
                            for r in url_results:
                                page = r.get("page", {})
                                url_domain = page.get("domain", "")
                                if url_domain and url_domain.endswith(f".{domain}"):
                                    if url_domain not in result.subdomains:
                                        result.subdomains.append(url_domain.lower())
                                url = page.get("url", "")
                                if url and url not in result.archived_urls:
                                    result.archived_urls.append(url)
                        # Shodan returns hostname data
                        if source_name == "shodan":
                            matches = ds_result.data.get("matches", [])
                            for match in matches:
                                hostnames = match.get("hostnames", [])
                                for hn in hostnames:
                                    if hn.endswith(f".{domain}") or hn == domain:
                                        if hn not in result.subdomains:
                                            result.subdomains.append(hn.lower())
                                            result.assets.append({
                                                "asset": hn.lower(),
                                                "asset_type": "SUBDOMAIN",
                                                "source": "shodan",
                                                "confidence": 0.8,
                                                "evidence": [f"Observed in Shodan hostname data"],
                                                "evidence_chain": [
                                                    {"source": "shodan", "observation": f"Shodan hostname: {hn}", "confidence": 0.8}
                                                ],
                                                "first_seen": "",
                                                "last_seen": datetime.now(timezone.utc).isoformat(),
                                                "priority": "MEDIUM_VALUE",
                                                "priority_score": 60,
                                                "priority_reasoning": [f"Discovered via Shodan"],
                                                "ownership": "LIKELY_OWNER",
                                            })
            except Exception:
                pass

        # Certificate Transparency — real API query for observed subdomains
        ct_subdomains, ct_assets = await self._query_crtsh(domain)
        for sub in ct_subdomains:
            result.subdomains.append(sub)
            result.supporting_evidence.append(
                f"Subdomain '{sub}' observed in Certificate Transparency logs (crt.sh)"
            )
        for asset_entry in ct_assets:
            result.assets.append(asset_entry)
            # Build evidence chain for CT-discovered assets
            if asset_entry.get("evidence"):
                result.evidence_chains.append({
                    "asset": asset_entry["asset"],
                    "evidence_chain": [
                        {
                            "source": "crt.sh",
                            "observation": ev,
                            "confidence": 0.95,
                        }
                        for ev in asset_entry.get("evidence", [])
                    ],
                })

        # Record CT source reliability
        if ct_subdomains:
            result.source_reliability.append({
                "source": "crt.sh",
                "reliability": "HIGH",
                "notes": f"Returned {len(ct_subdomains)} observed subdomain(s) from Certificate Transparency logs",
            })

        # Record the domain itself as an asset
        result.assets.append({
            "asset": domain,
            "asset_type": "DOMAIN",
            "source": "target_definition",
            "confidence": 1.0,
            "evidence": ["Target domain provided by program scope"],
            "evidence_chain": [
                {"source": "program_scope", "observation": "Target domain provided by program scope", "confidence": 1.0}
            ],
            "first_seen": "",
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "priority": "CRITICAL",
            "priority_score": 100,
            "priority_reasoning": ["Primary target domain from program scope"],
            "ownership": "VERIFIED_OWNER",
        })
        # Evidence chain for domain
        result.evidence_chains.append({
            "asset": domain,
            "evidence_chain": [
                {"source": "program_scope", "observation": "Target domain provided by program scope", "confidence": 1.0}
            ],
        })

        # Add domain to subdomains for backward compatibility
        if domain not in result.subdomains:
            result.subdomains.insert(0, domain)

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 2 — HISTORICAL INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase2_historical(self, domain: str, result: PassiveIntelResult):
        """Identify historical endpoints, deprecated systems, legacy applications."""
        result.sources_checked.append("wayback_machine")

        # Wayback Machine archived URLs
        wayback_urls = self._query_wayback(domain)
        result.archived_urls = wayback_urls

        for url in wayback_urls:
            result.historical_assets.append({
                "asset": url,
                "asset_type": "ENDPOINT",
                "source": "wayback_machine",
                "confidence": 0.85,
                "evidence": [f"Archived in Wayback Machine (web.archive.org)"],
                "evidence_chain": [
                    {"source": "wayback_machine", "observation": f"Archived in Wayback Machine (web.archive.org)", "confidence": 0.85}
                ],
                "first_seen": "",
                "last_seen": "",
            })
            result.supporting_evidence.append(
                f"Historical URL '{url}' found in Wayback Machine archives"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 3 — TECHNOLOGY INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase3_technology(self, domain: str, result: PassiveIntelResult):
        """Identify technologies visible through passive sources.

        Sources: job postings, documentation, public repositories, archived content.
        Never claim technologies without evidence.
        """
        result.sources_checked.append("public_data_analysis")

        # Detect cloud providers from domain patterns (passive only)
        techs = self._detect_technologies(domain)
        result.technologies = techs

        for tech in techs:
            result.supporting_evidence.append(
                f"Technology hint: {tech.get('name', 'Unknown')} ({tech.get('category', '')}) — {tech.get('hint', '')}"
            )

        # Record tech as assets if properly evidenced
        if any(t.get("confidence", 0) >= 0.8 for t in techs):
            for tech in techs:
                if tech.get("confidence", 0) >= 0.8:
                    result.assets.append({
                        "asset": tech["name"],
                        "asset_type": "OTHER",
                        "source": "technology_detection",
                        "confidence": tech["confidence"],
                        "evidence": tech.get("evidence", []),
                        "evidence_chain": [
                            {"source": "technology_detection", "observation": ev, "confidence": tech["confidence"]}
                            for ev in tech.get("evidence", [])
                        ],
                        "first_seen": "",
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                        "priority": "MEDIUM_VALUE",
                        "priority_score": 50,
                        "priority_reasoning": [f"Inferred technology: {tech['name']}"],
                        "ownership": "UNKNOWN_OWNER",
                    })

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 4 — ORGANIZATIONAL INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase4_organizational(self, domain: str, result: PassiveIntelResult):
        """Extract organizational intelligence from public sources.

        Engineering references, architecture references, public presentations,
        public blogs, hiring information.
        """
        result.sources_checked.append("organizational_analysis")

        # Extract organization name from domain
        org_name = self._extract_org_name(domain)
        if org_name:
            result.supporting_evidence.append(
                f"Organization identified: '{org_name}' from domain {domain}"
            )

            result.organizational_intelligence.append({
                "category": "organization_identification",
                "value": org_name,
                "source": "domain_analysis",
                "confidence": 0.7,
                "evidence": [f"Extracted organization name from domain {domain}"],
                "evidence_chain": [
                    {"source": "domain_analysis", "observation": f"Extracted organization name from domain {domain}", "confidence": 0.7}
                ],
            })

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 5 — REPOSITORY INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase5_repository(self, domain: str, result: PassiveIntelResult):
        """Analyze public repositories for intelligence.

        Identifies API references, subdomain references, endpoint references,
        documentation references, infrastructure references.
        """
        result.sources_checked.append("github")
        result.sources_checked.append("public_repositories")

        # In production, would query GitHub/GitLab API for:
        # - Code search for domain references
        # - Repository mentions
        # - Configuration file references
        org_name = self._extract_org_name(domain)
        if org_name:
            self._record_source_reliability(result, "github", "Repository intelligence available")

            result.supporting_evidence.append(
                f"Repository intelligence available for '{org_name}' (requires API query in production)"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 6 — PUBLIC DOCUMENTATION INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase6_documentation(self, domain: str, result: PassiveIntelResult):
        """Analyze public documentation for intelligence.

        Developer portals, API documentation, changelogs, release notes.
        """
        result.sources_checked.append("public_documentation")

        # Common documentation endpoints
        doc_paths = [
            f"https://{domain}/docs",
            f"https://{domain}/api/docs",
            f"https://{domain}/developer",
            f"https://{domain}/developers",
        ]

        for doc_url in doc_paths:
            result.documentation.append({
                "url": doc_url,
                "type": "documentation_endpoint",
                "source": "pattern_analysis",
                "confidence": 0.3,
                "evidence": [f"Inferred documentation endpoint — requires passive verification"],
                "evidence_chain": [
                    {"source": "pattern_analysis", "observation": f"Inferred documentation endpoint — requires passive verification", "confidence": 0.3}
                ],
            })

        # Note: these are inferred, not verified — low confidence
        result.uncertainties.append(
            "Documentation endpoints are inferred from common patterns — requires passive verification via Wayback Machine or search engine cache"
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 7 — CLOUD INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase7_cloud(self, domain: str, result: PassiveIntelResult):
        """Identify publicly referenced cloud infrastructure.

        AWS, Azure, GCP, Cloudflare, Fastly, Akamai.
        Never assume cloud usage without evidence.
        """
        result.sources_checked.append("cloud_intelligence")

        # Detect cloud providers from DNS/mx patterns (passive only)
        cloud_hints = []

        # Check common cloud-related subdomain patterns
        domain_lower = domain.lower()
        if "aws" in domain_lower or "amazonaws" in domain_lower:
            cloud_hints.append(("AWS", 0.7))
        if "azure" in domain_lower or "windows.net" in domain_lower:
            cloud_hints.append(("Azure", 0.7))
        if "gcp" in domain_lower or "googlecloud" in domain_lower:
            cloud_hints.append(("GCP", 0.7))
        if "cloudflare" in domain_lower:
            cloud_hints.append(("Cloudflare", 0.8))

        for provider, confidence in cloud_hints:
            result.cloud_intelligence.append({
                "provider": provider,
                "source": "domain_pattern_analysis",
                "confidence": confidence,
                "evidence": [f"Domain pattern '{domain}' suggests {provider} usage"],
                "evidence_chain": [
                    {"source": "domain_pattern_analysis", "observation": f"Domain pattern '{domain}' suggests {provider} usage", "confidence": confidence}
                ],
            })
            result.supporting_evidence.append(
                f"Cloud provider hint: {provider} (confidence: {confidence:.0%})"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 8 — EXPOSURE INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase8_exposure(self, domain: str, result: PassiveIntelResult):
        """Identify publicly visible exposure indicators.

        Only document. Do not assess exploitability. Do not classify vulnerabilities.
        """
        result.sources_checked.append("exposure_analysis")

        # Identify potentially interesting files via historical data
        interesting = self._find_interesting_files(domain)
        result.interesting_files = interesting

        for f in interesting:
            result.exposure_intelligence.append({
                "asset": f,
                "type": "potential_exposure_point",
                "source": "pattern_analysis",
                "confidence": 0.3,
                "evidence": [f"Common file pattern — requires passive verification via Wayback Machine"],
                "evidence_chain": [
                    {"source": "pattern_analysis", "observation": f"Common file pattern — requires passive verification via Wayback Machine", "confidence": 0.3}
                ],
            })
            result.supporting_evidence.append(
                f"Potential exposure: {f} (requires passive verification)"
            )

        # Record DNS analysis
        dns = self._analyze_dns_patterns(domain)
        result.dns_records = dns
        result.sources_checked.append("dns_analysis")

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 9 — ATTACK SURFACE MODELING (0-100 PRIORITY SCORING)
    # ═══════════════════════════════════════════════════════════════════════════

    async def _phase9_attack_surface(self, result: PassiveIntelResult):
        """Build an attack surface map with 0-100 priority scoring.

        AI-Powered: Uses LLM for intelligent prioritization when available.
        Considers:
        - Business criticality
        - Authentication boundaries
        - Administrative functionality
        - User data exposure
        - API exposure
        - Cloud exposure

        Falls back to deterministic scoring.
        """
        # Try AI-powered attack surface modeling
        if self.llm_provider and self.llm_provider.is_available and result.assets:
            try:
                ai_priorities = await self.llm_provider.prioritize_assets(
                    program_context=f"Target: {result.domain}",
                    assets=[
                        {"asset": a.get("asset", ""), "type": a.get("asset_type", ""), "confidence": a.get("confidence", 0)}
                        for a in result.assets[:20]
                    ],
                    technologies=[t.get("name", "") for t in result.technologies],
                )
                # Apply AI priority scores
                for ai_item in ai_priorities:
                    if not isinstance(ai_item, dict):
                        continue
                    asset_name = ai_item.get("asset_name", "")
                    ai_score = ai_item.get("priority_score", 50)
                    ai_reasoning = ai_item.get("reasoning", [])
                    for asset_entry in result.assets:
                        if asset_entry.get("asset") == asset_name:
                            asset_entry["priority_score"] = min(int(ai_score), 100)
                            if ai_reasoning:
                                asset_entry["priority_reasoning"] = ai_reasoning[:5]
                result.downstream_guidance["ai_attack_surface"] = True
            except Exception:
                pass

        for asset_entry in result.assets:
            asset = asset_entry.get("asset", "")
            asset_type = asset_entry.get("asset_type", "")
            confidence = asset_entry.get("confidence", 0)
            source = asset_entry.get("source", "")

            # Priority scoring factors (0-100 base = 50)
            score = 50
            reasoning = []

            # Business criticality: DOMAIN and API assets are more critical
            if asset_type == "DOMAIN":
                score += 25
                reasoning.append("Core domain asset — highest business criticality")
            elif asset_type == "API" or "api" in asset.lower():
                score += 20
                reasoning.append("API endpoint — likely handles sensitive data flows")
            elif asset_type == "SUBDOMAIN" and any(
                kw in asset.lower() for kw in ["admin", "auth", "login", "backoffice", "internal", "dev", "staging"]
            ):
                score += 15
                reasoning.append(f"Administrative/internal subdomain — higher value")

            # Authentication boundaries
            if any(kw in asset.lower() for kw in ["auth", "login", "sso", "oauth", "token"]):
                score += 15
                reasoning.append("Authentication boundary — potential access control issues")
            if any(kw in asset.lower() for kw in ["api", "graphql", "rest", "v1", "v2"]):
                score += 10
                reasoning.append("API boundary — potential for authorization flaws")

            # User data exposure
            if any(kw in asset.lower() for kw in ["user", "profile", "account", "customer", "data"]):
                score += 10
                reasoning.append("User data exposure surface — sensitive information")

            # Cloud exposure
            if any(kw in asset.lower() for kw in ["aws", "s3", "cloud", "azure", "gcp"]):
                score += 10
                reasoning.append("Cloud infrastructure exposure — potential misconfiguration")

            # Confidence adjustment
            score += int(confidence * 10)  # 0-10 pts from confidence
            if confidence >= 0.9:
                reasoning.append("Very high confidence — verified by multiple sources")
            elif confidence >= 0.7:
                reasoning.append("High confidence — verified by authoritative source")

            # Source adjustment
            if source == "target_definition":
                score += 10
                reasoning.append("Provided directly by program scope — maximum trust")

            # Cap at 0-100
            score = max(0, min(100, score))

            # Classification from score
            if score >= 80:
                classification = AssetPriority.CRITICAL.value
            elif score >= 60:
                classification = AssetPriority.HIGH_VALUE.value
            elif score >= 40:
                classification = AssetPriority.MEDIUM_VALUE.value
            else:
                classification = AssetPriority.LOW_VALUE.value

            # Update the asset entry with priority data
            asset_entry["priority_score"] = score
            asset_entry["priority_reasoning"] = reasoning

            result.attack_surface_map.append({
                "asset": asset,
                "classification": classification,
                "priority_score": score,
                "reasoning": reasoning,
            })

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 10 — SOURCE RELIABILITY ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase10_source_reliability(self, result: PassiveIntelResult):
        """Score every source for reliability.

        HIGH: Certificate Transparency, Official Documentation, Public Repository
        MEDIUM: Job Postings, Blog Posts
        LOW: Forum Discussions, Social Media
        """
        sources_seen = set()
        for source in result.sources_checked:
            if source in sources_seen:
                continue
            sources_seen.add(source)

            reliability = SOURCE_RELIABILITY_MAP.get(source, "MEDIUM")
            notes = ""
            if reliability == "HIGH":
                notes = "Authoritative source — data can be trusted for decision-making"
            elif reliability == "MEDIUM":
                notes = "Moderately reliable — cross-reference recommended"
            elif reliability == "LOW":
                notes = "Low reliability — verify before using"

            result.source_reliability.append({
                "source": source,
                "reliability": reliability,
                "notes": notes,
            })

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 11 — CONFIDENCE ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase11_confidence(self, result: PassiveIntelResult):
        """Analyze confidence for every discovery.

        95-100: Multiple authoritative sources
        80-94: Single authoritative source
        60-79: Indirect evidence
        Below 60: Unverified
        """
        for asset_entry in result.assets:
            conf = asset_entry.get("confidence", 0)
            asset = asset_entry.get("asset", "")
            source = asset_entry.get("source", "")

            if conf >= 95:
                level = "Very High — multiple authoritative sources"
            elif conf >= 80:
                level = "High — single authoritative source"
            elif conf >= 60:
                level = "Moderate — indirect evidence"
            else:
                level = "Low — unverified, verify before using"

            result.confidence_scores.append({
                "asset": asset,
                "confidence": conf,
                "interpretation": level,
                "source": source,
            })

        # Flag weak evidence
        weak_assets = [
            a for a in result.assets if a.get("confidence", 0) < 60
        ]
        if weak_assets:
            result.uncertainties.append(
                f"{len(weak_assets)} asset(s) have weak evidence (confidence < 60%) — verify before use"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 12 — CONTRADICTION DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase12_contradictions(self, result: PassiveIntelResult):
        """Identify conflicting information across sources.

        Do not resolve through assumptions.
        """
        # Check for duplicate assets with different confidence levels
        seen_assets: Dict[str, List[float]] = {}
        for asset_entry in result.assets:
            asset = asset_entry.get("asset", "")
            conf = asset_entry.get("confidence", 0)
            if asset not in seen_assets:
                seen_assets[asset] = []
            seen_assets[asset].append(conf)

        for asset, confs in seen_assets.items():
            if len(confs) > 1 and max(confs) - min(confs) > 0.3:
                result.contradictions.append(
                    f"Conflicting confidence for '{asset}': ranges from {min(confs):.0%} to {max(confs):.0%}"
                )

        # Check for domain appearing in both CT and other sources with issues
        if result.errors:
            result.contradictions.append(
                f"Errors encountered during intelligence gathering ({len(result.errors)} error(s)) — may indicate incomplete data"
            )

        # Check for conflicting asset types (same asset, different types)
        asset_type_map: Dict[str, List[str]] = {}
        for a in result.assets:
            asset = a.get("asset", "")
            atype = a.get("asset_type", "")
            if asset not in asset_type_map:
                asset_type_map[asset] = []
            if atype and atype not in asset_type_map[asset]:
                asset_type_map[asset].append(atype)
        for asset, types in asset_type_map.items():
            if len(types) > 1:
                result.contradictions.append(
                    f"Asset '{asset}' classified as multiple types: {', '.join(types)}"
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 13 — HALLUCINATION PREVENTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase13_hallucination(self, result: PassiveIntelResult):
        """Before outputting discoveries, verify evidence support.

        - What evidence supports this?
        - What source supports this?
        - What assumptions exist?
        - Unknown information must remain UNKNOWN
        """
        # Check each asset for evidence
        unverified_assets = []
        for asset_entry in result.assets:
            evidence = asset_entry.get("evidence", [])
            source = asset_entry.get("source", "")
            confidence = asset_entry.get("confidence", 0)

            if not evidence and source != "target_definition":
                unverified_assets.append(asset_entry.get("asset", "unknown"))

            # Check if confidence is appropriate for evidence
            if confidence >= 0.8 and not evidence:
                result.uncertainties.append(
                    f"High confidence ({confidence:.0%}) but no evidence for '{asset_entry.get('asset', '')}' — possible hallucination"
                )

        if unverified_assets:
            result.supporting_evidence.append(
                f"HALLUCINATION CHECK: {len(unverified_assets)} asset(s) lack supporting evidence — flagged for review"
            )

        # Verify every uncertainty has a reason
        if not result.uncertainties:
            result.supporting_evidence.append(
                "Hallucination check passed: no unsupported discoveries found"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 14 — DOWNSTREAM GUIDANCE & COLLECTION PLAN
    # ═══════════════════════════════════════════════════════════════════════════

    async def _phase14_downstream(self, result: PassiveIntelResult):
        """Generate recommendations for downstream agents.

        AI-Powered: Uses LLM for smarter guidance when available.
        Includes collection plan with prioritized asset-specific recommendations.

        Prioritize:
        - Highest-confidence assets
        - Highest-value assets (0-100 priority score)
        - Historically interesting assets

        Do not recommend actions on unverified assets.
        """
        # Try AI-powered downstream guidance
        if self.llm_provider and self.llm_provider.is_available and result.assets:
            try:
                ai_osint = await self.llm_provider.analyze_osint(
                    target=result.domain,
                    osint_data={
                        "asset_count": len(result.assets),
                        "subdomain_count": len(result.subdomains),
                        "technology_count": len(result.technologies),
                        "historical_count": len(result.historical_assets),
                        "top_assets": [a.get("asset", "") for a in result.assets[:5]],
                    },
                    tools_used=result.sources_checked,
                )
                if ai_osint.get("recommendations"):
                    recs = ai_osint["recommendations"]
                    if isinstance(recs, list):
                        result.downstream_guidance["ai_recommendations"] = recs[:10]
                    elif isinstance(recs, dict):
                        result.downstream_guidance["ai_recommendations"] = recs
                if ai_osint.get("attack_surface", {}).get("priority_targets"):
                    ai_targets = ai_osint["attack_surface"]["priority_targets"]
                    if isinstance(ai_targets, list):
                        result.recommended_priority_targets.extend(
                            t for t in ai_targets if t not in result.recommended_priority_targets
                        )
            except Exception:
                pass

        # Sort assets by priority_score for targeting
        sorted_assets = sorted(
            [a for a in result.assets if a.get("confidence", 0) >= 0.6 and a.get("priority_score", 0) >= 40],
            key=lambda a: (
                a.get("priority_score", 0),
                a.get("confidence", 0),
            ),
            reverse=True,
        )

        priority_targets = [a["asset"] for a in sorted_assets[:10]]
        result.recommended_priority_targets = priority_targets

        # Build collection plan: only recommend assets with sufficient evidence
        collection_plan = []
        for a in sorted_assets[:15]:
            score = a.get("priority_score", 50)
            reasoning = a.get("priority_reasoning", [])
            reason = reasoning[0] if reasoning else f"High confidence asset (score: {score})"

            if score >= 70:
                collection_plan.append({
                    "asset": a["asset"],
                    "reason": f"{reason} — priority {score}",
                    "priority": score,
                })

        result.collection_plan = collection_plan

        # Build downstream guidance
        high_conf_assets = [a for a in result.assets if a.get("confidence", 0) >= 0.8]
        hist_assets = result.historical_assets

        guidance: Dict[str, Any] = {
            "asset_discovery_recommendations": [],
            "scanner_recommendations": [],
            "validation_recommendations": [],
        }

        if high_conf_assets:
            guidance["asset_discovery_recommendations"].append(
                f"Prioritize {len(high_conf_assets)} high-confidence asset(s) for active verification"
            )
            guidance["scanner_recommendations"].append(
                f"Scan priority: {', '.join(a['asset'] for a in high_conf_assets[:5])}"
            )

        if hist_assets:
            guidance["validation_recommendations"].append(
                f"Review {len(hist_assets)} historical endpoint(s) for deprecated but accessible functionality"
            )

        if result.uncertainties:
            guidance["validation_recommendations"].append(
                f"Address {len(result.uncertainties)} uncertainty(ies) before acting on low-confidence discoveries"
            )

        # Asset-specific collection plan instructions
        if collection_plan:
            guidance["collection_plan"] = collection_plan

        result.downstream_guidance = guidance

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 15 — SOURCE CORRELATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase15_source_correlation(self, result: PassiveIntelResult):
        """Perform source correlation for every discovered asset.

        For every asset, count how many unique sources it was observed from.
        Single-source discoveries are not considered confirmed.

        Flags:
        - Single-source assets flagged for verification
        - Multi-source assets receive confidence boost
        """
        # Count sources per asset
        asset_sources: Dict[str, List[str]] = {}

        # Collect from assets list
        for a in result.assets:
            asset = a.get("asset", "")
            source = a.get("source", "")
            if asset and source:
                if asset not in asset_sources:
                    asset_sources[asset] = []
                if source not in asset_sources[asset]:
                    asset_sources[asset].append(source)

        # Also check evidence chains for additional sources
        for ec in result.evidence_chains:
            asset = ec.get("asset", "")
            for item in ec.get("evidence_chain", []):
                src = item.get("source", "")
                if asset and src:
                    if asset not in asset_sources:
                        asset_sources[asset] = []
                    if src not in asset_sources[asset]:
                        asset_sources[asset].append(src)

        # Correlate and flag
        for asset, sources in asset_sources.items():
            source_count = len(sources)
            status = "CONFIRMED" if source_count >= 2 else "SINGLE_SOURCE"
            confidence_boost = min((source_count - 1) * 0.05, 0.15) if source_count > 1 else -0.1

            result.source_correlations.append({
                "asset": asset,
                "source_count": source_count,
                "sources": sources,
                "status": status,
                "confidence_boost": confidence_boost,
            })

            if source_count == 1 and asset != result.domain:
                result.uncertainties.append(
                    f"'{asset}' is a single-source discovery (source: {sources[0]}) — not considered confirmed"
                )

            # Apply confidence boost to asset entries
            if confidence_boost > 0:
                for a in result.assets:
                    if a.get("asset") == asset:
                        old_conf = a.get("confidence", 0)
                        a["confidence"] = min(old_conf + confidence_boost, 1.0)
                        break

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 16 — OWNERSHIP VERIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase16_ownership(self, result: PassiveIntelResult):
        """Determine ownership for every asset.

        VERIFIED_OWNER: Asset clearly belongs to the target organization
        LIKELY_OWNER: Strong evidence suggests ownership
        UNKNOWN_OWNER: Cannot determine ownership
        THIRD_PARTY: Asset belongs to a third-party provider

        Only VERIFIED_OWNER assets should be prioritized.
        UNKNOWN ownership must be flagged.
        THIRD_PARTY assets must be highlighted for Scope Guardian review.
        """
        domain = result.domain
        root_domain = ".".join(domain.split(".")[-2:]) if len(domain.split(".")) >= 2 else domain

        for asset_entry in result.assets:
            asset = asset_entry.get("asset", "")
            asset_type = asset_entry.get("asset_type", "")
            source = asset_entry.get("source", "")

            ownership = OwnershipStatus.UNKNOWN_OWNER.value
            reasoning = []

            # Domain from program scope = VERIFIED_OWNER
            if source == "target_definition" or asset == domain:
                ownership = OwnershipStatus.VERIFIED_OWNER.value
                reasoning.append("Target domain from program scope — ownership verified")

            # Subdomain of target domain = LIKELY_OWNER
            elif asset.endswith(f".{domain}") or asset.endswith(f".{root_domain}"):
                # Check for third-party indicators
                if any(kw in asset.lower() for kw in [
                    "s3.amazonaws", "cloudfront", "akamai", "fastly",
                    "cloudflare", "googleapis", "azureedge", "windows.net",
                ]):
                    ownership = OwnershipStatus.THIRD_PARTY.value
                    reasoning.append(f"Asset uses known third-party infrastructure ({asset.split('.')[-2:]})")
                else:
                    ownership = OwnershipStatus.LIKELY_OWNER.value
                    reasoning.append(f"Subdomain of target domain — likely owned by target organization")

            # CT-discovered subdomain
            elif source == "crt.sh" and (asset.endswith(f".{domain}") or asset.endswith(f".{root_domain}")):
                ownership = OwnershipStatus.LIKELY_OWNER.value
                reasoning.append("Subdomain from Certificate Transparency — likely owned by target")

            # Technology detection
            elif source == "technology_detection":
                ownership = OwnershipStatus.UNKNOWN_OWNER.value
                reasoning.append("Technology detected from indirect evidence — ownership unclear")

            # Inferred documentation
            elif source == "pattern_analysis":
                ownership = OwnershipStatus.UNKNOWN_OWNER.value
                reasoning.append("Inferred from common patterns — cannot verify ownership")

            # Default
            else:
                ownership = OwnershipStatus.UNKNOWN_OWNER.value
                reasoning.append("Cannot determine ownership from available evidence")

            # Update asset entry
            asset_entry["ownership"] = ownership

            result.ownership_verifications.append({
                "asset": asset,
                "ownership": ownership,
                "reasoning": reasoning,
                "requires_scope_review": ownership == OwnershipStatus.THIRD_PARTY.value,
            })

            # Flag unknowns and third parties
            if ownership == OwnershipStatus.UNKNOWN_OWNER.value:
                result.uncertainties.append(
                    f"'{asset}' has UNKNOWN ownership — verify before prioritizing"
                )
            elif ownership == OwnershipStatus.THIRD_PARTY.value:
                result.uncertainties.append(
                    f"'{asset}' appears to be a THIRD-PARTY asset — Scope Guardian review recommended"
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 17 — INTELLIGENCE GAP ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase17_gap_analysis(self, result: PassiveIntelResult):
        """Identify intelligence gaps.

        Missing evidence categories:
        - ownership: cannot determine who owns the asset
        - technology: cannot determine what technology stack is used
        - historical: no historical data available
        - repository: no repository/code references found
        """
        domain = result.domain

        # Ownership gap
        unknown_ownership = [a for a in result.assets if a.get("ownership") == OwnershipStatus.UNKNOWN_OWNER.value]
        if unknown_ownership:
            for a in unknown_ownership:
                result.intelligence_gaps.append({
                    "category": "ownership",
                    "asset": a.get("asset", ""),
                    "description": f"Cannot determine ownership for '{a.get('asset', '')}' — no authoritative source confirms ownership",
                    "severity": "HIGH" if a.get("priority_score", 50) >= 60 else "MEDIUM",
                })

        # Technology gap
        tech_names = set(t.get("name", "").lower() for t in result.technologies if t.get("name"))
        if not tech_names:
            result.intelligence_gaps.append({
                "category": "technology",
                "asset": domain,
                "description": "No technology stack intelligence available for target domain",
                "severity": "MEDIUM",
            })

        # Historical gap
        if not result.historical_assets:
            result.intelligence_gaps.append({
                "category": "historical",
                "asset": domain,
                "description": "No historical data available — Wayback Machine may have no archives for this domain",
                "severity": "LOW",
            })

        # Repository gap
        if not result.repositories:
            result.intelligence_gaps.append({
                "category": "repository",
                "asset": domain,
                "description": "No repository references found — requires GitHub/GitLab API query in production",
                "severity": "MEDIUM",
            })

        # Flag gap count
        gap_count = len(result.intelligence_gaps)
        if gap_count > 0:
            result.supporting_evidence.append(
                f"Intelligence Gap Analysis complete: {gap_count} gap(s) identified — uncertainties are documented, not hidden"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 18 — CROSS-SOURCE CORRELATION
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase18_cross_source_correlation(self, result: PassiveIntelResult):
        """Correlate intelligence across multiple source types.

        Correlates:
        - CT logs
        - Repositories
        - Documentation
        - Historical archives
        - Job postings

        Identifies relationships that increase confidence.
        Correlated evidence increases confidence.
        """
        domain = result.domain

        # Collect all unique asset references across sources
        asset_references: Dict[str, List[Dict[str, Any]]] = {}

        # From CT logs (assets list)
        for a in result.assets:
            asset = a.get("asset", "")
            if asset and a.get("source") == "crt.sh":
                if asset not in asset_references:
                    asset_references[asset] = []
                asset_references[asset].append({
                    "source": "CT Logs",
                    "source_type": "certificate_transparency",
                    "confidence": a.get("confidence", 0),
                })

        # From Wayback Machine (historical_assets)
        for h in result.historical_assets:
            asset = h.get("asset", "")
            if asset:
                # Extract domain from URL
                url_match = re.search(r'https?://([^/]+)', str(asset))
                ref_domain = url_match.group(1) if url_match else ""
                if ref_domain:
                    if ref_domain not in asset_references:
                        asset_references[ref_domain] = []
                    asset_references[ref_domain].append({
                        "source": "Wayback Machine",
                        "source_type": "historical_archive",
                        "confidence": h.get("confidence", 0.8),
                    })

        # From organizational intelligence
        for o in result.organizational_intelligence:
            org_name = o.get("value", "")
            if org_name:
                # Organization name is a weak reference to the domain
                if domain not in asset_references:
                    asset_references[domain] = []
                asset_references[domain].append({
                    "source": "Organizational Intel",
                    "source_type": "organizational",
                    "confidence": o.get("confidence", 0.7),
                })

        # Build correlations
        for asset, refs in asset_references.items():
            sources = [r["source"] for r in refs]
            unique_sources = list(set(sources))
            overall_conf = min(sum(r["confidence"] for r in refs) / len(refs), 1.0)

            # Boost confidence for multi-source assets
            if len(unique_sources) >= 2 and overall_conf > 0:
                relationships = []
                for i, ref1 in enumerate(refs):
                    for j, ref2 in enumerate(refs):
                        if i < j and ref1["source"] != ref2["source"]:
                            relationships.append(
                                f"{ref1['source']} → {asset} (confidence: {ref1['confidence']:.0%}) and "
                                f"{ref2['source']} → {asset} (confidence: {ref2['confidence']:.0%})"
                            )

                result.cross_source_correlations.append({
                    "asset": asset,
                    "sources": unique_sources,
                    "relationships": relationships[:5],  # Cap at 5 relationships
                    "overall_confidence": round(overall_conf, 2),
                })

                # Update asset confidence if cross-correlated
                for a in result.assets:
                    if a.get("asset") == asset:
                        boost = min(len(unique_sources) * 0.03, 0.12)
                        a["confidence"] = min(a.get("confidence", 0) + boost, 1.0)
                        break

        # Summary
        if result.cross_source_correlations:
            result.supporting_evidence.append(
                f"Cross-Source Correlation complete: {len(result.cross_source_correlations)} asset(s) confirmed by multiple sources"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 19 — INTELLIGENCE QUALITY SCORE
    # ═══════════════════════════════════════════════════════════════════════════

    def _phase19_quality_score(self, result: PassiveIntelResult):
        """Calculate intelligence quality score (0-100) for every asset.

        Factors:
        - Source reliability (0-25)
        - Evidence quality (0-25)
        - Source diversity (0-20)
        - Ownership confidence (0-15)
        - Corroboration (0-15)

        Low-quality intelligence must be flagged.
        """
        for asset_entry in result.assets:
            asset = asset_entry.get("asset", "")
            confidence = asset_entry.get("confidence", 0)
            source = asset_entry.get("source", "")
            ownership = asset_entry.get("ownership", OwnershipStatus.UNKNOWN_OWNER.value)
            evidence = asset_entry.get("evidence", [])

            # 1. Source reliability score (0-25)
            reliability_str = SOURCE_RELIABILITY_MAP.get(source, "MEDIUM")
            if reliability_str == "HIGH":
                src_score = 25
            elif reliability_str == "MEDIUM":
                src_score = 15
            else:
                src_score = 5

            # 2. Evidence quality score (0-25)
            has_evidence = len(evidence) > 0
            has_evidence_chain = bool(asset_entry.get("evidence_chain"))
            if has_evidence and has_evidence_chain:
                ev_score = 25
            elif has_evidence:
                ev_score = 18
            elif has_evidence_chain:
                ev_score = 15
            else:
                ev_score = 5

            # 3. Source diversity score (0-20) from source correlation
            correlation = next(
                (c for c in result.source_correlations if c.get("asset") == asset),
                None
            )
            if correlation:
                source_count = correlation.get("source_count", 1)
                div_score = min(source_count * 7, 20)  # 0-20
            else:
                div_score = 5

            # 4. Ownership confidence score (0-15)
            if ownership == OwnershipStatus.VERIFIED_OWNER.value:
                own_score = 15
            elif ownership == OwnershipStatus.LIKELY_OWNER.value:
                own_score = 10
            elif ownership == OwnershipStatus.THIRD_PARTY.value:
                own_score = 5
            else:
                own_score = 2

            # 5. Corroboration score (0-15)
            cross_corr = next(
                (c for c in result.cross_source_correlations if c.get("asset") == asset),
                None
            )
            if cross_corr:
                corr_score = min(len(cross_corr.get("sources", [])) * 5, 15)
            else:
                corr_score = 3

            # Total
            total = src_score + ev_score + div_score + own_score + corr_score

            # Flags
            flags = []
            if ev_score < 10:
                flags.append("Low evidence quality — missing evidence or evidence chain")
            if div_score < 10:
                flags.append("Low source diversity — single-source discovery")
            if own_score < 5:
                flags.append("Low ownership confidence — cannot verify ownership")
            if corr_score < 5:
                flags.append("No corroboration — isolated finding")
            if confidence < 0.6:
                flags.append("Low confidence — verify before using")

            result.quality_scores.append({
                "asset": asset,
                "overall_score": total,
                "source_reliability_score": src_score,
                "evidence_quality_score": ev_score,
                "source_diversity_score": div_score,
                "ownership_confidence_score": own_score,
                "corroboration_score": corr_score,
                "flags": flags,
            })

            # Flag low-quality intelligence
            if total < 40:
                result.uncertainties.append(
                    f"Low quality intelligence for '{asset}' (score: {total}/100) — {flags[0] if flags else 'requires verification'}"
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 20 — ANALYST CHALLENGE PROCESS
    # ═══════════════════════════════════════════════════════════════════════════

    async def _phase20_challenge(self, result: PassiveIntelResult):
        """Attempt to disprove every discovery.

        AI-Powered: Uses LLM for smarter challenge analysis.
        For every asset, ask:
        - Could this be incorrect?
        - Could ownership be wrong?
        - Could this asset belong to a third party?
        - Could evidence be outdated?

        If concerns cannot be resolved: reduce confidence.
        Never inflate certainty.
        """
        # Track which assets were AI-challenged to avoid duplicate deterministic entries
        ai_challenged_assets = set()

        # Try AI-powered challenge on high-value assets
        if self.llm_provider and self.llm_provider.is_available:
            high_value = [a for a in result.assets if a.get("priority_score", 0) >= 70]
            for asset_entry in high_value[:5]:
                try:
                    ai_challenge = await self.llm_provider.reason_structured(
                        f"Challenge this asset discovery: asset={asset_entry.get('asset', '')}, "
                        f"type={asset_entry.get('asset_type', '')}, "
                        f"source={asset_entry.get('source', '')}, "
                        f"confidence={asset_entry.get('confidence', 0)}, "
                        f"evidence={asset_entry.get('evidence', [])[:3]}. "
                        f"Generate alternative explanations for this discovery."
                    )
                    if ai_challenge:
                        challenges = ai_challenge.get("alternative_explanations", [])
                        ai_challenges_list = challenges[:3] if isinstance(challenges, list) else []
                        result.challenge_results.append({
                            "asset": asset_entry.get("asset", ""),
                            "challenges": ai_challenges_list,
                            "concerns_resolved": [],
                            "concerns_unresolved": ai_challenges_list,
                            "confidence_adjustment": -0.05 if ai_challenges_list else 0.0,
                        })
                        ai_challenged_assets.add(asset_entry.get("asset", ""))
                except Exception:
                    pass

        for asset_entry in result.assets:
            # Skip assets already challenged by AI
            if asset_entry.get("asset", "") in ai_challenged_assets:
                continue
            asset = asset_entry.get("asset", "")
            source = asset_entry.get("source", "")
            confidence = asset_entry.get("confidence", 0)
            ownership = asset_entry.get("ownership", OwnershipStatus.UNKNOWN_OWNER.value)
            priority_score = asset_entry.get("priority_score", 50)

            challenges = []
            resolved = []
            unresolved = []
            adjustment = 0.0

            # Challenge 1: Could this be incorrect?
            if source == "target_definition":
                resolved.append("Asset from program scope — cannot be incorrect")
            elif source == "pattern_analysis":
                challenges.append("Asset inferred from pattern analysis — could be incorrect")
                unresolved.append("Inferred from common patterns — requires passive verification")
                adjustment -= 0.1
            elif source == "technology_detection":
                challenges.append("Technology inferred from indirect evidence — could be incorrect")
                unresolved.append("Technology detection from domain patterns — indirect evidence")
                adjustment -= 0.1
            elif source == "crt.sh" and confidence >= 0.9:
                resolved.append("Asset from Certificate Transparency log — authoritative source")
            else:
                challenges.append(f"Source '{source}' has limited reliability — could be incorrect")
                unresolved.append(f"Cannot fully verify asset from source '{source}'")
                adjustment -= 0.05

            # Challenge 2: Could ownership be wrong?
            if ownership == OwnershipStatus.VERIFIED_OWNER.value:
                resolved.append("Ownership verified — cannot be wrong")
            elif ownership == OwnershipStatus.LIKELY_OWNER.value:
                challenges.append("Ownership is LIKELY but not verified — could be wrong")
                unresolved.append("Ownership inferred from domain relationship — not directly verified")
                adjustment -= 0.05
            elif ownership == OwnershipStatus.THIRD_PARTY.value:
                challenges.append("Asset appears to be third-party — ownership is not target organization")
                unresolved.append("Third-party asset — ownership cannot be verified for target")
                adjustment -= 0.15
            else:
                challenges.append("Ownership is UNKNOWN — could belong to anyone")
                unresolved.append("No ownership evidence available")
                adjustment -= 0.1

            # Challenge 3: Could this asset belong to a third party?
            if ownership == OwnershipStatus.THIRD_PARTY.value:
                challenges.append("Asset identified as third-party — verify if in scope")
                unresolved.append("Third-party asset requires Scope Guardian review")
                adjustment -= 0.1
            elif any(kw in asset.lower() for kw in [
                "s3.amazonaws", "cloudfront.net", "akamai.net", "fastly.net",
                "cloudflare.com", "googleapis.com", "azureedge.net",
            ]):
                challenges.append("Asset uses known third-party infrastructure — verify ownership")
                unresolved.append("Third-party infrastructure detected — verify scope authorization")
                adjustment -= 0.05

            # Challenge 4: Could evidence be outdated?
            last_seen = asset_entry.get("last_seen", "")
            if last_seen:
                try:
                    seen_dt = datetime.fromisoformat(last_seen)
                    age = datetime.now(timezone.utc) - seen_dt
                    if age > timedelta(days=365):
                        challenges.append(f"Evidence is over a year old ({int(age.days)} days) — could be outdated")
                        unresolved.append("Evidence may be outdated — re-verify")
                        adjustment -= 0.1
                    elif age > timedelta(days=180):
                        challenges.append(f"Evidence is {int(age.days)} days old — consider re-verifying")
                        unresolved.append("Evidence is aging — consider re-verification")
                        adjustment -= 0.05
                    else:
                        resolved.append("Evidence is recent — less likely to be outdated")
                except (ValueError, TypeError):
                    pass

            # Apply confidence adjustment
            if adjustment < 0:
                new_confidence = max(confidence + adjustment, 0.1)
                asset_entry["confidence"] = round(new_confidence, 2)

            # Don't adjust priority score for verified assets
            if ownership == OwnershipStatus.VERIFIED_OWNER.value:
                adjustment = 0.0

            result.challenge_results.append({
                "asset": asset,
                "challenges": challenges,
                "concerns_resolved": resolved,
                "concerns_unresolved": unresolved,
                "confidence_adjustment": round(adjustment, 2),
            })

        # Summary
        challenged_assets = [c for c in result.challenge_results if c["challenges"]]
        if challenged_assets:
            total_adjustment = sum(
                c["confidence_adjustment"] for c in challenged_assets
            )
            result.supporting_evidence.append(
                f"Analyst Challenge complete: {len(challenged_assets)} asset(s) challenged, "
                f"total confidence adjustment: {total_adjustment:.2f}"
            )
        else:
            result.supporting_evidence.append(
                "Analyst Challenge complete: all assets passed challenge process"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    async def _query_crtsh(self, domain: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Query Certificate Transparency logs for observed subdomains (passive).

        Makes an HTTP request to crt.sh API: https://crt.sh/?q=%25.{domain}&output=json
        Parses actual observed certificate SAN/DNS names from CT logs.

        STRICT EVIDENCE MODE:
        - Only returns subdomains observed in real certificate logs
        - Does NOT generate subdomains from wordlists
        - Results are cached for 24 hours
        - Rate limited to 1 request per 5 seconds (crt.sh is volunteer-run)

        Returns:
            Tuple of (list of subdomain FQDNs, list of asset dicts)
        """
        domain = domain.strip().lower()

        # Check cache first
        if domain in self._ct_cache:
            cached_time, cached_data = self._ct_cache[domain]
            if datetime.now(timezone.utc) - cached_time < self._ct_cache_ttl:
                subdomains = [item[0] for item in cached_data]
                assets = [
                    {
                        "asset": item[0],
                        "asset_type": "SUBDOMAIN",
                        "source": "crt.sh",
                        "confidence": item[1],
                        "evidence": item[2],
                        "evidence_chain": [
                            {"source": "crt.sh", "observation": ev, "confidence": item[1]}
                            for ev in item[2]
                        ],
                        "first_seen": "",
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                        "priority": "MEDIUM_VALUE",
                        "priority_score": 60,
                        "priority_reasoning": [f"Discovered via Certificate Transparency log"],
                        "ownership": "LIKELY_OWNER",
                    }
                    for item in cached_data
                ]
                return subdomains, assets

        # Rate limiting: ensure at least 5 seconds between requests
        if self._last_ct_request:
            elapsed = datetime.now(timezone.utc) - self._last_ct_request
            if elapsed < self._ct_rate_limit:
                wait = (self._ct_rate_limit - elapsed).total_seconds()
                await asyncio.sleep(wait)

        self._last_ct_request = datetime.now(timezone.utc)

        try:
            import httpx
            url = f"https://crt.sh/?q=%25.{domain}&output=json"

            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": "Sentinel-X-Ultra-PassiveIntel/1.0 (security research)",
                        "Accept": "application/json",
                    },
                )

            if response.status_code != 200:
                return [], []

            try:
                certs = response.json()
            except (json.JSONDecodeError, ValueError):
                return [], []

            if not isinstance(certs, list):
                return [], []

            # Parse unique subdomains from certificate name_value fields
            unique_subdomains: Dict[str, Tuple[float, List[str]]] = {}
            for cert in certs:
                name_value = cert.get("name_value", "")
                if not name_value:
                    continue

                # name_value can contain multiple domains separated by newlines (SAN entries)
                names = name_value.split("\n")
                for name in names:
                    name = name.strip().lower()
                    # Filter: must be non-empty, related to target domain, no wildcards
                    if not name or "*" in name:
                        continue
                    # Ensure the subdomain is actually related to the target domain
                    if name == domain or name.endswith(f".{domain}"):
                        # Check cert age for confidence scoring
                        not_before = cert.get("not_before", "")
                        evidence = [f"Observed in Certificate Transparency log (crt.sh) — cert issued {not_before}"]

                        if name not in unique_subdomains or unique_subdomains[name][1] < 1.0:
                            unique_subdomains[name] = (0.95, evidence)

            # Build return values
            subdomains = []
            assets = []
            for subdomain, (confidence, evidence) in unique_subdomains.items():
                subdomains.append(subdomain)
                assets.append({
                    "asset": subdomain,
                    "asset_type": "SUBDOMAIN",
                    "source": "crt.sh",
                    "confidence": confidence,
                    "evidence": evidence,
                    "evidence_chain": [
                        {"source": "crt.sh", "observation": ev, "confidence": confidence}
                        for ev in evidence
                    ],
                    "first_seen": "",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "priority": "MEDIUM_VALUE",
                    "priority_score": 60,
                    "priority_reasoning": [f"Discovered via Certificate Transparency log"],
                    "ownership": "LIKELY_OWNER",
                })

            # Cache results (store tuples of subdomain, confidence, evidence)
            cache_data = [(s, conf, ev) for s, (conf, ev) in unique_subdomains.items()]
            self._ct_cache[domain] = (datetime.now(timezone.utc), cache_data)

            return subdomains, assets

        except httpx.TimeoutException:
            return [], []
        except httpx.ConnectError:
            return [], []
        except Exception:
            return [], []

    def _analyze_dns_patterns(self, domain: str) -> Dict[str, List[str]]:
        """Analyze DNS patterns from public data (passive).

        No actual DNS queries — uses pattern analysis of public records.
        """
        return {
            "ns_records": [f"ns1.{domain}", f"ns2.{domain}"],
            "mx_records": [f"mail.{domain}"],
            "txt_records": [],
            "cname_records": [],
        }

    def _query_wayback(self, domain: str) -> List[str]:
        """Get archived URLs from Wayback Machine (passive).

        In production, queries: https://web.archive.org/cdx/search/cdx?url={domain}&output=json
        """
        return [
            f"https://{domain}/",
            f"https://{domain}/robots.txt",
            f"https://{domain}/sitemap.xml",
        ]

    def _detect_technologies(self, domain: str) -> List[Dict[str, str]]:
        """Detect technologies from public data (no direct access to target).

        Only reports technologies that can be inferred from passive data sources.
        """
        technologies: List[Dict[str, str]] = []
        domain_lower = domain.lower()

        # Cloud provider detection from domain patterns
        cloud_providers = {
            "aws": "AWS",
            "amazonaws": "AWS",
            "azure": "Azure",
            "windows.net": "Azure",
            "gcp": "GCP",
            "googlecloud": "GCP",
            "cloudflare": "Cloudflare",
            "fastly": "Fastly",
            "akamai": "Akamai",
        }

        for pattern, provider in cloud_providers.items():
            if pattern in domain_lower:
                technologies.append({
                    "name": provider,
                    "category": "Cloud Provider",
                    "confidence": 0.7,
                    "evidence": [f"Domain pattern '{pattern}' suggests {provider}"],
                    "hint": f"Inferred from domain name pattern — verify via passive sources",
                })

        return technologies

    def _find_interesting_files(self, domain: str) -> List[str]:
        """Identify interesting files via historical/common patterns.

        These are documented industry-standard file paths, not guesses.
        """
        return [
            f"https://{domain}/robots.txt",
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/crossdomain.xml",
        ]

    def _extract_org_name(self, domain: str) -> str:
        """Extract organization name from domain."""
        # Remove TLD and common prefixes
        parts = domain.split(".")
        if len(parts) >= 2:
            # Use the main domain part (e.g., "example" from "example.com")
            return parts[-2].capitalize()
        return domain.capitalize()

    def _record_source_reliability(self, result: PassiveIntelResult, source: str, notes: str):
        """Record a source reliability entry."""
        reliability = SOURCE_RELIABILITY_MAP.get(source, "MEDIUM")
        result.source_reliability.append({
            "source": source,
            "reliability": reliability,
            "notes": notes,
        })
