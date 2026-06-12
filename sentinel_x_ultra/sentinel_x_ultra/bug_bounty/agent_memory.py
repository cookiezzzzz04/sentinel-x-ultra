"""
AGENT MEMORY — Cross-Agent Shared Knowledge Store (Phase 3, Upgraded).

Provides a shared, structured memory that enables agents to share findings,
avoid redundant work, and build on each other's intelligence.

Upgraded with:
- Cross-reference queries: agents can ask "what does Agent 4 know about X?"
- Context builders: generate rich context packets for each downstream agent
- Priority scoring: dynamic priority recalculation based on new data
- Provenance chains: track which agents contributed to each piece of knowledge
- Downstream guidance: build instruction packets for Agents 5-10
"""

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class MemoryEntry:
    """A single entry in the shared agent memory."""
    source_agent: str = ""
    key: str = ""
    value: Any = None
    timestamp: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceChain:
    """Tracks which agents contributed to a piece of knowledge."""
    key: str = ""
    contributors: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_updated: str = ""
    confidence: float = 0.0


class AgentMemory:
    """
    Shared memory store for all 10 bug bounty agents.

    Agents can write discoveries and read each other's findings.
    Provides deduplication, priority ordering, provenance tracking,
    and cross-agent context building.
    """

    def __init__(self):
        self._assets: Dict[str, Dict[str, Any]] = {}
        self._priority_targets: List[Dict[str, Any]] = []
        self._technologies: Dict[str, List[str]] = {}
        self._subdomains: Dict[str, Set[str]] = {}
        self._findings: List[Dict[str, Any]] = []
        self._validated_findings: List[Dict[str, Any]] = []
        self._scope_boundaries: Dict[str, str] = {}
        self._historical_urls: List[str] = []
        self._policy_rules: Dict[str, Any] = {}
        self._program_intelligence: Dict[str, Any] = {}
        self._ownership_map: Dict[str, str] = {}
        self._reconnaissance_map: Dict[str, List[str]] = {}
        self._provenance: Dict[str, ProvenanceChain] = {}
        self._history: List[MemoryEntry] = []
        self._cvss_context: Dict[str, Any] = {}
        self._exploitability_map: Dict[str, str] = {}

    # ── Write APIs ──────────────────────────────────────────────────────────

    def record_asset(self, source: str, asset_name: str, asset_type: str,
                     confidence: float, metadata: Optional[Dict] = None):
        """Record a discovered asset from any agent with provenance tracking."""
        if asset_name not in self._assets or self._assets[asset_name].get("confidence", 0) < confidence:
            self._assets[asset_name] = {
                "name": asset_name,
                "type": asset_type,
                "confidence": confidence,
                "discovered_by": source,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": metadata or {},
            }
        self._update_provenance(f"asset:{asset_name}", source, confidence)
        self._history.append(MemoryEntry(
            source_agent=source, key=f"asset:{asset_name}",
            value={"type": asset_type, "confidence": confidence},
            timestamp=datetime.now(timezone.utc).isoformat(),
        ))

    def record_priority_target(self, source: str, target: str, score: int, reason: str = ""):
        """Record a priority target for downstream scanners with dedup by higher score."""
        existing = {t["target"]: t["score"] for t in self._priority_targets}
        if target not in existing or score > existing[target]:
            if target in existing:
                self._priority_targets = [t for t in self._priority_targets if t["target"] != target]
            self._priority_targets.append({
                "target": target,
                "score": score,
                "source": source,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            self._priority_targets.sort(key=lambda x: x["score"], reverse=True)

    def record_technology(self, source: str, domain: str, technology: str):
        """Record a detected technology."""
        if domain not in self._technologies:
            self._technologies[domain] = []
        if technology not in self._technologies[domain]:
            self._technologies[domain].append(technology)
            self._update_provenance(f"tech:{domain}:{technology}", source, 0.7)

    def record_subdomain(self, source: str, domain: str, subdomain: str):
        """Record a discovered subdomain relationship."""
        if domain not in self._subdomains:
            self._subdomains[domain] = set()
        self._subdomains[domain].add(subdomain)

    def record_finding(self, source: str, finding: Dict[str, Any]):
        """Record a discovered finding from a scanner."""
        self._findings.append({
            **finding,
            "discovered_by": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._update_provenance(f"finding:{finding.get('title', 'unknown')}", source, 0.8)

    def record_validated_finding(self, source: str, finding: Dict[str, Any]):
        """Record a validated finding (passed Agent 7)."""
        self._validated_findings.append({
            **finding,
            "validated_by": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def record_scope(self, source: str, target: str, status: str):
        """Record a scope authorization result."""
        self._scope_boundaries[target] = status

    def record_ownership(self, source: str, asset: str, status: str):
        """Record ownership status for an asset."""
        self._ownership_map[asset] = status
        self._update_provenance(f"ownership:{asset}", source, 0.9 if status == "VERIFIED" else 0.5)

    def record_policy_rule(self, source: str, rule: Dict[str, Any]):
        """Record a policy enforcement rule."""
        self._policy_rules[rule.get("vuln_type", "unknown")] = rule

    def record_historical_url(self, source: str, url: str):
        """Record a historical URL from OSINT."""
        if url not in self._historical_urls:
            self._historical_urls.append(url)

    def record_program_intel(self, source: str, intel: Dict[str, Any]):
        """Record program intelligence from Agent 1."""
        self._program_intelligence = {**self._program_intelligence, **intel}

    def record_reconnaissance(self, source: str, targets: List[str]):
        """Record which sources discovered which targets (for provenance)."""
        if source not in self._reconnaissance_map:
            self._reconnaissance_map[source] = []
        for t in targets:
            if t not in self._reconnaissance_map[source]:
                self._reconnaissance_map[source].append(t)

    def record_cvss_context(self, source: str, context: Dict[str, Any]):
        """Record CVSS scoring context from Agent 9."""
        self._cvss_context.update(context)

    def record_exploitability(self, source: str, target: str, rating: str):
        """Record exploitability rating for a target."""
        self._exploitability_map[target] = rating

    def _update_provenance(self, key: str, source: str, confidence: float):
        """Update the provenance chain for a knowledge item."""
        now = datetime.now(timezone.utc).isoformat()
        if key not in self._provenance:
            self._provenance[key] = ProvenanceChain(
                key=key, contributors=[], first_seen=now, confidence=confidence,
            )
        chain = self._provenance[key]
        if source not in chain.contributors:
            chain.contributors.append(source)
        chain.last_updated = now
        chain.confidence = max(chain.confidence, confidence)

    def get_provenance(self, key: str) -> Optional[ProvenanceChain]:
        """Get the provenance chain for a knowledge item."""
        return self._provenance.get(key)

    # ── Cross-Reference Queries ─────────────────────────────────────────────

    def query_by_agent(self, agent_name: str) -> Dict[str, Any]:
        """Get ALL knowledge contributed by a specific agent.
        
        Useful for cross-referencing: "what did Agent 4 discover?"
        """
        results = {
            "assets": [],
            "technologies": [],
            "findings": [],
            "subdomains": [],
            "priority_targets": [],
        }
        for asset_name, asset in self._assets.items():
            if asset.get("discovered_by") == agent_name:
                results["assets"].append(asset)
        for domain, techs in self._technologies.items():
            # Check provenance for techs from this agent
            for tech in techs:
                prov = self.get_provenance(f"tech:{domain}:{tech}")
                if prov and agent_name in prov.contributors:
                    results["technologies"].append({"domain": domain, "technology": tech})
        for finding in self._findings:
            if finding.get("discovered_by") == agent_name:
                results["findings"].append(finding)
        return results

    def query_by_target(self, target: str) -> Dict[str, Any]:
        """Get ALL knowledge related to a specific target.
        
        Useful for: "what do we know about example.com?"
        """
        results = {
            "scope_status": self.get_scope_status(target),
            "ownership": self.get_ownership(target),
            "technologies": self.get_technologies(target),
            "subdomains": self.get_subdomains(target),
            "findings": [],
            "exploitability": self._exploitability_map.get(target, "UNKNOWN"),
        }
        for finding in self._findings:
            if target in str(finding.get("target", "")) or target in str(finding.get("endpoint", "")):
                results["findings"].append(finding)
        return results

    def get_attack_surface_summary(self, domain: str) -> Dict[str, Any]:
        """Build a complete attack surface summary for a domain.
        
        Combines: subdomains, technologies, priority targets, findings,
        scope, ownership, and historical URLs into one packet.
        """
        return {
            "domain": domain,
            "subdomains": self.get_subdomains(domain),
            "technologies": self.get_technologies(domain),
            "priority_targets": self.get_priority_targets(min_score=50),
            "active_findings": [f for f in self._findings if domain in str(f.get("target", ""))],
            "validated_findings": [f for f in self._validated_findings if domain in str(f.get("target", ""))],
            "scope": self.get_scope_status(domain),
            "ownership": self.get_ownership(domain),
            "historical_urls": self._historical_urls[:20],
            "asset_count": len([a for a in self._assets if domain in a]),
            "provenance": {k: v.contributors for k, v in self._provenance.items() if domain in k},
        }

    # ── Downstream Context Builders ─────────────────────────────────────────

    def build_context_for_agent_5(self, domain: str) -> Dict[str, Any]:
        """Build context packet for Agent 5 (Active Enumeration).
        
        Includes: high-confidence assets, priority targets, technologies,
        subdomains already known, scope boundaries.
        """
        return {
            "domain": domain,
            "known_subdomains": self.get_subdomains(domain),
            "technologies": self.get_technologies(domain),
            "priority_targets": self.get_priority_targets(min_score=60),
            "high_confidence_assets": self.get_assets(min_confidence=0.8),
            "scope_status": self.get_scope_status(domain),
            "source_agents": self._provenance.get(f"asset:{domain}", ProvenanceChain()).contributors,
        }

    def build_context_for_agent_6(self, domain: str) -> Dict[str, Any]:
        """Build context packet for Agent 6 (Vulnerability Scanner).
        
        Includes: priority targets, known technologies, historical vulns,
        endpoints from passive intel, attack surface classifications.
        """
        return {
            "domain": domain,
            "priority_targets": self.get_priority_targets(min_score=70),
            "technologies": self.get_technologies(domain),
            "known_findings": [f for f in self._findings if domain in str(f.get("target", ""))],
            "known_scope": self.get_scope_status(domain),
            "historical_vulnerability_types": list(set(
                f.get("test_type", f.get("type", "")) for f in self._findings
                if f.get("vulnerable", False)
            )),
        }

    def build_context_for_agent_7(self, finding_id: str) -> Dict[str, Any]:
        """Build context packet for Agent 7 (Validation Engine).
        
        Includes: related findings, scope context, policy rules.
        """
        finding = next((f for f in self._findings if f.get("id") == finding_id), {})
        target = str(finding.get("target", ""))
        return {
            "finding": finding,
            "scope_status": self.get_scope_status(target),
            "ownership": self.get_ownership(target),
            "related_findings": [f for f in self._findings if f.get("target") == target][:5],
            "policy_rules": dict(self._policy_rules),
        }

    def build_context_for_agent_8(self, finding_id: str) -> Dict[str, Any]:
        """Build context packet for Agent 8 (Exploitation).
        
        Includes: validated finding, analysis context, CVSS context.
        """
        validated = next((f for f in self._validated_findings if f.get("id") == finding_id), {})
        return {
            "finding": validated,
            "cvss_context": dict(self._cvss_context),
            "exploitability": self._exploitability_map.get(validated.get("target", ""), "UNKNOWN"),
        }

    def build_context_for_agent_9(self, finding_id: str) -> Dict[str, Any]:
        """Build context packet for Agent 9 (Analysis).
        
        Includes: historical CVSS scores for similar findings,
        exploitability context, technology stack.
        """
        return {
            "cvss_history": dict(self._cvss_context),
            "exploitability_map": dict(self._exploitability_map),
            "related_validated": [
                f for f in self._validated_findings
                if f.get("type") == next(
                    (vf.get("type") for vf in self._validated_findings if vf.get("id") == finding_id),
                    None
                )
            ][:5],
        }

    def build_context_for_agent_10(self, project_id: str = "") -> Dict[str, Any]:
        """Build context packet for Agent 10 (Report Generation).
        
        Includes: all validated findings, analysis results, PoC details,
        scope and policy context for the complete report.
        """
        return {
            "total_findings": len(self._validated_findings),
            "findings": list(self._validated_findings[-20:]),
            "policy_rules": dict(self._policy_rules),
            "program_intel": dict(self._program_intelligence),
            "all_assets": list(self._assets.values()),
            "all_priority_targets": self._priority_targets[:10],
            "provenance_summary": {k: v.contributors for k, v in self._provenance.items()},
        }

    # ── Read APIs ───────────────────────────────────────────────────────────

    def get_assets(self, min_confidence: float = 0.0) -> List[Dict[str, Any]]:
        return [a for a in self._assets.values() if a["confidence"] >= min_confidence]

    def get_priority_targets(self, min_score: int = 0) -> List[Dict[str, Any]]:
        return [t for t in self._priority_targets if t["score"] >= min_score]

    def get_technologies(self, domain: str = "") -> Dict[str, List[str]]:
        if domain:
            return {domain: self._technologies.get(domain, [])}
        return dict(self._technologies)

    def get_subdomains(self, domain: str) -> List[str]:
        return list(self._subdomains.get(domain, set()))

    def get_all_subdomains(self) -> Dict[str, List[str]]:
        return {d: list(s) for d, s in self._subdomains.items()}

    def get_findings(self, status: str = "") -> List[Dict[str, Any]]:
        if status:
            return [f for f in self._findings if f.get("status") == status]
        return list(self._findings)

    def get_validated_findings(self) -> List[Dict[str, Any]]:
        return list(self._validated_findings)

    def get_scope_status(self, target: str) -> str:
        return self._scope_boundaries.get(target, "UNCLEAR")

    def get_ownership(self, asset: str) -> str:
        return self._ownership_map.get(asset, "UNKNOWN_OWNER")

    def get_historical_urls(self) -> List[str]:
        return list(self._historical_urls)

    def get_program_intel(self) -> Dict[str, Any]:
        return dict(self._program_intelligence)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "assets_count": len(self._assets),
            "priority_targets_count": len(self._priority_targets),
            "technologies_count": sum(len(v) for v in self._technologies.values()),
            "subdomains_count": sum(len(v) for v in self._subdomains.values()),
            "findings_count": len(self._findings),
            "validated_findings_count": len(self._validated_findings),
            "historical_urls_count": len(self._historical_urls),
            "scope_entries_count": len(self._scope_boundaries),
            "ownership_entries_count": len(self._ownership_map),
            "reconnaissance_sources": len(self._reconnaissance_map),
            "provenance_chains": len(self._provenance),
            "last_updated": self._history[-1].timestamp if self._history else "",
        }
