"""
BUG BOUNTY ORCHESTRATOR — Full 10-Agent Pipeline.

Orchestrates the complete bug bounty workflow:
1. URL Parser → 2. Policy Enforcer → 3. Scope Guardian
4. Passive Intel → 5. Active Enum → 6. Vuln Scanner
7. Validation Engine → 8. Exploitation → 9. Analysis → 10. Report Generation
"""

import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..agent_tool_integration import get_agent_tool_integration
from .active_enum import ActiveEnumerationAgent, ActiveEnumResult
from .agent_memory import AgentMemory
from .analysis import AnalysisAgent, FindingAnalysis
from .data_sources import DataSourceAggregator
from .execution_engine import (
    get_parallel_executor,
    get_rate_limiter,
    get_result_cache,
    get_timeout_manager,
)
from .exploitation import ExploitationAgent, ProofOfConcept
from .llm_provider import LLMProvider, get_llm_provider
from .passive_intel import PassiveIntelligenceAgent, PassiveIntelResult
from .policy_enforcer import PolicyEnforcerAgent, PolicyRule
from .report_generation import ReportGenerationAgent, VulnerabilityReport
from .scope_guardian import (
    ScopeCheckResult,
    ScopeGuardianAgent,
)
from .security_guard import (
    get_ethical_guard,
    get_output_sanitizer,
    get_resource_limiter,
    get_scope_validator,
)
from .system_prompts import AGENT_ARCHITECTURE, DECISION_HIERARCHY, FOUNDATIONAL_PRINCIPLES
from .url_parser import AssetEntry, ProgramIntelligence, URLParserAgent
from .validation_engine import ValidationEngineAgent, ValidationResult
from .vuln_scanner import TestResult, VulnerabilityScannerAgent
from .webhook import WebhookManager


@dataclass
class BugBountyPipelineResult:
    """Complete result of running all 10 agents."""
    pipeline_id: str = ""
    program_intel: ProgramIntelligence | None = None
    policy_rules: list[PolicyRule] = field(default_factory=list)
    policy_decisions: list[dict[str, Any]] = field(default_factory=list)
    scope_results: list[ScopeCheckResult] = field(default_factory=list)
    scope_authorizations: list[dict[str, Any]] = field(default_factory=list)
    passive_intel: list[PassiveIntelResult] = field(default_factory=list)
    active_enum: list[ActiveEnumResult] = field(default_factory=list)
    scan_results: list[TestResult] = field(default_factory=list)
    validation_results: list[ValidationResult] = field(default_factory=list)
    proofs_of_concept: list[ProofOfConcept] = field(default_factory=list)
    analyses: list[FindingAnalysis] = field(default_factory=list)
    reports: list[VulnerabilityReport] = field(default_factory=list)
    file_findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    ethical_rules_applied: bool = True
    downstream_guidance: dict[str, Any] = field(default_factory=dict)


class BugBountyOrchestrator:
    """
    Orchestrates all 10 bug bounty agents with the foundational principles
    and decision hierarchy baked into every step.

    AI-POWERED UPGRADE (Phase 1):
    - All agents now have access to an LLMProvider for AI reasoning
    - Replaces hardcoded heuristics with real LLM-powered analysis
    - Supports OpenAI, Claude, Ollama providers

    REAL TOOL INTEGRATION (Phase 2):
    - Agents 4, 5, 6 call real tools via AgentToolIntegration
    - 30 security tools available: nmap, httpx, nuclei, sqlmap, etc.
    """

    def __init__(self, webhook_manager: WebhookManager | None = None, llm_provider: LLMProvider | None = None):
        self.webhook_manager = webhook_manager
        self.llm_provider = llm_provider or get_llm_provider()
        self.memory = AgentMemory()  # Phase 3: Cross-agent shared memory

        # Phase 6: Execution infrastructure — must be created before DataSourceAggregator
        self.executor = get_parallel_executor(max_concurrency=10)
        self.cache = get_result_cache(default_ttl=600.0)
        self.rate_limiter = get_rate_limiter(tokens_per_second=20.0)
        self.timeout_manager = get_timeout_manager(default_timeout=60.0)

        # Phase 4: Live external APIs with shared cache (depends on Phase 6 cache)
        self.data_sources = DataSourceAggregator(cache=self.cache)

        # Phase 7: Security infrastructure
        self.scope_validator = get_scope_validator()
        self.sanitizer = get_output_sanitizer(mode="MODERATE")
        self.ethical_guard = get_ethical_guard(fail_on_violation=False)
        self.resource_limiter = get_resource_limiter()

        # All agents now receive the LLM provider for AI reasoning
        self.agent_1 = URLParserAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_2 = PolicyEnforcerAgent(webhook_manager=webhook_manager, llm_provider=self.llm_provider, memory=self.memory)
        self.agent_3 = ScopeGuardianAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_4 = PassiveIntelligenceAgent(llm_provider=self.llm_provider, memory=self.memory, data_sources=self.data_sources)
        self.agent_5 = ActiveEnumerationAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_6 = VulnerabilityScannerAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_7 = ValidationEngineAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_8 = ExploitationAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_9 = AnalysisAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.agent_10 = ReportGenerationAgent(llm_provider=self.llm_provider, memory=self.memory)
        self.system_prompt = self._build_system_prompt()
        self.ethical_rules = self._build_ethical_rules()

    def _build_system_prompt(self) -> str:
        """Build the complete system prompt for all agents."""
        return "\n\n".join([
            FOUNDATIONAL_PRINCIPLES,
            DECISION_HIERARCHY,
            AGENT_ARCHITECTURE,
        ])

    def _build_ethical_rules(self) -> list[str]:
        """Build the ethical rules that govern all agent actions."""
        return [
            "NEVER test unauthorized targets",
            "NEVER cause service disruption or data loss",
            "NEVER exfiltrate user data",
            "ALWAYS operate read-only",
            "ALWAYS verify scope before any action",
            "ALWAYS validate findings before reporting",
            "Scope is law — if not in-scope, it's out-of-scope",
            "Quality over quantity — validate every finding",
        ]

    async def run_pipeline(
        self,
        target_url: str = "",
        target_domain: str = "",
        in_scope: list[str] | None = None,
        out_of_scope: list[str] | None = None,
        project_id: str | None = None,
        folder_files: dict[str, str] | None = None,
    ) -> BugBountyPipelineResult:
        """Run the complete 10-agent bug bounty pipeline."""
        result = BugBountyPipelineResult(
            pipeline_id=str(uuid.uuid4()),
            started_at=datetime.utcnow().isoformat(),
        )

        try:
            # Store folder files on orchestrator for agent access
            self.folder_files = folder_files or {}
            self._project_id = project_id

            # Phase 1: Program Intelligence (Agents 1-3)
            if target_url:
                result.program_intel = await self._run_agent_1(target_url)
                if result.program_intel:
                    self._run_agent_2(result)
                    self._run_agent_3_from_intel(result)

            # Phase 2: Reconnaissance (Agents 4-5)
            targets = [target_domain] if target_domain else []
            if not targets and result.program_intel:
                targets = result.program_intel.in_scope_domains[:5]

            for target in targets:
                in_scope_targets = self._check_scope(target, in_scope or [], out_of_scope or [])
                if in_scope_targets:
                    intel = await self._run_agent_4(target)
                    result.passive_intel.append(intel)
                    enum = await self._run_agent_5(target)
                    result.active_enum.append(enum)

            # Apply OSINT downstream guidance from passive intelligence
            self._apply_osint_downstream_guidance(result)

            # Run the 12-phase Scope Authorization on all targets
            self._authorize_targets(result)

            # Phase 3: Vulnerability Testing (Agent 6)
            # Aggregated scanning: once a vulnerability type is found on any endpoint,
            # skip it on subsequent endpoints to prevent 89 identical findings.
            found_vuln_types = set()
            for enum_result in result.active_enum:
                for endpoint in enum_result.endpoints:
                    # Only test vulnerability types not yet found on previous endpoints
                    remaining_types = None if not found_vuln_types else [
                        t for t in ["sql_injection", "xss", "idor", "ssrf", "auth_bypass",
                                    "command_injection", "ssti", "path_traversal", "xxe",
                                    "open_redirect", "csrf", "business_logic",
                                    "information_disclosure", "privilege_escalation"]
                        if t not in found_vuln_types
                    ]
                    if remaining_types is not None and not remaining_types:
                        continue  # All types already found, skip this endpoint
                    test_results = await self._run_agent_6(endpoint.path, test_types=remaining_types)
                    result.scan_results.extend(test_results)
                    for t in test_results:
                        if t.vulnerable:
                            found_vuln_types.add(t.test_type)

            # Evaluate all findings through Agent 2's Policy Decision Engine (12-phase pipeline)
            self._evaluate_findings(result)

            # Phase 4: Validation & Exploitation (Agents 7-8)
            for test in result.scan_results:
                if test.vulnerable:
                    finding = {
                        "id": str(uuid.uuid4()),
                        "title": test.description,
                        "type": test.test_type,
                        "target": test.target,
                        "severity": test.severity,
                        "description": test.description,
                        "evidence": test.evidence,
                        "cwe_ids": test.cwe_ids,
                        "owasp_category": test.owasp_category,
                        "confidence": test.confidence,
                        "prerequisites": "None documented",
                        "reproduction_steps": [f"Send {test.test_type} payload to {test.target}"],
                    }
                    validation = await self._run_agent_7(finding)
                    result.validation_results.append(validation)
                    if validation.decision == "PROMOTE":
                        poc = await self._run_agent_8(finding)
                        result.proofs_of_concept.append(poc)

            # Phase 5: Analysis & Reporting (Agents 9-10)
            for poc in result.proofs_of_concept:
                analysis = await self._run_agent_9(poc)
                result.analyses.append(analysis)
                finding = {
                    "title": poc.title,
                    "endpoint": "",
                    "description": poc.impact_demonstration,
                    "validation_status": "PROMOTE",
                    "scope_status": "ALLOW",
                    "policy_status": "ALLOW",
                }
                report = await self._run_agent_10(finding, analysis, poc)
                result.reports.append(report)

            # Scan folder files for security issues (API keys, secrets, vulnerable patterns)
            if self.folder_files:
                result.file_findings = self._scan_folder_files(self.folder_files)

        except Exception as e:
            result.errors.append(f"Pipeline error: {e!s}")

        result.completed_at = datetime.utcnow().isoformat()

        # Fire pipeline completion webhook (non-blocking)
        if self.webhook_manager:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(self._fire_pipeline_completed_webhook(result))
                else:
                    loop.run_until_complete(self._fire_pipeline_completed_webhook(result))
            except (RuntimeError, Exception):
                pass

        return result

    async def _fire_pipeline_completed_webhook(self, result: BugBountyPipelineResult):
        """Fire a webhook for pipeline completion (async)."""
        if not self.webhook_manager:
            return
        summary = self.get_summary(result)
        await self.webhook_manager.fire_pipeline_completed(
            pipeline_id=result.pipeline_id,
            summary=summary,
            policy_decisions=result.policy_decisions,
        )

    async def _run_agent_1(self, url: str) -> ProgramIntelligence | None:
        """Agent 1: Parse program URL using AI-powered intelligence.

        Phase 1 Upgrade: Uses LLMProvider for advanced program analysis
        when page content is available. Falls back to regex extraction.
        """
        try:
            result = await self.agent_1.parse(url)
            # If we have raw content and LLM is available, enhance with AI analysis
            if result.raw_content and self.llm_provider and self.llm_provider.is_available:
                try:
                    ai_analysis = await self.llm_provider.analyze_program(url, result.raw_content)
                    if ai_analysis:
                        # Merge AI findings into the intelligence profile
                        result.program_name = ai_analysis.get("program_name", result.program_name)
                        result.organization = ai_analysis.get("organization", result.organization)
                        result.extraction_confidence = "HIGH" if ai_analysis.get("status") else result.extraction_confidence
                        # Add AI-discovered assets
                        ai_assets = ai_analysis.get("assets", [])
                        if ai_assets:
                            existing = set(a.identifier for a in result.assets)
                            for asset_data in ai_assets:
                                if isinstance(asset_data, dict) and asset_data.get("identifier") not in existing:
                                    result.assets.append(AssetEntry(
                                        identifier=asset_data.get("identifier", ""),
                                        asset_type=asset_data.get("asset_type", "domain"),
                                        scope_status=asset_data.get("scope_status", "UNCLEAR"),
                                        confidence=float(asset_data.get("confidence", 50)),
                                    ))
                                    if asset_data.get("scope_status") == "IN_SCOPE":
                                        result.in_scope_domains.append(asset_data.get("identifier", ""))
                        # Add AI findings to metadata
                        result.errors.append(f"AI enhanced: {self.llm_provider.provider_name}")
                except Exception as e:
                    result.errors.append(f"AI analysis enhancement failed: {str(e)[:80]}")
            return result
        finally:
            await self.agent_1.close()

    def _run_agent_2(self, result: BugBountyPipelineResult):
        """Agent 2: Enforce policy using the full 12-phase Policy Decision Engine.
        Loads program policy and evaluates all findings from scan results.
        """
        if result.program_intel:
            self.agent_2.load_program_policy(result.program_intel)
            result.policy_rules = self.agent_2.custom_rules

    async def _evaluate_findings(self, result: BugBountyPipelineResult):
        """Run the 12-phase Policy Decision Engine on all scan findings.
        Phase 5 Deep: Now async with LLM-powered decision phases.
        Stores ALLOW/REVIEW/REJECT decisions and detailed output.
        """
        result.policy_decisions = []
        for test in result.scan_results:
            if not test.vulnerable:
                continue
            finding = {
                "title": getattr(test, 'description', 'Unknown finding'),
                "type": getattr(test, 'test_type', 'unknown'),
                "target": getattr(test, 'target', ''),
                "endpoint": getattr(test, 'endpoint', ''),
                "severity": getattr(test, 'severity', 'medium'),
                "description": getattr(test, 'description', ''),
                "evidence": getattr(test, 'evidence', {}),
                "impact": getattr(test, 'impact', ''),
                "reproduction_steps": getattr(test, 'reproduction_steps', []),
            }
            decision = await self.agent_2.evaluate(finding)
            result.policy_decisions.append({
                "finding_title": finding["title"],
                "finding_type": finding["type"],
                "decision": decision.decision.value,
                "confidence": decision.confidence,
                "compliance_score": decision.program_compliance_score,
                "scope_status": decision.scope_status,
                "evidence_tier": decision.evidence_tier,
                "impact_status": decision.impact_status,
                "duplicate_risk": decision.duplicate_risk,
                "vulnerability_eligibility": decision.vulnerability_eligibility,
                "policy_citations": decision.policy_citations,
                "supporting_evidence": decision.supporting_evidence,
                "rejection_arguments": decision.rejection_arguments,
                "triager_assessment": decision.triager_assessment,
                "uncertainties": decision.uncertainties,
                "assumptions": decision.assumptions,
                "reasoning": decision.reasoning,
                "recommended_next_action": decision.recommended_next_action,
            })

    def _run_agent_3_from_intel(self, result: BugBountyPipelineResult):
        """Agent 3: Set up scope from program intel."""
        if result.program_intel:
            self.agent_3.set_scope(
                in_scope=result.program_intel.in_scope_domains,
                out_of_scope=result.program_intel.out_of_scope_domains,
            )
            # Also set program-level metadata for richer authorization
            self.agent_3.set_program_scope(
                owned_domains=result.program_intel.in_scope_domains,
            )

    def _check_scope(self, target: str, in_scope: list[str], out_of_scope: list[str]) -> bool:
        """Check if target is in scope (Agent 3 integration)."""
        self.agent_3.set_scope(in_scope=in_scope, out_of_scope=out_of_scope)
        check = self.agent_3.check_target(target)
        return check.in_scope

    def _authorize_targets(self, result: BugBountyPipelineResult):
        """Run the 12-phase Scope Authorization Engine on all discovered targets.
        Uses agent_3.authorize() to produce ALLOW/REVIEW/BLOCK decisions with
        the full authorization output schema.
        """
        result.scope_authorizations = []
        targets_to_authorize = set()

        # Collect targets from passive intel
        for intel in result.passive_intel:
            if hasattr(intel, 'target') and intel.target:
                targets_to_authorize.add(intel.target)
            if hasattr(intel, 'domains'):
                for d in intel.domains:
                    targets_to_authorize.add(d)
            if hasattr(intel, 'subdomains'):
                for s in intel.subdomains:
                    targets_to_authorize.add(s)

        # Collect targets from active enumeration
        for enum in result.active_enum:
            if hasattr(enum, 'target') and enum.target:
                targets_to_authorize.add(enum.target)
            if hasattr(enum, 'endpoints'):
                for ep in enum.endpoints:
                    ep_target = getattr(ep, 'target', getattr(ep, 'host', getattr(ep, 'path', '')))
                    if ep_target:
                        targets_to_authorize.add(ep_target)
            if hasattr(enum, 'subdomains'):
                for s in enum.subdomains:
                    targets_to_authorize.add(s)

        # Also authorize targets from program intel
        if result.program_intel:
            for d in result.program_intel.in_scope_domains:
                targets_to_authorize.add(d)

        # Run the 12-phase authorization for each unique target
        for target in sorted(targets_to_authorize):
            if not target:
                continue
            auth = self.agent_3.authorize(target)
            result.scope_authorizations.append({
                "target": target,
                "decision": auth.decision.value,
                "authorized": auth.authorized,
                "authorization_confidence": auth.authorization_confidence,
                "ownership_status": auth.ownership_status,
                "scope_status": auth.scope_status,
                "asset_type": auth.asset_type,
                "matched_scope_rule": auth.matched_scope_rule,
                "matched_policy_rule": auth.matched_policy_rule,
                "risk_of_misauthorization": auth.risk_of_misauthorization,
                "allowed_actions": auth.allowed_actions,
                "restricted_actions": auth.restricted_actions,
                "prohibited_actions": auth.prohibited_actions,
                "path_restrictions": auth.path_restrictions,
                "policy_restrictions": auth.policy_restrictions,
                "contradictions": auth.contradictions,
                "uncertainties": auth.uncertainties,
                "supporting_evidence": auth.supporting_evidence,
                "reasoning": auth.reasoning,
                "recommended_next_action": auth.recommended_next_action,
            })

    async def _run_agent_4(self, target: str) -> PassiveIntelResult:
        """Agent 4: Passive intelligence with full 14-phase OSINT analysis.
        Uses all available passive tools (Amass, Sublist3r, Knockpy, dnscan, gau, waybackurls, subfinder)
        via AgentToolIntegration and feeds real tool results into AI reasoning.

        Phase 3: Writes results to shared AgentMemory so downstream agents (5-10)
        can benefit from upstream OSINT intelligence.

        Phase 4: Enriches OSINT with external data sources (Shodan, Censys, SecurityTrails, URLScan)."""
        integration = get_agent_tool_integration()

        # Rate-limit external tool API calls
        wait = await self.rate_limiter.acquire(tokens=2.0)
        if wait > 0:
            await asyncio.sleep(wait)
        tool_report = await integration.run_for_agent_4(target)

        wait = await self.rate_limiter.acquire(tokens=1.0)
        if wait > 0:
            await asyncio.sleep(wait)
        result = await self.agent_4.gather(target)

        # Phase 2: Feed real tool results into AI reasoning context
        tool_data = tool_report.to_dict() if hasattr(tool_report, 'to_dict') else {}
        result.tool_integration_findings = tool_data
        result.tools_executed = len(tool_report.tools_executed)
        result.tool_findings_count = tool_report.total_findings

        # Provide tool execution details to AI reasoning
        tool_details = []
        for te in tool_report.tools_executed:
            tool_details.append({
                "tool": te.tool_name,
                "findings_count": len(te.findings),
                "execution_time": getattr(te, 'execution_time', 0),
                "status": getattr(te, 'status', 'unknown'),
            })
        result.downstream_guidance["tool_execution_details"] = tool_details

        # Phase 3: Write Agent 4 results to shared memory for downstream agents
        if self.memory:
            try:
                # Record discovered assets
                for asset_entry in result.assets:
                    self.memory.record_asset(
                        source="agent_4",
                        asset_name=asset_entry.get("asset", ""),
                        asset_type=asset_entry.get("asset_type", "UNKNOWN"),
                        confidence=asset_entry.get("confidence", 0.5),
                        metadata={"evidence": asset_entry.get("evidence", [])[:3]},
                    )
                # Record priority targets
                for target_name in result.recommended_priority_targets:
                    self.memory.record_priority_target(
                        source="agent_4", target=target_name, score=70,
                    )
                # Record subdomains in memory
                for sub in result.subdomains:
                    self.memory.record_subdomain("agent_4", target, sub)
                # Record historical URLs
                for url in result.archived_urls:
                    self.memory.record_historical_url("agent_4", url)
                # Record ownership
                for asset_entry in result.assets:
                    ownership = asset_entry.get("ownership", "UNKNOWN_OWNER")
                    self.memory.record_ownership("agent_4", asset_entry.get("asset", ""), ownership)
            except Exception:
                pass

        return result

    def _apply_osint_downstream_guidance(self, result: BugBountyPipelineResult):
        """Use OSINT intelligence from Agent 4 to guide downstream agents (Agents 5-10).

        Applies:
        - attack_surface_map: prioritized targets for scanning
        - recommended_priority_targets: highest-value assets for testing
        - downstream_guidance: specific recommendations for each downstream agent
        """
        if not result.passive_intel:
            return

        # Collect all OSINT data across all passive intel results
        all_priority_targets: list[str] = []
        all_attack_surface: list[dict[str, Any]] = []
        all_guidance: dict[str, Any] = {
            "asset_discovery_recommendations": [],
            "scanner_recommendations": [],
            "validation_recommendations": [],
        }
        all_high_confidence: list[str] = []

        for intel in result.passive_intel:
            # Priority targets
            if hasattr(intel, 'recommended_priority_targets'):
                all_priority_targets.extend(intel.recommended_priority_targets)

            # Attack surface map
            if hasattr(intel, 'attack_surface_map'):
                all_attack_surface.extend(intel.attack_surface_map)

            # Downstream guidance
            if hasattr(intel, 'downstream_guidance'):
                for key in all_guidance:
                    if key in intel.downstream_guidance:
                        vals = intel.downstream_guidance[key]
                        if isinstance(vals, list):
                            all_guidance[key].extend(vals)
                        elif isinstance(vals, str) and vals not in all_guidance[key]:
                            all_guidance[key].append(vals)

            # High-confidence assets (>80%)
            if hasattr(intel, 'assets'):
                for a in intel.assets:
                    if a.get("confidence", 0) >= 0.8:
                        asset_name = a.get("asset", "")
                        if asset_name and asset_name not in all_high_confidence:
                            all_high_confidence.append(asset_name)

        # Store consolidated guidance on the pipeline result
        result.downstream_guidance["osint_priority_targets"] = all_priority_targets[:20]
        result.downstream_guidance["osint_attack_surface"] = all_attack_surface
        result.downstream_guidance["osint_high_confidence_assets"] = all_high_confidence
        result.downstream_guidance["osint_recommendations"] = all_guidance

        # Agent 5 (Active Enum): prioritize high-confidence subdomains
        if all_priority_targets:
            result.downstream_guidance["active_enumeration_priority"] = all_priority_targets[:10]
        if all_high_confidence:
            result.downstream_guidance["active_enumeration_targets"] = all_high_confidence[:15]

        # Agent 6 (Vulnerability Scanner): prioritize CRITICAL and HIGH_VALUE assets
        critical_high = [
            e["asset"] for e in all_attack_surface
            if e.get("classification") in ("CRITICAL", "HIGH_VALUE")
        ]
        if critical_high:
            result.downstream_guidance["scanning_priority"] = critical_high[:10]
            result.downstream_guidance["scanning_recommendation"] = (
                f"Prioritize scanning {len(critical_high)} critical/high-value asset(s)"
            )

        # Agent 7-10 (Validation, Exploitation, Analysis, Report):
        # Provide historical and exposure intelligence for context
        historical_endpoints = []
        for intel in result.passive_intel:
            if hasattr(intel, 'archived_urls'):
                historical_endpoints.extend(intel.archived_urls)
        if historical_endpoints:
            result.downstream_guidance["historical_context"] = list(set(historical_endpoints))[:10]

    async def _run_agent_5(self, target: str) -> ActiveEnumResult:
        """Agent 5: Active enumeration with all active tools.
        Uses dirsearch, gobuster, wfuzz, ffuf, nmap, dnsx via AgentToolIntegration.
        Feeds real tool findings into AI reasoning context."""
        integration = get_agent_tool_integration()

        # Rate-limit external tool API calls
        wait = await self.rate_limiter.acquire(tokens=2.0)
        if wait > 0:
            await asyncio.sleep(wait)
        tool_report = await integration.run_for_agent_5(target)

        wait = await self.rate_limiter.acquire(tokens=1.0)
        if wait > 0:
            await asyncio.sleep(wait)
        result = await self.agent_5.enumerate(target)

        tool_data = tool_report.to_dict() if hasattr(tool_report, 'to_dict') else {}
        result.tool_integration_findings = tool_data
        result.tools_executed = len(tool_report.tools_executed)
        result.tool_findings_count = tool_report.total_findings

        # Store tool execution details for downstream AI reasoning
        result.tool_execution_details = [
            {
                "tool": te.tool_name,
                "findings_count": len(te.findings),
                "status": getattr(te, 'status', 'unknown'),
            }
            for te in tool_report.tools_executed
        ]

        return result

    async def _run_agent_6(self, endpoint: str, test_types: list[str] | None = None) -> list[TestResult]:
        """Agent 6: Vulnerability scanning using all available tools.

        Phase 2: Feeds real tool findings (nuclei, sqlmap, dalfox, corstest, wpscan, cmsmap)
        directly into the agent's 11-phase scanning pipeline for AI-powered analysis.
        Every tool finding includes: tool name, severity, raw output, endpoint.

        test_types limits which vuln types to check for deduplication.
        """
        integration = get_agent_tool_integration()

        # Rate-limit external tool API calls
        wait = await self.rate_limiter.acquire(tokens=3.0)
        if wait > 0:
            await asyncio.sleep(wait)
        tool_report = await integration.run_for_agent_6(endpoint)

        wait = await self.rate_limiter.acquire(tokens=1.0)
        if wait > 0:
            await asyncio.sleep(wait)
        result = await self.agent_6.scan(endpoint, test_types=test_types)

        # Phase 2: Integrate real tool findings as evidence for AI reasoning
        for tr in tool_report.tools_executed:
            for finding in tr.findings:
                finding_severity = str(finding.get("severity", finding.get("confidence", "")))
                is_vulnerable = finding_severity.upper() in ("CRITICAL", "HIGH", "MEDIUM")
                finding_title = finding.get("title", finding.get("message", finding.get("issue", str(finding)[:100])))
                result.append(TestResult(
                    target=endpoint,
                    test_type=f"tool_{tr.tool_name}",
                    vulnerable=is_vulnerable,
                    description=f"[{tr.tool_name}] {finding_title}",
                    evidence=finding,
                    severity="high" if finding_severity.upper() == "CRITICAL" else "medium",
                    confidence=0.8 if is_vulnerable else 0.3,
                    # Feed raw tool output into AI reasoning context
                    raw_artifacts=[f"Tool: {tr.tool_name}", f"Raw: {str(finding)[:200]}"],
                ))

        # Store tool integration data for downstream use
        result.tool_integration = tool_report.to_dict() if hasattr(tool_report, 'to_dict') else {}

        return result

    async def _run_agent_7(self, finding: dict[str, Any]) -> ValidationResult:
        """Agent 7: Validation engine."""
        return await self.agent_7.validate(finding)

    async def _run_agent_8(self, finding: dict[str, Any]) -> ProofOfConcept:
        """Agent 8: Exploitation/PoC."""
        return await self.agent_8.create_poc(finding)

    async def _run_agent_9(self, finding: Any) -> FindingAnalysis:
        """Agent 9: Evidence-driven security analysis.

        Builds a rich finding dict from the ProofOfConcept object, including:
        - Evidence from PoC report (reproduction steps, observed behavior, impact evidence)
        - Validation status set to PROMOTE (already passed Agent 7)
        - Title and description from the PoC
        """
        # Build a rich finding dict from the ProofOfConcept for Agent 9's evidence-driven analysis
        title = getattr(finding, 'title', 'Unknown')
        finding_id = getattr(finding, 'finding_id', '')
        impact = getattr(finding, 'impact_demonstration', '')
        steps = getattr(finding, 'steps', [])

        # Extract evidence from the PoC report
        evidence_items = {}
        observed_behavior = []
        reproduction_steps = []
        impact_evidence = []

        report = getattr(finding, 'report', None)
        if report:
            rep_steps = getattr(report, 'reproduction_steps', [])
            if isinstance(rep_steps, list):
                for s in rep_steps:
                    if isinstance(s, dict):
                        action = s.get('action', '')
                        evidence_refs = s.get('evidence_refs', [])
                        if action:
                            reproduction_steps.append({"action": action, "evidence_refs": evidence_refs})

            obs_behavior = getattr(report, 'observed_behavior', [])
            if isinstance(obs_behavior, list):
                observed_behavior = obs_behavior

            imp_ev = getattr(report, 'impact_evidence', [])
            if isinstance(imp_ev, list):
                impact_evidence = imp_ev

            # Build evidence dict from all available evidence sources
            evidence_items = {
                "reproduction_steps": json.dumps(reproduction_steps) if reproduction_steps else "",
                "observed_behavior": json.dumps(observed_behavior) if observed_behavior else "",
                "impact_evidence": json.dumps(impact_evidence) if impact_evidence else "",
                "impact_demonstration": impact,
            }

        # Also try to extract from legacy steps
        if isinstance(steps, list) and not reproduction_steps:
            for i, step in enumerate(steps):
                if isinstance(step, dict):
                    reproduction_steps.append({
                        "action": step.get('description', step.get('action', '')),
                        "request": step.get('request', ''),
                        "response": step.get('response', ''),
                    })
                    if step.get('request'):
                        evidence_items["request"] = step.get('request', '')
                    if step.get('response'):
                        evidence_items["response"] = step.get('response', '')

        finding_dict = {
            "id": finding_id,
            "title": title,
            "type": "",
            "description": impact,
            "evidence": evidence_items,
            "observed_behavior": observed_behavior,
            "reproduction_steps": reproduction_steps,
            "impact_evidence": impact_evidence,
            "demonstrated_impact": [impact] if impact else [],
            "validation_status": "PROMOTE",
        }

        return await self.agent_9.analyze(finding_dict)

    async def _run_agent_10(self, finding: dict[str, Any], analysis: Any, poc: Any) -> VulnerabilityReport:
        """Agent 10: Report generation. Passes rich structured data to the strict renderer."""
        # Build rich analysis dict from FindingAnalysis object
        analysis_dict = {}
        if analysis:
            try:
                cvss_obj = getattr(analysis, 'cvss', None)
                analysis_dict["severity"] = getattr(cvss_obj, 'severity', "Medium") if cvss_obj else "Medium"
                analysis_dict["cvss_vector"] = getattr(cvss_obj, 'vector_string', "") if cvss_obj else ""
                analysis_dict["business_impact"] = getattr(analysis, 'business_impact', "")
                analysis_dict["cwe_primary"] = getattr(analysis, 'cwe_primary', "")
                analysis_dict["owasp_mapping"] = getattr(analysis, 'owasp_mapping', "")
                analysis_dict["remediation_priority"] = getattr(analysis, 'remediation_priority', "")
                analysis_dict["confidence"] = getattr(analysis, 'confidence', 0.0)
                # Also include detailed analysis if available
                detailed = getattr(analysis, 'detailed', None)
                if detailed:
                    analysis_dict["detailed"] = {
                        "cvss": {
                            "vector": getattr(getattr(detailed, 'cvss', None), 'vector', ''),
                            "score": getattr(getattr(detailed, 'cvss', None), 'score', ''),
                            "severity": getattr(getattr(detailed, 'cvss', None), 'severity', ''),
                        },
                        "cwe": {"primary": getattr(getattr(detailed, 'cwe', None), 'primary', '')},
                        "owasp": {"primary": getattr(getattr(detailed, 'owasp', None), 'primary', '')},
                        "business_impact": getattr(detailed, 'business_impact', ''),
                    }
            except Exception:
                pass

        # Build rich poc dict from ProofOfConcept object
        poc_dict = {}
        if poc:
            try:
                poc_dict["title"] = getattr(poc, 'title', '')
                poc_dict["impact_demonstration"] = getattr(poc, 'impact_demonstration', '')
                # Steps (legacy format)
                steps = getattr(poc, 'steps', [])
                poc_dict["steps"] = steps
                # Extract reproduction steps, observed behavior, and impact evidence from PoCReport
                report = getattr(poc, 'report', None)
                if report:
                    rep_steps = getattr(report, 'reproduction_steps', [])
                    # reproduction_steps is List[Dict] with 'action' key
                    if isinstance(rep_steps, list):
                        poc_dict["steps_to_reproduce"] = [
                            s if isinstance(s, dict) else {"action": str(s)}
                            for s in rep_steps
                        ]
                    # observed_behavior for attack scenario content
                    obs_behavior = getattr(report, 'observed_behavior', [])
                    if isinstance(obs_behavior, list) and obs_behavior:
                        poc_dict["observed_behavior"] = obs_behavior
                    # impact_evidence for impact documentation
                    imp_ev = getattr(report, 'impact_evidence', [])
                    if isinstance(imp_ev, list) and imp_ev:
                        poc_dict["impact_evidence"] = imp_ev
                    # No request/response/screenshots on PoCReport — those fields are NOT CAPTURED
                    # unless the finding provides them
            except Exception:
                pass

        return await self.agent_10.generate_report(finding, analysis_dict, poc_dict)

    def _scan_folder_files(self, folder_files: dict[str, str]) -> list[dict[str, Any]]:
        """Scan uploaded folder files for common security issues.
        Detects hardcoded secrets, API keys, SQL injection patterns,
        command injection, insecure configs, and other common vulnerabilities.
        """
        findings: list[dict[str, Any]] = []
        seen = set()

        # Patterns to scan for
        secret_patterns = [
            (r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?', 'Hardcoded API Key', 'HIGH'),
            (r'(?i)(?:secret|token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["\']?[A-Za-z0-9_\-.]{20,}["\']?', 'Hardcoded Secret/Token', 'CRITICAL'),
            (r'(?i)password\s*[:=]\s*["\'][^"\']+["\']', 'Hardcoded Password', 'CRITICAL'),
            (r'(?i)(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?[A-Z0-9]{16,}["\']?', 'AWS Credential', 'CRITICAL'),
            (r'(?i)(?:sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]{10,}', 'Stripe API Key', 'CRITICAL'),
            (r'(?i)(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36}', 'GitHub Token', 'CRITICAL'),
            (r'(?i)(?:xox[parb]-)[A-Za-z0-9\-]{10,}', 'Slack Token', 'CRITICAL'),
            (r'(?i)(?:-----BEGIN\s?(?:RSA\s)?PRIVATE\s?KEY-----)', 'Private Key Embedded', 'CRITICAL'),
            (r'(?i)(?:mongodb\+srv|postgresql|mysql|redis|amqp)://[^\s"]+(?:@)[^\s"]+', 'Database Connection String', 'CRITICAL'),
            (r'(?i)(?:JWT|jwt)\s*[:=]\s*["\']?eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}["\']?', 'JWT Token Hardcoded', 'HIGH'),
            (r'(?i)-----BEGIN\s?CERTIFICATE-----', 'Certificate Embedded', 'MEDIUM'),
        ]

        vuln_patterns = [
            (r'(?i)(?:exec|eval|system|popen|subprocess\.call|subprocess\.Popen|os\.system)\s*\(', 'Command Injection (dynamic execution)', 'HIGH'),
            (r'(?i)(?:exec|execute|sp_executesql|raw_query|nativeQuery)\s*\([^)]*\+', 'SQL Injection (string concatenation)', 'HIGH'),
            (r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*"', 'SQL Injection (query concatenation)', 'HIGH'),
            (r'(?i)(?:innerHTML|outerHTML|dangerouslySetInnerHTML|v-html)\s*[:=]', 'XSS (HTML injection)', 'HIGH'),
            (r'(?i)(?:pickle\.loads?|yaml\.load\s*\(|marshal\.loads?)', 'Insecure Deserialization', 'HIGH'),
            (r'(?i)(?:sprintf|format_string|%s\s*%s|%x\s*%x)', 'Format String Vulnerability', 'MEDIUM'),
            (r'(?i)(?:allow_url_include|allow_url_fopen)\s*=\s*(?:on|true|1)', 'Insecure PHP Config', 'HIGH'),
            (r'(?i)(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1)', 'Debug Mode Enabled', 'MEDIUM'),
            (r'(?i)(?:CORS|Access-Control-Allow-Origin)\s*[:=]\s*["\']?\*["\']?', 'Permissive CORS', 'MEDIUM'),
            (r'(?i)(?:password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', 'Hardcoded Credential', 'HIGH'),
        ]

        for filepath, content in folder_files.items():
            if not content or len(content) > 100000:
                continue
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith(('#', '//', '/*', '*', '<!--')):
                    continue

                # Check secret patterns
                for pattern, title, severity in secret_patterns:
                    match = re.search(pattern, stripped)
                    if match:
                        sig = f"{title}:{filepath}:{match.group()[:30]}"
                        if sig not in seen:
                            seen.add(sig)
                            findings.append({
                                "title": title,
                                "severity": severity,
                                "type": "secret_leak",
                                "file": filepath,
                                "line": i,
                                "match": match.group()[:60],
                                "description": f"Potential {title.lower()} detected in {filepath} on line {i}",
                                "evidence": f"Line {i}: {stripped[:120]}",
                                "confidence": 0.8,
                            })
                        break

                # Check vulnerability patterns
                for pattern, title, severity in vuln_patterns:
                    match = re.search(pattern, stripped)
                    if match:
                        sig = f"{title}:{filepath}:{match.group()[:30]}"
                        if sig not in seen:
                            seen.add(sig)
                            findings.append({
                                "title": title,
                                "severity": severity,
                                "type": "vulnerability",
                                "file": filepath,
                                "line": i,
                                "match": match.group()[:60],
                                "description": f"Potential {title.lower()} pattern in {filepath} on line {i}",
                                "evidence": f"Line {i}: {stripped[:120]}",
                                "confidence": 0.6,
                            })
                        break

        # Sort by severity (CRITICAL first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

        return findings

    def get_summary(self, result: BugBountyPipelineResult) -> dict[str, Any]:
        """Get a human-readable summary of pipeline results."""
        policy_decisions_summary = {}
        if result.policy_decisions:
            allows = sum(1 for d in result.policy_decisions if d["decision"] == "ALLOW")
            reviews = sum(1 for d in result.policy_decisions if d["decision"] == "REVIEW")
            rejects = sum(1 for d in result.policy_decisions if d["decision"] == "REJECT")
            policy_decisions_summary = {
                "total_evaluated": len(result.policy_decisions),
                "allow": allows,
                "review": reviews,
                "reject": rejects,
                "avg_compliance_score": sum(d.get("compliance_score", 0) for d in result.policy_decisions) / len(result.policy_decisions) if result.policy_decisions else 0,
            }

        return {
            "pipeline_id": result.pipeline_id,
            "duration_seconds": (
                datetime.fromisoformat(result.completed_at) - datetime.fromisoformat(result.started_at)
            ).total_seconds() if result.started_at and result.completed_at else 0,
            "program": result.program_intel.program_name if result.program_intel else "N/A",
            "targets_scanned": len(result.active_enum),
            "vulnerabilities_found": len(result.scan_results),
            "validated_findings": len(result.validation_results),
            "proofs_of_concept": len(result.proofs_of_concept),
            "reports_generated": len(result.reports),
            "errors": len(result.errors),
            "ethical_rules_applied": result.ethical_rules_applied,
            "policy_decisions": policy_decisions_summary,
            "osint_intelligence": {
                "priority_targets": result.downstream_guidance.get("osint_priority_targets", [])[:5],
                "high_confidence_assets": len(result.downstream_guidance.get("osint_high_confidence_assets", [])),
                "attack_surface_entries": len(result.downstream_guidance.get("osint_attack_surface", [])),
                "scanning_priority": result.downstream_guidance.get("scanning_priority", [])[:3],
            },
            "scope_authorizations": {
                "total": len(result.scope_authorizations),
                "allow": sum(1 for a in result.scope_authorizations if a["decision"] == "ALLOW"),
                "review": sum(1 for a in result.scope_authorizations if a["decision"] == "REVIEW"),
                "block": sum(1 for a in result.scope_authorizations if a["decision"] == "BLOCK"),
                "avg_confidence": round(
                    sum(a.get("authorization_confidence", 0) for a in result.scope_authorizations) / len(result.scope_authorizations), 2
                ) if result.scope_authorizations else 0,
            },
        }
