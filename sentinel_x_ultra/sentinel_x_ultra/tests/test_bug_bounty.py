"""
Tests for the Bug Bounty Multi-Agent Framework.

Tests:
1. Orchestrator creates all 10 agents without TypeError
2. Each agent accepts llm_provider parameter
3. Each agent accepts memory parameter
4. Agent 4 accepts data_sources parameter
5. LLMProvider creates successfully
6. AgentMemory read/write works
7. DataSourceAggregator creates successfully
"""

import sys
import os
import pytest
from unittest.mock import AsyncMock, patch

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestBugBountyOrchestrator:
    """Test that the orchestrator creates all 10 agents without errors."""

    def test_orchestrator_creates_all_agents(self):
        """Verify all 10 agents are created without TypeError from missing llm_provider parameter."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator

        orchestrator = BugBountyOrchestrator()

        # All 10 agents must exist and not be None
        assert orchestrator.agent_1 is not None
        assert orchestrator.agent_2 is not None
        assert orchestrator.agent_3 is not None
        assert orchestrator.agent_4 is not None
        assert orchestrator.agent_5 is not None
        assert orchestrator.agent_6 is not None
        assert orchestrator.agent_7 is not None
        assert orchestrator.agent_8 is not None
        assert orchestrator.agent_9 is not None
        assert orchestrator.agent_10 is not None

    def test_orchestrator_agents_have_llm_provider(self):
        """Verify all agents received the LLM provider."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator

        orchestrator = BugBountyOrchestrator()

        assert hasattr(orchestrator.agent_1, 'llm_provider')
        assert hasattr(orchestrator.agent_2, 'llm_provider')
        assert hasattr(orchestrator.agent_3, 'llm_provider')
        assert hasattr(orchestrator.agent_4, 'llm_provider')
        assert hasattr(orchestrator.agent_5, 'llm_provider')
        assert hasattr(orchestrator.agent_6, 'llm_provider')
        assert hasattr(orchestrator.agent_7, 'llm_provider')
        assert hasattr(orchestrator.agent_8, 'llm_provider')
        assert hasattr(orchestrator.agent_9, 'llm_provider')
        assert hasattr(orchestrator.agent_10, 'llm_provider')

    def test_orchestrator_agents_have_memory(self):
        """Verify all agents received the shared memory store."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator

        orchestrator = BugBountyOrchestrator()

        assert orchestrator.memory is not None
        assert hasattr(orchestrator.agent_1, 'memory')
        assert hasattr(orchestrator.agent_2, 'memory')
        assert hasattr(orchestrator.agent_3, 'memory')
        assert hasattr(orchestrator.agent_4, 'memory')
        assert hasattr(orchestrator.agent_5, 'memory')
        assert hasattr(orchestrator.agent_6, 'memory')
        assert hasattr(orchestrator.agent_7, 'memory')
        assert hasattr(orchestrator.agent_8, 'memory')
        assert hasattr(orchestrator.agent_9, 'memory')
        assert hasattr(orchestrator.agent_10, 'memory')

    def test_agent_4_has_data_sources(self):
        """Verify Agent 4 received the DataSourceAggregator."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator

        orchestrator = BugBountyOrchestrator()

        assert orchestrator.data_sources is not None
        assert hasattr(orchestrator.agent_4, 'data_sources')
        assert orchestrator.agent_4.data_sources is not None

    def test_orchestrator_has_system_prompt(self):
        """Verify orchestrator builds the system prompt."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator

        orchestrator = BugBountyOrchestrator()

        assert orchestrator.system_prompt is not None
        assert len(orchestrator.system_prompt) > 0

    def test_orchestrator_has_ethical_rules(self):
        """Verify ethical rules are defined."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator

        orchestrator = BugBountyOrchestrator()

        assert orchestrator.ethical_rules is not None
        assert len(orchestrator.ethical_rules) > 0


class TestAgentMemory:
    """Test the cross-agent shared memory store."""

    def test_memory_create(self):
        """Verify AgentMemory creates successfully."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory

        memory = AgentMemory()
        assert memory is not None

    def test_memory_record_and_read_asset(self):
        """Verify assets can be recorded and retrieved."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory

        memory = AgentMemory()
        memory.record_asset("agent_4", "example.com", "DOMAIN", 0.95)

        assets = memory.get_assets()
        assert len(assets) == 1
        assert assets[0]["name"] == "example.com"
        assert assets[0]["type"] == "DOMAIN"
        assert assets[0]["confidence"] == 0.95
        assert assets[0]["discovered_by"] == "agent_4"

    def test_memory_priority_targets(self):
        """Verify priority targets are sorted by score."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory

        memory = AgentMemory()
        memory.record_priority_target("agent_4", "low.com", 30)
        memory.record_priority_target("agent_4", "high.com", 90)
        memory.record_priority_target("agent_4", "med.com", 60)

        targets = memory.get_priority_targets()
        assert len(targets) == 3
        assert targets[0]["target"] == "high.com"  # Highest score first
        assert targets[1]["target"] == "med.com"
        assert targets[2]["target"] == "low.com"

    def test_memory_deduplication(self):
        """Verify duplicate assets are deduplicated."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory

        memory = AgentMemory()
        memory.record_asset("agent_4", "same.com", "DOMAIN", 0.8)
        # Second recording with higher confidence should replace
        memory.record_asset("agent_5", "same.com", "DOMAIN", 0.95)

        assets = memory.get_assets()
        assert len(assets) == 1  # Deduplicated
        assert assets[0]["confidence"] == 0.95  # Higher confidence kept

    def test_memory_get_summary(self):
        """Verify summary returns correct counts."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory

        memory = AgentMemory()
        memory.record_asset("agent_4", "a.com", "DOMAIN", 0.9)
        memory.record_asset("agent_4", "b.com", "SUBDOMAIN", 0.8)
        memory.record_priority_target("agent_4", "a.com", 90)
        memory.record_subdomain("agent_5", "a.com", "api.a.com")
        memory.record_subdomain("agent_5", "a.com", "admin.a.com")

        summary = memory.get_summary()
        assert summary["assets_count"] == 2
        assert summary["priority_targets_count"] == 1
        assert summary["subdomains_count"] == 2


class TestDataSourceAggregator:
    """Test the external data source aggregator."""

    def test_aggregator_creates(self):
        """Verify DataSourceAggregator creates successfully."""
        from sentinel_x_ultra.bug_bounty.data_sources import DataSourceAggregator

        agg = DataSourceAggregator()
        assert agg is not None
        assert agg.shodan is not None
        assert agg.censys is not None
        assert agg.securitytrails is not None
        assert agg.urlscan is not None


class TestLLMProvider:
    """Test the LLM provider creates without errors."""

    def test_llm_provider_creates(self):
        """Verify LLMProvider creates successfully."""
        from sentinel_x_ultra.bug_bounty.llm_provider import LLMProvider, get_llm_provider

        provider = LLMProvider()
        assert provider is not None
        assert provider.provider_name is not None

    def test_get_llm_provider_returns_instance(self):
        """Verify get_llm_provider returns a valid instance."""
        from sentinel_x_ultra.bug_bounty.llm_provider import get_llm_provider

        provider = get_llm_provider()
        assert provider is not None

    def test_llm_fallback_response(self):
        """Verify fallback responses work when no API keys configured."""
        from sentinel_x_ultra.bug_bounty.llm_provider import LLMProvider

        provider = LLMProvider()
        result = provider._fallback_response("test")
        assert "[LLM Fallback: test]" in result


class TestSystemPrompts:
    """Test the system prompts are well-formed."""

    def test_full_system_prompt(self):
        """Verify get_full_system_prompt returns complete prompt."""
        from sentinel_x_ultra.bug_bounty.system_prompts import get_full_system_prompt

        prompt = get_full_system_prompt()
        assert prompt is not None
        assert "FOUNDATIONAL PRINCIPLES" in prompt
        assert "DECISION HIERARCHY" in prompt
        assert "AGENT ARCHITECTURE" in prompt
        assert "AGENT 1" in prompt or "Agent 1" in prompt
        assert "AGENT 10" in prompt or "Agent 10" in prompt or "Report Generation" in prompt


class TestAgent9LLMFallback:
    """Test Agent 9's LLM fallback behavior when llm_provider is None."""

    @pytest.mark.asyncio
    async def test_classify_cwe_falls_back_without_llm(self):
        """Verify _classify_cwe uses deterministic pattern matching when llm_provider=None."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent, CWEInfo

        agent = AnalysisAgent(llm_provider=None)

        evidence = [
            {"type": "observed_behavior", "value": "script alert(1) xss cross-site <script onerror"},
            {"type": "reproduction_step", "value": "Inject <script>alert(document.cookie)</script> into search parameter"},
            {"type": "impact_evidence", "value": "Script executed in victim's browser, cookie returned"},
        ]
        cwe_info = await agent._classify_cwe(
            {"type": "xss", "description": "Cross-site scripting in search parameter"},
            evidence,
        )

        assert isinstance(cwe_info, CWEInfo)
        assert cwe_info.primary.startswith("CWE-")
        # Should detect javascript_execution pattern and return CWE-79
        assert cwe_info.primary == "CWE-79"

    @pytest.mark.asyncio
    async def test_classify_cwe_handles_empty_evidence(self):
        """Verify _classify_cwe returns CWE-UNKNOWN with no evidence."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent, CWEInfo

        agent = AnalysisAgent(llm_provider=None)

        cwe_info = await agent._classify_cwe(
            {"type": "unknown", "description": ""},
            [],
        )

        assert isinstance(cwe_info, CWEInfo)
        assert cwe_info.primary == "CWE-UNKNOWN"

    @pytest.mark.asyncio
    async def test_derive_cvss_falls_back_without_llm(self):
        """Verify _derive_cvss uses deterministic keyword logic when llm_provider=None."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent, CVSSEntry

        agent = AnalysisAgent(llm_provider=None)

        evidence = [
            {"type": "reproduction_step", "value": "Send GET request to https://example.com/api/users/123"},
            {"type": "observed_behavior", "value": "Unauthorized data returned: another user's profile data exposed"},
            {"type": "impact_evidence", "value": "Confidential user data returned without authentication"},
        ]
        cvss_entry = await agent._derive_cvss(
            {"type": "idor", "description": "IDOR in user profile endpoint"},
            evidence,
        )

        assert isinstance(cvss_entry, CVSSEntry)
        assert cvss_entry.severity in ("None", "Low", "Medium", "High", "Critical", "UNKNOWN")
        # Should detect network access, data exposed = High confidentiality
        assert cvss_entry.metrics.AV == "Network"
        assert cvss_entry.metrics.C == "High"
        assert cvss_entry.score != "UNKNOWN"

    @pytest.mark.asyncio
    async def test_derive_cvss_handles_minimal_evidence(self):
        """Verify _derive_cvss produces valid CVSSEntry even with minimal evidence."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent, CVSSEntry

        agent = AnalysisAgent(llm_provider=None)

        cvss_entry = await agent._derive_cvss(
            {"type": "unknown", "description": ""},
            [{"type": "description", "value": "Something happened but unclear what"}],
        )

        assert isinstance(cvss_entry, CVSSEntry)
        assert cvss_entry.vector is not None
        assert cvss_entry.metrics.AV is not None


class TestAgentImports:
    """Test all agents can be imported without errors."""

    def test_import_all_agents(self):
        """Verify all 10 agent modules import successfully."""
        from sentinel_x_ultra.bug_bounty.url_parser import URLParserAgent, ProgramIntelligence, AssetEntry
        from sentinel_x_ultra.bug_bounty.policy_enforcer import PolicyEnforcerAgent, PolicyEnforcementResult, PolicyRule
        from sentinel_x_ultra.bug_bounty.scope_guardian import ScopeGuardianAgent, ScopeCheckResult
        from sentinel_x_ultra.bug_bounty.passive_intel import PassiveIntelligenceAgent, PassiveIntelResult
        from sentinel_x_ultra.bug_bounty.active_enum import ActiveEnumerationAgent, ActiveEnumResult
        from sentinel_x_ultra.bug_bounty.vuln_scanner import VulnerabilityScannerAgent, TestResult
        from sentinel_x_ultra.bug_bounty.validation_engine import ValidationEngineAgent, ValidationResult
        from sentinel_x_ultra.bug_bounty.exploitation import ExploitationAgent, ProofOfConcept
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent, FindingAnalysis, CWEInfo, CVSSEntry
        from sentinel_x_ultra.bug_bounty.report_generation import ReportGenerationAgent, VulnerabilityReport

        # Verify all are classes
        assert callable(URLParserAgent)
        assert callable(PolicyEnforcerAgent)
        assert callable(ScopeGuardianAgent)
        assert callable(PassiveIntelligenceAgent)
        assert callable(ActiveEnumerationAgent)
        assert callable(VulnerabilityScannerAgent)
        assert callable(ValidationEngineAgent)
        assert callable(ExploitationAgent)
        assert callable(AnalysisAgent)
        assert callable(ReportGenerationAgent)

    def test_import_new_modules(self):
        """Verify Phase 3 and Phase 4 modules import successfully."""
        from sentinel_x_ultra.bug_bounty.agent_memory import AgentMemory, MemoryEntry
        from sentinel_x_ultra.bug_bounty.data_sources import (
            DataSourceAggregator, ShodanClient, CensysClient,
            SecurityTrailsClient, URLScanClient, DataSourceResult,
        )
        from sentinel_x_ultra.bug_bounty.execution_engine import ResultCache
        from sentinel_x_ultra.bug_bounty.data_sources import set_shared_cache, _ResultCacheAdapter

        assert callable(AgentMemory)
        assert callable(MemoryEntry)
        assert callable(DataSourceAggregator)
        assert callable(ShodanClient)
        assert callable(CensysClient)
        assert callable(SecurityTrailsClient)
        assert callable(ResultCache)
        assert callable(set_shared_cache)
    