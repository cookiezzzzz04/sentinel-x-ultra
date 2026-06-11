"""
Comprehensive unit tests for the Bug Bounty Multi-Agent Framework v7.0.
Tests all 10 agents: happy path, edge cases, backward compatibility,
and anti-hallucination guarantees.
"""

import sys
import json
import asyncio
from typing import Any, Dict, List
from dataclasses import dataclass, field
from unittest.mock import patch, MagicMock

import pytest


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def loop(event_loop):
    """Yield the event loop for each test."""
    return event_loop


# =============================================================================
# Agent 1 — URL Parser
# =============================================================================

class TestURLParser:
    """Agent 1: URL Parser Agent — parses HackerOne/BugCrowd program URLs."""

    def test_imports(self):
        """Verify URLParserAgent and ProgramIntelligence are importable."""
        from sentinel_x_ultra.bug_bounty.url_parser import URLParserAgent, ProgramIntelligence
        assert URLParserAgent is not None
        assert ProgramIntelligence is not None

    def test_program_intelligence_dataclass(self):
        """Verify ProgramIntelligence has all expected fields."""
        from sentinel_x_ultra.bug_bounty.url_parser import ProgramIntelligence
        pi = ProgramIntelligence(
            program_name="Test Program",
            url="https://hackerone.com/test",
            platform="hackerone",
        )
        assert pi.program_name == "Test Program"
        assert pi.url == "https://hackerone.com/test"
        assert pi.platform == "hackerone"
        assert hasattr(pi, 'in_scope_domains')
        assert hasattr(pi, 'out_of_scope_domains')

    def test_url_parser_instantiation(self):
        """Verify URLParserAgent can be instantiated."""
        from sentinel_x_ultra.bug_bounty.url_parser import URLParserAgent
        agent = URLParserAgent()
        assert agent is not None

    @pytest.mark.asyncio
    async def test_parse_unknown_url(self, loop):
        """Parse should handle unknown URL format gracefully."""
        from sentinel_x_ultra.bug_bounty.url_parser import URLParserAgent
        agent = URLParserAgent()
        result = await agent.parse("https://unknown-platform.com/test")
        await agent.close()
        assert result is not None


# =============================================================================
# Agent 2 — Policy Enforcer
# =============================================================================

class TestPolicyEnforcer:
    """Agent 2: Policy Enforcement Agent — 12-phase policy decision engine."""

    def test_imports(self):
        """Verify PolicyEnforcerAgent and key types are importable."""
        from sentinel_x_ultra.bug_bounty.policy_enforcer import (
            PolicyEnforcerAgent, PolicyDecision, PolicyDecisionOutput,
            PolicyRule, ScopeStatus, AssetEligibility, TestingCompliance,
            VulnEligibility, EvidenceTier, DuplicateRisk,
        )
        assert PolicyEnforcerAgent is not None
        assert PolicyDecision is not None
        assert PolicyRule is not None

    def test_policy_decision_enum(self):
        """Verify PolicyDecision has ALLOW/REVIEW/REJECT."""
        from sentinel_x_ultra.bug_bounty.policy_enforcer import PolicyDecision
        assert hasattr(PolicyDecision, 'ALLOW')
        assert hasattr(PolicyDecision, 'REVIEW')
        assert hasattr(PolicyDecision, 'REJECT')

    def test_policy_decision_output_dataclass(self):
        """Verify PolicyDecisionOutput has all expected fields."""
        from sentinel_x_ultra.bug_bounty.policy_enforcer import PolicyDecision, PolicyDecisionOutput
        pdo = PolicyDecisionOutput(
            decision=PolicyDecision.ALLOW,
            confidence=85.0,
        )
        assert pdo.decision == PolicyDecision.ALLOW
        assert pdo.confidence == 85.0
        assert hasattr(pdo, 'scope_status')
        assert hasattr(pdo, 'evidence_tier')
        assert hasattr(pdo, 'program_compliance_score')

    def test_agent_instantiation(self):
        """Verify PolicyEnforcerAgent can be instantiated."""
        from sentinel_x_ultra.bug_bounty.policy_enforcer import PolicyEnforcerAgent
        agent = PolicyEnforcerAgent()
        assert agent is not None

    def test_evaluate_returns_decision(self):
        """Verify evaluate() returns a PolicyDecisionOutput."""
        from sentinel_x_ultra.bug_bounty.policy_enforcer import PolicyEnforcerAgent
        agent = PolicyEnforcerAgent()
        finding = {"title": "Test", "type": "xss", "target": "example.com", "severity": "medium"}
        result = agent.evaluate(finding)
        assert result is not None
        from sentinel_x_ultra.bug_bounty.policy_enforcer import PolicyDecisionOutput
        assert isinstance(result, PolicyDecisionOutput)


# =============================================================================
# Agent 3 — Scope Guardian
# =============================================================================

class TestScopeGuardian:
    """Agent 3: Scope Guardian — authorization and scope enforcement."""

    def test_imports(self):
        """Verify ScopeGuardianAgent and key types are importable."""
        from sentinel_x_ultra.bug_bounty.scope_guardian import (
            ScopeGuardianAgent, ScopeCheckResult, ScopeAuthorization,
            AuthorizationState, OwnershipStatus, AssetType, RiskLevel,
        )
        assert ScopeGuardianAgent is not None

    def test_scope_check_happy_path(self):
        """Verify check_target returns a ScopeCheckResult."""
        from sentinel_x_ultra.bug_bounty.scope_guardian import ScopeGuardianAgent
        agent = ScopeGuardianAgent()
        agent.set_scope(in_scope=["example.com"], out_of_scope=[])
        result = agent.check_target("example.com")
        assert result is not None
        assert result.in_scope is True

    def test_scope_check_out_of_scope(self):
        """Verify out-of-scope targets are detected."""
        from sentinel_x_ultra.bug_bounty.scope_guardian import ScopeGuardianAgent
        agent = ScopeGuardianAgent()
        agent.set_scope(in_scope=["example.com"], out_of_scope=["evil.com"])
        result = agent.check_target("evil.com")
        assert result is not None
        assert result.in_scope is False

    def test_authorize_unknown_target(self):
        """Verify authorization handles unknown targets."""
        from sentinel_x_ultra.bug_bounty.scope_guardian import ScopeGuardianAgent
        agent = ScopeGuardianAgent()
        auth = agent.authorize("unknown-target.com")
        assert auth is not None
        assert hasattr(auth, 'decision')


# =============================================================================
# Agent 4 — Passive Intelligence
# =============================================================================

class TestPassiveIntel:
    """Agent 4: Passive Intelligence Agent — OSINT analysis with 20 phases."""

    def test_imports(self):
        """Verify PassiveIntelligenceAgent and result type are importable."""
        from sentinel_x_ultra.bug_bounty.passive_intel import (
            PassiveIntelligenceAgent, PassiveIntelResult,
            DiscoveredAsset, AssetClass,
        )
        assert PassiveIntelligenceAgent is not None
        assert PassiveIntelResult is not None

    def test_passive_intel_result_dataclass(self):
        """Verify PassiveIntelResult has all expected fields."""
        from sentinel_x_ultra.bug_bounty.passive_intel import PassiveIntelResult
        result = PassiveIntelResult(domain="example.com")
        assert result.domain == "example.com"
        assert hasattr(result, 'subdomains')
        assert hasattr(result, 'assets')
        assert hasattr(result, 'evidence_chains')
        assert hasattr(result, 'ownership_verifications')

    def test_discovered_asset_evidence_chain(self):
        """Verify DiscoveredAsset supports evidence_chain."""
        from sentinel_x_ultra.bug_bounty.passive_intel import DiscoveredAsset
        asset = DiscoveredAsset(
            asset="example.com",
            confidence=0.9,
            evidence_chain=[{"source": "crt.sh", "observation": "found in CT log", "confidence": 0.9}],
        )
        assert asset.asset == "example.com"
        assert len(asset.evidence_chain) == 1
        assert asset.evidence_chain[0]["source"] == "crt.sh"

    @pytest.mark.asyncio
    async def test_gather_returns_result(self, loop):
        """Verify gather() returns a PassiveIntelResult."""
        from sentinel_x_ultra.bug_bounty.passive_intel import PassiveIntelligenceAgent
        agent = PassiveIntelligenceAgent()
        result = await agent.gather("example.com")
        assert result is not None
        assert result.target == "example.com"
        # Should have the domain itself as an asset
        assert len(result.subdomains) >= 1

    @pytest.mark.asyncio
    async def test_osint_gather_backward_compat(self, loop):
        """Verify osint_gather() still works (backward compat)."""
        from sentinel_x_ultra.bug_bounty.passive_intel import PassiveIntelligenceAgent
        agent = PassiveIntelligenceAgent()
        result = await agent.osint_gather("example.com")
        assert result is not None
        assert result.target == "example.com"


# =============================================================================
# Agent 5 — Active Enumeration
# =============================================================================

class TestActiveEnum:
    """Agent 5: Active Enumeration Agent — attack surface analysis with 14 phases."""

    def test_imports(self):
        """Verify ActiveEnumerationAgent and result type are importable."""
        from sentinel_x_ultra.bug_bounty.active_enum import (
            ActiveEnumerationAgent, ActiveEnumResult, AssetAnalysis,
            AssetConfidence, OwnershipStatus, AssetClassification,
        )
        assert ActiveEnumerationAgent is not None
        assert ActiveEnumResult is not None
        assert AssetAnalysis is not None

    def test_asset_analysis_dataclass(self):
        """Verify AssetAnalysis has all required output fields."""
        from sentinel_x_ultra.bug_bounty.active_enum import AssetAnalysis, AssetConfidence, OwnershipStatus, AssetClassification
        aa = AssetAnalysis(
            asset_name="example.com",
            asset_type=AssetClassification.DOMAIN.value,
            ownership_status=OwnershipStatus.VERIFIED_OWNER.value,
            confidence_classification=AssetConfidence.CONFIRMED.value,
        )
        assert aa.asset_name == "example.com"
        assert aa.asset_type == "DOMAIN"
        assert aa.ownership_status == "VERIFIED_OWNER"
        assert aa.confidence_classification == "CONFIRMED"
        assert hasattr(aa, 'asset_id')
        assert hasattr(aa, 'criticality_score')
        assert hasattr(aa, 'priority_score')
        assert hasattr(aa, 'exposure_level')
        assert hasattr(aa, 'relationships')
        assert hasattr(aa, 'evidence')
        assert hasattr(aa, 'contradictions')
        assert hasattr(aa, 'intelligence_gaps')

    @pytest.mark.asyncio
    async def test_enumerate_returns_result(self, loop):
        """Verify enumerate() returns an ActiveEnumResult."""
        from sentinel_x_ultra.bug_bounty.active_enum import ActiveEnumerationAgent
        agent = ActiveEnumerationAgent()
        result = await agent.enumerate("example.com")
        assert result is not None
        assert result.target == "example.com"

    def test_active_enum_result_backward_compat(self):
        """Verify ActiveEnumResult preserves backward compat fields."""
        from sentinel_x_ultra.bug_bounty.active_enum import ActiveEnumResult
        result = ActiveEnumResult(domain="example.com")
        assert result.domain == "example.com"
        assert hasattr(result, 'subdomains')  # property
        assert hasattr(result, 'endpoints')
        assert hasattr(result, 'open_ports')


# =============================================================================
# Agent 6 — Vulnerability Scanner
# =============================================================================

class TestVulnScanner:
    """Agent 6: Vulnerability Scanner Agent — OWASP Top 10 testing."""

    def test_imports(self):
        """Verify VulnerabilityScannerAgent and TestResult are importable."""
        from sentinel_x_ultra.bug_bounty.vuln_scanner import VulnerabilityScannerAgent, TestResult
        assert VulnerabilityScannerAgent is not None
        assert TestResult is not None

    def test_test_result_dataclass(self):
        """Verify TestResult has all expected fields."""
        from sentinel_x_ultra.bug_bounty.vuln_scanner import TestResult
        tr = TestResult(
            target="example.com",
            test_type="xss",
            vulnerable=True,
            description="Test XSS found",
            severity="High",
        )
        assert tr.target == "example.com"
        assert tr.test_type == "xss"
        assert tr.vulnerable is True
        assert tr.severity == "High"
        assert hasattr(tr, 'evidence')
        assert hasattr(tr, 'confidence')

    @pytest.mark.asyncio
    async def test_scan_returns_list(self, loop):
        """Verify scan() returns a list of TestResults."""
        from sentinel_x_ultra.bug_bounty.vuln_scanner import VulnerabilityScannerAgent
        agent = VulnerabilityScannerAgent()
        results = await agent.scan("https://example.com")
        assert isinstance(results, list)


# =============================================================================
# Agent 7 — Validation Engine
# =============================================================================

class TestValidationEngine:
    """Agent 7: Validation Engine — multi-stage validation."""

    def test_imports(self):
        """Verify ValidationEngineAgent and result types are importable."""
        from sentinel_x_ultra.bug_bounty.validation_engine import (
            ValidationEngineAgent, ValidationResult, NormalizedFinding,
        )
        assert ValidationEngineAgent is not None
        assert ValidationResult is not None

    @pytest.mark.asyncio
    async def test_validate_returns_result(self, loop):
        """Verify validate() returns a ValidationResult."""
        from sentinel_x_ultra.bug_bounty.validation_engine import ValidationEngineAgent
        agent = ValidationEngineAgent()
        finding = {"title": "Test", "type": "xss", "target": "example.com", "severity": "medium"}
        result = await agent.validate(finding)
        assert result is not None
        assert hasattr(result, 'decision')


# =============================================================================
# Agent 8 — Exploitation/PoC
# =============================================================================

class TestExploitation:
    """Agent 8: Exploitation Agent — PoC and evidence documentation engine."""

    def test_imports(self):
        """Verify ExploitationAgent and key types are importable."""
        from sentinel_x_ultra.bug_bounty.exploitation import (
            ExploitationAgent, ProofOfConcept, PoCReport, PoCStep,
            Decision, EvidenceQuality, ConfidenceLevel,
        )
        assert ExploitationAgent is not None
        assert ProofOfConcept is not None
        assert PoCReport is not None

    def test_proof_of_concept_backward_compat(self):
        """Verify ProofOfConcept preserves all original fields."""
        from sentinel_x_ultra.bug_bounty.exploitation import ProofOfConcept
        poc = ProofOfConcept(finding_id="test-123", title="XSS Found")
        assert poc.finding_id == "test-123"
        assert poc.title == "XSS Found"
        assert hasattr(poc, 'steps')
        assert hasattr(poc, 'impact_demonstration')
        assert hasattr(poc, 'safe')
        # New fields
        assert hasattr(poc, 'report')
        assert hasattr(poc, 'decision')
        assert hasattr(poc, 'confidence')

    def test_poc_report_schema(self):
        """Verify PoCReport matches required output schema."""
        from sentinel_x_ultra.bug_bounty.exploitation import PoCReport, Decision
        report = PoCReport(
            decision=Decision.GENERATE.value,
            confidence=85,
            evidence_quality="HIGH",
            reproduction_steps=[
                {"step": 1, "action": "Send request", "evidence_refs": ["EV-1"]},
            ],
        )
        assert report.decision == "GENERATE"
        assert report.confidence == 85
        assert report.evidence_quality == "HIGH"
        assert len(report.reproduction_steps) == 1
        assert hasattr(report, 'observed_behavior')
        assert hasattr(report, 'impact_evidence')
        assert hasattr(report, 'triage_prediction')

    @pytest.mark.asyncio
    async def test_create_poc_authorization_gate(self, loop):
        """Verify authorization gate blocks non-ALLOW scope."""
        from sentinel_x_ultra.bug_bounty.exploitation import ExploitationAgent
        agent = ExploitationAgent()
        finding = {
            "id": "test-001", "title": "Test",
            "scope_status": "BLOCK",
            "policy_status": "ALLOW",
            "validation_status": "PROMOTE",
        }
        poc = await agent.create_poc(finding)
        assert poc.decision == "BLOCK"  # Gate should block

    @pytest.mark.asyncio
    async def test_create_poc_passes_valid(self, loop):
        """Verify valid finding passes authorization gate."""
        from sentinel_x_ultra.bug_bounty.exploitation import ExploitationAgent
        agent = ExploitationAgent()
        finding = {
            "id": "test-002", "title": "XSS",
            "target": "example.com",
            "scope_status": "ALLOW",
            "policy_status": "ALLOW",
            "validation_status": "PROMOTE",
            "evidence": {"req": "GET /search", "resp": "200 OK"},
        }
        poc = await agent.create_poc(finding)
        assert poc is not None
        assert hasattr(poc, 'report')


# =============================================================================
# Agent 9 — Analysis (Evidence-Driven)
# =============================================================================

class TestAnalysis:
    """Agent 9: Evidence-Driven Security Analysis Engine (v2)."""

    def test_imports(self):
        """Verify AnalysisAgent and key types are importable."""
        from sentinel_x_ultra.bug_bounty.analysis import (
            AnalysisAgent, FindingAnalysis, DetailedAnalysis,
            CVSSEntry, CVSSMetrics, CWEInfo, CWEAlternative,
            OWASPInfo, OWASPAlternative, CVSSScore,
        )
        assert AnalysisAgent is not None
        assert FindingAnalysis is not None
        assert DetailedAnalysis is not None

    def test_finding_analysis_backward_compat(self):
        """Verify FindingAnalysis preserves all original fields."""
        from sentinel_x_ultra.bug_bounty.analysis import FindingAnalysis
        fa = FindingAnalysis(title="XSS Test")
        assert fa.title == "XSS Test"
        assert hasattr(fa, 'cvss')
        assert hasattr(fa, 'cwe_primary')
        assert hasattr(fa, 'cwe_secondary')
        assert hasattr(fa, 'owasp_mapping')
        assert hasattr(fa, 'exploitability')
        assert hasattr(fa, 'remediation_priority')
        assert hasattr(fa, 'business_impact')
        # New fields
        assert hasattr(fa, 'detailed')
        assert hasattr(fa, 'decision')
        assert hasattr(fa, 'confidence')
        assert hasattr(fa, 'evidence_used')
        assert hasattr(fa, 'uncertainties')

    def test_cvss_metrics_defaults_to_unknown(self):
        """Verify CVSSMetrics defaults to UNKNOWN (anti-hallucination)."""
        from sentinel_x_ultra.bug_bounty.analysis import CVSSMetrics
        m = CVSSMetrics()
        assert m.AV == "UNKNOWN"
        assert m.AC == "UNKNOWN"
        assert m.PR == "UNKNOWN"
        assert m.UI == "UNKNOWN"
        assert m.S == "UNKNOWN"
        assert m.C == "UNKNOWN"
        assert m.I == "UNKNOWN"
        assert m.A == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_validate_gate_blocks_non_promote(self, loop):
        """Verify validation gate blocks non-PROMOTE findings."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent
        agent = AnalysisAgent()
        finding = {"id": "t1", "title": "Test", "validation_status": "REVIEW", "evidence": {"r": "GET /"}}
        result = await agent.analyze(finding)
        assert result.decision == "REVIEW"

    @pytest.mark.asyncio
    async def test_validate_gate_blocks_missing_evidence(self, loop):
        """Verify missing evidence leads to BLOCK."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent
        agent = AnalysisAgent()
        finding = {"id": "t2", "title": "No Evidence", "validation_status": "PROMOTE"}
        result = await agent.analyze(finding)
        assert result.decision == "BLOCK"

    @pytest.mark.asyncio
    async def test_full_analysis_with_evidence(self, loop):
        """Verify full analysis produces valid output with evidence."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent
        agent = AnalysisAgent()
        finding = {
            "id": "t3", "title": "XSS",
            "validation_status": "PROMOTE",
            "evidence": {"req": "GET /search?q=<script>alert(1)</script>", "resp": "200 OK with <script>alert(1)</script>"},
            "observed_behavior": [{"claim": "JavaScript executes in victim browser"}],
            "reproduction_steps": [{"action": "Send request with XSS payload"}],
            "impact_evidence": [{"claim": "Unauthorized script execution"}],
            "demonstrated_impact": ["XSS executed successfully"],
        }
        result = await agent.analyze(finding)
        assert result.decision in ("GENERATE", "REVIEW")
        assert result.cvss is not None
        assert result.cvss.base_score > 0
        assert result.cwe_primary != ""
        assert 0 <= result.confidence <= 100

    def test_cvss_coefficients_not_inverted(self):
        """Verify CVSS coefficients are correct: unauthenticated > authenticated."""
        from sentinel_x_ultra.bug_bounty.analysis import AnalysisAgent, CVSSMetrics
        agent = AnalysisAgent()
        m1 = CVSSMetrics(AV='Network', AC='Low', PR='None', UI='None', S='Unchanged', C='High', I='None', A='None')
        m2 = CVSSMetrics(AV='Network', AC='Low', PR='High', UI='Required', S='Unchanged', C='Low', I='None', A='None')
        score1 = agent._calculate_cvss_score(m1)  # unauthenticated
        score2 = agent._calculate_cvss_score(m2)  # requires admin + user click
        assert score1 >= score2, f"CVSS inversion: {score1} < {score2}"


# =============================================================================
# Agent 10 — Report Generation (Strict Evidence-to-Blank.md)
# =============================================================================

class TestReportGeneration:
    """Agent 10: Strict Evidence-to-Blank.md Rendering Engine."""

    def test_imports(self):
        """Verify ReportGenerationAgent and VulnerabilityReport are importable."""
        from sentinel_x_ultra.bug_bounty.report_generation import (
            ReportGenerationAgent, VulnerabilityReport,
            UNKNOWN, NOT_DEMONSTRATED, NOT_CAPTURED, NOT_PROVIDED,
        )
        assert ReportGenerationAgent is not None
        assert VulnerabilityReport is not None
        assert UNKNOWN == "UNKNOWN"
        assert NOT_DEMONSTRATED == "NOT DEMONSTRATED"
        assert NOT_CAPTURED == "NOT CAPTURED"
        assert NOT_PROVIDED == "NOT PROVIDED"

    def test_vulnerability_report_backward_compat(self):
        """Verify VulnerabilityReport preserves all original fields."""
        from sentinel_x_ultra.bug_bounty.report_generation import VulnerabilityReport
        report = VulnerabilityReport(title="XSS Found", generated_at="2024-01-01")
        assert report.title == "XSS Found"
        assert hasattr(report, 'issue_description')
        assert hasattr(report, 'affected_url')
        assert hasattr(report, 'risk_rating')
        assert hasattr(report, 'cvss')
        assert hasattr(report, 'impact')
        assert hasattr(report, 'attack_scenario')
        assert hasattr(report, 'steps_to_reproduce')
        assert hasattr(report, 'request')
        assert hasattr(report, 'response')
        assert hasattr(report, 'screenshots')
        assert hasattr(report, 'references')
        assert hasattr(report, 'generated_at')
        # New field
        assert hasattr(report, 'decision')

    def test_render_markdown_uses_strict_placeholders(self):
        """Verify render_markdown uses UNKNOWN/NOT_DEMONSTRATED/NOT_CAPTURED/NOT_PROVIDED."""
        from sentinel_x_ultra.bug_bounty.report_generation import VulnerabilityReport, UNKNOWN, NOT_DEMONSTRATED, NOT_CAPTURED, NOT_PROVIDED
        report = VulnerabilityReport(generated_at="2024-01-01")
        md = report.render_markdown()
        assert UNKNOWN in md
        assert NOT_DEMONSTRATED in md
        assert NOT_CAPTURED in md
        assert NOT_PROVIDED in md

    def test_screenshots_omitted_when_empty(self):
        """Verify screenshots section is omitted when no screenshots provided."""
        from sentinel_x_ultra.bug_bounty.report_generation import VulnerabilityReport
        report = VulnerabilityReport(title="Test", generated_at="2024-01-01")
        md = report.render_markdown()
        assert "## Screenshots" not in md

    def test_screenshots_rendered_when_provided(self):
        """Verify screenshots section is rendered when data exists."""
        from sentinel_x_ultra.bug_bounty.report_generation import VulnerabilityReport
        report = VulnerabilityReport(title="Test", screenshots=["https://example.com/shot.png"], generated_at="2024-01-01")
        md = report.render_markdown()
        assert "## Screenshots" in md
        assert "shot.png" in md

    @pytest.mark.asyncio
    async def test_hard_gate_rejects_missing_fields(self, loop):
        """Verify hard gate rejects findings without validation/scope/policy status."""
        from sentinel_x_ultra.bug_bounty.report_generation import ReportGenerationAgent
        agent = ReportGenerationAgent()
        finding = {"title": "Test"}
        result = await agent.generate_report(finding, {}, {})
        assert result.decision == "REVIEW"
        assert "REVIEW" in result.issue_description

    @pytest.mark.asyncio
    async def test_hard_gate_passes_with_gate_fields(self, loop):
        """Verify hard gate passes when all required fields are present."""
        from sentinel_x_ultra.bug_bounty.report_generation import ReportGenerationAgent
        agent = ReportGenerationAgent()
        finding = {
            "title": "XSS",
            "validation_status": "PROMOTE",
            "scope_status": "ALLOW",
            "policy_status": "ALLOW",
        }
        result = await agent.generate_report(finding, {}, {})
        # Decision will be REVIEW because no PoC steps
        assert result.decision == "REVIEW"

    @pytest.mark.asyncio
    async def test_priority_poc_before_finding(self, loop):
        """Verify PoC impact_demonstration takes priority over finding description."""
        from sentinel_x_ultra.bug_bounty.report_generation import ReportGenerationAgent
        agent = ReportGenerationAgent()
        finding = {
            "title": "Test", "description": "Finding desc",
            "validation_status": "PROMOTE", "scope_status": "ALLOW", "policy_status": "ALLOW",
        }
        poc = {"impact_demonstration": "PoC impact", "target": "https://poc.com"}
        result = await agent.generate_report(finding, {}, poc)
        assert "PoC impact" in result.issue_description
        assert "Finding desc" not in result.issue_description

    @pytest.mark.asyncio
    async def test_conflict_detection_severity(self, loop):
        """Verify severity conflicts trigger REVIEW."""
        from sentinel_x_ultra.bug_bounty.report_generation import ReportGenerationAgent
        agent = ReportGenerationAgent()
        finding = {"title": "C", "severity": "Low",
            "validation_status": "PROMOTE", "scope_status": "ALLOW", "policy_status": "ALLOW"}
        analysis = {"severity": "Critical"}
        result = await agent.generate_report(finding, analysis, {})
        assert result.decision == "REVIEW"
        assert "Severity conflict" in result.issue_description

    @pytest.mark.asyncio
    async def test_conflict_detection_impact_contradiction(self, loop):
        """Verify impact contradictions trigger REVIEW."""
        from sentinel_x_ultra.bug_bounty.report_generation import ReportGenerationAgent
        agent = ReportGenerationAgent()
        finding = {"title": "D", "description": "data exposed at vulnerable endpoint", "impact": "false positive, no exposure",
            "validation_status": "PROMOTE", "scope_status": "ALLOW", "policy_status": "ALLOW"}
        result = await agent.generate_report(finding, {}, {})
        assert result.decision == "REVIEW"
        assert "Impact contradiction" in result.issue_description

    def test_blank_md_format_structure(self):
        """Verify the Blank.md report has all required sections."""
        from sentinel_x_ultra.bug_bounty.report_generation import VulnerabilityReport
        report = VulnerabilityReport(
            title="XSS", issue_description="Reflected XSS", affected_url="https://x.com",
            risk_rating="High", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            impact="Data compromised", attack_scenario="Sent payload",
            steps_to_reproduce=["Step 1"], request="GET /", response="200 OK",
            affected_demographic="", recommended_fix="Sanitize input",
            references=["CWE: CWE-79", "OWASP: A03:2021 Injection"],
            screenshots=[], generated_at="2024-01-01",
        )
        md = report.render_markdown()
        assert "# XSS" in md
        assert "## Issue Description" in md
        assert "## Affected Asset / URL" in md
        assert "## Risk Rating" in md
        assert "## CVSS 3.1 Score" in md
        assert "## Impact" in md
        assert "## Attack Scenario" in md
        assert "## Steps to Reproduce (PoC)" in md
        assert "## Request" in md
        assert "## Response" in md
        assert "## Affected Users / Demographic" in md
        assert "## Recommended Fix" in md
        assert "## References" in md
        assert "**Generated At:**" in md


# =============================================================================
# Orchestrator Integration
# =============================================================================

class TestOrchestrator:
    """Bug Bounty Orchestrator — full 10-agent pipeline integration."""

    def test_imports(self):
        """Verify orchestrator and pipeline result are importable."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator, BugBountyPipelineResult
        assert BugBountyOrchestrator is not None
        assert BugBountyPipelineResult is not None

    def test_orchestrator_initialization(self):
        """Verify orchestrator initializes all 10 agents."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator
        orch = BugBountyOrchestrator()
        assert orch.agent_1 is not None
        assert orch.agent_2 is not None
        assert orch.agent_3 is not None
        assert orch.agent_4 is not None
        assert orch.agent_5 is not None
        assert orch.agent_6 is not None
        assert orch.agent_7 is not None
        assert orch.agent_8 is not None
        assert orch.agent_9 is not None
        assert orch.agent_10 is not None

    def test_ethical_rules_loaded(self):
        """Verify ethical rules are loaded on init."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator
        orch = BugBountyOrchestrator()
        assert len(orch.ethical_rules) >= 5
        assert any("NEVER" in rule for rule in orch.ethical_rules)
        assert any("ALWAYS" in rule for rule in orch.ethical_rules)

    def test_system_prompt_built(self):
        """Verify system prompt combines all sections."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator
        orch = BugBountyOrchestrator()
        assert len(orch.system_prompt) > 100
        assert "FOUNDATIONAL" in orch.system_prompt

    def test_pipeline_result_dataclass(self):
        """Verify BugBountyPipelineResult has all expected fields."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyPipelineResult
        result = BugBountyPipelineResult(pipeline_id="test-123")
        assert result.pipeline_id == "test-123"
        assert hasattr(result, 'program_intel')
        assert hasattr(result, 'policy_rules')
        assert hasattr(result, 'passive_intel')
        assert hasattr(result, 'active_enum')
        assert hasattr(result, 'scan_results')
        assert hasattr(result, 'validation_results')
        assert hasattr(result, 'proofs_of_concept')
        assert hasattr(result, 'analyses')
        assert hasattr(result, 'reports')
        assert hasattr(result, 'errors')

    @pytest.mark.asyncio
    async def test_agent_9_now_passes_evidence(self, loop):
        """Verify _run_agent_9 now passes evidence data for real analysis."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator
        from sentinel_x_ultra.bug_bounty.exploitation import ProofOfConcept, PoCReport, Decision
        orch = BugBountyOrchestrator()

        # Create a PoC with evidence data
        poc_report = PoCReport(
            decision=Decision.GENERATE.value, confidence=85, evidence_quality='HIGH',
            reproduction_steps=[
                {'step': 1, 'action': 'Send GET /search?q=<script>alert(1)</script>', 'evidence_refs': ['EV-1']},
            ],
            observed_behavior=[{'claim': 'JavaScript executes', 'evidence_refs': ['EV-2']}],
            impact_evidence=[{'claim': 'XSS executed', 'evidence_refs': ['EV-1']}],
        )
        poc = ProofOfConcept(finding_id='f1', title='XSS', report=poc_report)
        poc.impact_demonstration = 'XSS in browser'

        # Run agent 9 via orchestrator
        analysis = await orch._run_agent_9(poc)
        assert analysis is not None
        # With evidence data, Agent 9 should produce meaningful analysis
        assert hasattr(analysis, 'cwe_primary')
        assert hasattr(analysis, 'detailed')

    @pytest.mark.asyncio
    async def test_end_to_end_report_via_orchestrator(self, loop):
        """Verify full PoC->Analysis->Report chain via orchestrator produces a valid report."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator
        from sentinel_x_ultra.bug_bounty.exploitation import ProofOfConcept, PoCReport, Decision
        orch = BugBountyOrchestrator()

        # Create PoC with evidence
        poc_report = PoCReport(
            decision=Decision.GENERATE.value, confidence=85, evidence_quality='HIGH',
            reproduction_steps=[
                {'step': 1, 'action': 'Send GET /search?q=<script>', 'evidence_refs': ['EV-1']},
                {'step': 2, 'action': 'Observe script execution', 'evidence_refs': ['EV-2']},
            ],
            observed_behavior=[{'claim': 'JavaScript executes', 'evidence_refs': ['EV-2']}],
            impact_evidence=[{'claim': 'XSS in user session', 'evidence_refs': ['EV-1']}],
        )
        poc = ProofOfConcept(finding_id='f1', title='XSS Vulnerability', report=poc_report)
        poc.impact_demonstration = 'XSS executes in victim browser'

        # Run Agent 9 via orchestrator
        analysis = await orch._run_agent_9(poc)

        # Build finding dict for Agent 10
        finding = {
            'title': poc.title,
            'endpoint': 'https://example.com/search',
            'description': poc.impact_demonstration,
            'validation_status': 'PROMOTE',
            'scope_status': 'ALLOW',
            'policy_status': 'ALLOW',
        }

        # Run Agent 10 via orchestrator
        report = await orch._run_agent_10(finding, analysis, poc)
        assert report is not None
        from sentinel_x_ultra.bug_bounty.report_generation import VulnerabilityReport
        assert isinstance(report, VulnerabilityReport)
        assert report.decision == "GENERATE"

        # Verify report content
        assert "XSS" in report.title
        assert "CWE" in str(report.references) or "OWASP" in str(report.references)
        assert len(report.steps_to_reproduce) >= 1

        # Render and verify Blank.md
        md = report.render_markdown()
        assert "## Steps to Reproduce (PoC)" in md
        assert "## CVSS 3.1 Score" in md
        assert "## References" in md
        assert "## Screenshots" not in md  # No screenshots provided

    @pytest.mark.asyncio
    async def test_pipeline_runs_without_crashing(self, loop):
        """Verify run_pipeline executes without raising exceptions."""
        from sentinel_x_ultra.bug_bounty.orchestrator import BugBountyOrchestrator
        orch = BugBountyOrchestrator()
        result = await orch.run_pipeline(target_domain='example.com')
        assert result is not None
        assert result.pipeline_id is not None


# =============================================================================
# System Prompts & Foundation
# =============================================================================

class TestSystemPrompts:
    """System prompts and foundational principles."""

    def test_imports(self):
        """Verify system prompt exports are importable."""
        from sentinel_x_ultra.bug_bounty.system_prompts import (
            FOUNDATIONAL_PRINCIPLES, AGENT_ARCHITECTURE, DECISION_HIERARCHY,
            get_full_system_prompt,
        )
        assert len(FOUNDATIONAL_PRINCIPLES) > 50
        assert len(AGENT_ARCHITECTURE) > 50
        assert len(DECISION_HIERARCHY) > 50

    def test_full_system_prompt(self):
        """Verify get_full_system_prompt combines all sections."""
        from sentinel_x_ultra.bug_bounty.system_prompts import get_full_system_prompt
        prompt = get_full_system_prompt()
        assert len(prompt) > 200
        assert "Agent" in prompt
