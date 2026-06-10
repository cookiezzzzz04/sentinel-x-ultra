"""Tests for the V3 Methodology, Validation, and Report modules."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG_PARENT = Path(__file__).resolve().parents[2]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from sentinel_x_ultra.methodology import (  # noqa: E402
    AWESOME_BBB_TOOLS_CATEGORIES,
    BLANK_MD_TEMPLATE_SECTIONS,
    BURP_SUITE_PHASES,
    MethodologyReferenceEngine,
    ReferenceKind,
    get_methodology_engine,
)
from sentinel_x_ultra.validation import (  # noqa: E402
    CandidateFinding,
    EvidenceItem,
    FindingStatus,
    FindingValidationPipeline,
    PipelineStage,
    get_validation_pipeline,
)
from sentinel_x_ultra.report_template import (  # noqa: E402
    BlankReportRenderer,
    ReportFinding,
    finding_to_report_finding,
)


# ---------------------------------------------------------------------------
# Methodology Reference Engine
# ---------------------------------------------------------------------------


class TestMethodologyReferenceEngine:
    def test_seeds_three_v3_references(self):
        eng = MethodologyReferenceEngine()
        refs = eng.list_references()
        assert len(refs) == 3
        titles = {r.title for r in refs}
        assert any("ZephrFish" in t for t in titles)
        assert any("Burp" in t for t in titles)
        assert any("Awesome" in t for t in titles)

    def test_report_template_sections_match_blank_md(self):
        # The 13 sections the V3 spec expects from Blank.md
        for s in (
            "Title", "Issue Description", "Affected URL/Area",
            "Risk Rating", "Impact", "Attack Scenario",
            "Steps to Reproduce/PoC", "Request", "Response",
            "Screenshots", "Affected Demographic/User Base",
            "Recommended Fix", "References",
        ):
            assert s in BLANK_MD_TEMPLATE_SECTIONS

    def test_burp_suite_phases_present(self):
        assert "Setup & Configuration (FoxyProxy, CA Certificate, Lab)" in BURP_SUITE_PHASES
        assert "Interception & Modification (Proxy, Repeater)" in BURP_SUITE_PHASES

    def test_awesome_categories_present(self):
        for c in AWESOME_BBB_TOOLS_CATEGORIES:
            assert c  # non-empty
        assert "Fuzzing" in str(AWESOME_BBB_TOOLS_CATEGORIES)
        assert "AI Agents" in str(AWESOME_BBB_TOOLS_CATEGORIES)

    def test_filter_by_kind(self):
        eng = MethodologyReferenceEngine()
        templates = eng.list_references(kind=ReferenceKind.REPORT_TEMPLATE)
        assert len(templates) == 1
        assert "ZephrFish" in templates[0].title

    def test_tools_index_has_seed_entries(self):
        eng = MethodologyReferenceEngine()
        tools = eng.all_tools()
        names = {t["name"] for t in tools}
        for n in ("nmap", "sqlmap", "Burp Suite", "ffuf", "httpx", "gobuster"):
            assert n in names

    def test_tools_by_category(self):
        eng = MethodologyReferenceEngine()
        fuzz = eng.tools_by_category("Fuzzing")
        names = {t["name"] for t in fuzz}
        assert "ffuf" in names and "wfuzz" in names

    def test_is_evidence_rejects_methodology_refs(self):
        # The Golden Rule: a reference URL is NOT evidence.
        assert MethodologyReferenceEngine.is_evidence(
            "https://github.com/ZephrFish/BugBountyTemplates"
        ) is False
        assert MethodologyReferenceEngine.is_evidence("") is False
        # A target-sourced source IS evidence
        assert MethodologyReferenceEngine.is_evidence("source_code:auth/login.py") is True


# ---------------------------------------------------------------------------
# Finding Validation Pipeline
# ---------------------------------------------------------------------------


def _strong_finding() -> CandidateFinding:
    return CandidateFinding(
        finding_id="f-strong",
        title="SQL Injection in /api/users search parameter",
        description=(
            "The `q` parameter of /api/users is concatenated into a SQL "
            "query without parameterization, allowing arbitrary SQL execution."
        ),
        severity="High",
        confidence="High",
        evidence=[
            EvidenceItem(
                source="source_code:src/api/users.py:42",
                location="src/api/users.py line 42",
                confidence="high",
                context="cursor.execute(f\"SELECT * FROM users WHERE name='{q}'\")",
            ),
            EvidenceItem(
                source="http:POST /api/users?q=' OR 1=1--",
                location="runtime response to /api/users",
                confidence="high",
                context="REQUEST POST /api/users HTTP/1.1\\nq=' OR 1=1--",
            ),
        ],
        affected_components=["src/api/users.py", "/api/users"],
        source_agent="code_review",
    )


class TestFindingValidationPipeline:
    def test_strong_finding_promoted(self):
        pipe = FindingValidationPipeline()
        outcome = pipe.submit(_strong_finding())
        assert outcome.status == FindingStatus.PROMOTED
        assert all(r.passed for r in outcome.stage_results)
        assert outcome.promoted_at

    def test_finding_without_evidence_goes_to_review_queue(self):
        pipe = FindingValidationPipeline()
        f = _strong_finding()
        f.evidence = []
        outcome = pipe.submit(f)
        assert outcome.status == FindingStatus.REVIEW_QUEUE
        assert outcome.stage_results[0].stage == PipelineStage.EVIDENCE
        assert "INSUFFICIENT_EVIDENCE" in outcome.stage_results[0].notes

    def test_finding_with_only_methodology_evidence_rejected(self):
        # Golden Rule: a methodology ref is NOT evidence.
        pipe = FindingValidationPipeline()
        f = _strong_finding()
        f.evidence = [
            EvidenceItem(
                source="https://github.com/ZephrFish/BugBountyTemplates",
                location="n/a",
                confidence="high",
                context="report template",
            )
        ]
        outcome = pipe.submit(f)
        assert outcome.status == FindingStatus.REVIEW_QUEUE
        assert "methodology" in outcome.stage_results[0].notes.lower()

    def test_evidence_with_missing_fields_fails(self):
        pipe = FindingValidationPipeline()
        f = _strong_finding()
        f.evidence = [
            EvidenceItem(source="source:auth.py", location="", confidence="high", context="x")
        ]
        outcome = pipe.submit(f)
        assert outcome.status == FindingStatus.REVIEW_QUEUE
        assert "missing" in outcome.stage_results[0].notes.lower()

    def test_vague_finding_caught_by_debate(self):
        pipe = FindingValidationPipeline()
        f = _strong_finding()
        f.title = "x"
        f.affected_components = []
        outcome = pipe.submit(f)
        assert outcome.status == FindingStatus.REVIEW_QUEUE
        # First failing stage is evidence OR debate (here evidence passes
        # because we kept the evidence, debate fails on vague title).
        failed = [r for r in outcome.stage_results if not r.passed]
        assert failed[0].stage in (PipelineStage.DEBATE, PipelineStage.EVIDENCE)

    def test_invalid_severity_caught_by_critique(self):
        pipe = FindingValidationPipeline()
        f = _strong_finding()
        f.severity = "Catastrophic"  # invalid
        outcome = pipe.submit(f)
        assert outcome.status == FindingStatus.REVIEW_QUEUE
        # Critique stage should be the failing one
        failed = [r for r in outcome.stage_results if not r.passed]
        assert any(r.stage == PipelineStage.CRITIQUE for r in failed)

    def test_retry_promotes_after_finding_is_fixed(self):
        pipe = FindingValidationPipeline()
        f = CandidateFinding(
            finding_id="f-broken",
            title="x",  # too vague → debate fails
            description="d",
            severity="Medium",
            confidence="Medium",
            evidence=[],
        )
        outcome = pipe.submit(f)
        assert outcome.status == FindingStatus.REVIEW_QUEUE
        # Fix the finding and retry
        f.title = "Concrete title about authentication bypass"
        f.description = "An authenticated user can access admin endpoints via /api/admin/users."
        f.evidence = [
            EvidenceItem(
                source="http:GET /api/admin/users with user token",
                location="/api/admin/users",
                confidence="high",
                context="returned 200 with admin payload",
            )
        ]
        f.affected_components = ["/api/admin/users"]
        new_outcome = pipe.retry("f-broken")
        assert new_outcome is not None
        assert new_outcome.status == FindingStatus.PROMOTED

    def test_pipeline_records_all_stages(self):
        pipe = FindingValidationPipeline()
        outcome = pipe.submit(_strong_finding())
        stages = {r.stage for r in outcome.stage_results}
        # All stages except REPORT (which is the orchestrator's responsibility)
        for stage in (
            PipelineStage.EVIDENCE, PipelineStage.DEBATE, PipelineStage.CRITIQUE,
            PipelineStage.CORRELATION, PipelineStage.CONFIDENCE, PipelineStage.QA,
        ):
            assert stage in stages


# ---------------------------------------------------------------------------
# Report Template (Blank.md)
# ---------------------------------------------------------------------------


class TestBlankReportRenderer:
    def test_render_full_report_includes_all_blank_md_sections(self):
        renderer = BlankReportRenderer(project_name="Acme")
        f = ReportFinding(
            title="SQL Injection in /api/users",
            issue_description="Parameterized queries are missing.",
            affected_url="/api/users",
            risk_rating="High",
            impact="Data exfiltration",
            attack_scenario="Attacker sends crafted 'q' param.",
            steps_to_reproduce=["GET /api/users?q=' OR 1=1--"],
            recommended_fix="Use parameterized queries.",
            evidence=[{"source": "src/api/users.py", "location": "L42",
                        "confidence": "high", "context": "f-string SQL"}],
        )
        md = renderer.render_report([f])
        for section in (
            "# Security Assessment Report", "## Coverage", "## Findings",
            "## Issue Description", "## Affected URL/Area", "## Risk Rating",
            "### Impact", "### Attack Scenario", "## Steps to Reproduce / PoC",
            "### Request", "### Response", "### Evidence", "### Screenshots",
            "## Affected Demographic / User Base", "## Recommended Fix",
            "## References",
        ):
            assert section in md, f"Missing section: {section}"

    def test_render_executive_lists_top_risks(self):
        renderer = BlankReportRenderer(project_name="Acme")
        f1 = ReportFinding(title="SQLi", issue_description="x", affected_url="u",
                            risk_rating="Critical", impact="i", attack_scenario="a",
                            steps_to_reproduce=[], recommended_fix="r")
        f2 = ReportFinding(title="XSS", issue_description="x", affected_url="u",
                            risk_rating="Low", impact="i", attack_scenario="a",
                            steps_to_reproduce=[], recommended_fix="r")
        md = renderer.render_executive([f2, f1])
        # Critical listed before Low in the top risks
        assert md.index("SQLi") < md.index("XSS")

    def test_render_developer_includes_remediation(self):
        renderer = BlankReportRenderer(project_name="Acme")
        f = ReportFinding(title="XSS", issue_description="x", affected_url="u",
                            risk_rating="High", impact="i", attack_scenario="a",
                            steps_to_reproduce=[], recommended_fix="Escape output")
        md = renderer.render_developer([f])
        assert "Escape output" in md
        assert "XSS" in md

    def test_finding_to_report_finding_preserves_evidence(self):
        cf = _strong_finding()
        rf = finding_to_report_finding(cf)
        assert rf.title == cf.title
        assert rf.risk_rating == cf.severity
        assert len(rf.evidence) == len(cf.evidence)
        assert rf.evidence[0]["source"] == cf.evidence[0].source
