"""Tests for the V3 Coverage Tracking Engine and Agent Model Registry."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PKG_PARENT = Path(__file__).resolve().parents[2]
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from sentinel_x_ultra.coverage import (  # noqa: E402
    CoverageEngine,
    DIMENSIONS,
    DIMENSION_LABELS,
    DEFAULT_BASELINE,
)
from sentinel_x_ultra.agent_models import (  # noqa: E402
    AgentModelRegistry,
    DEFAULT_AGENT_MODELS,
    SCHEMA_VERSION,
)


# ---------------------------------------------------------------------------
# Coverage Tracking Engine
# ---------------------------------------------------------------------------


class TestCoverageEngine:
    def test_dimensions_match_v3_spec(self):
        # The seven V3 dimensions
        for d in (
            "authentication", "authorization", "business_logic", "api",
            "documentation", "architecture", "dependency",
        ):
            assert d in DIMENSIONS
        assert len(DIMENSIONS) == 7

    def test_dimension_labels_have_titles(self):
        assert DIMENSION_LABELS["authentication"] == "Authentication"
        assert DIMENSION_LABELS["business_logic"] == "Business Logic"

    def test_empty_project_yields_zero_coverage(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        report = eng.compute("p1")
        assert report.metrics == {d: 0.0 for d in DIMENSIONS}
        assert report.overall() == 0.0

    def test_auth_files_boost_authentication_coverage(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        # Give the project lots of auth files so we exceed the default baseline of 5
        auth_files = [
            f"src/auth/login{i}.py" for i in range(8)
        ]
        report = eng.compute("p2", workspace_files=auth_files)
        assert report.metrics["authentication"] == 1.0
        assert report.metrics["dependency"] == 0.0
        assert report.overall() > 0

    def test_dependency_files_boost_dependency_coverage(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        files = [
            "package.json", "package-lock.json", "requirements.txt",
            "pyproject.toml", "Cargo.toml", "Cargo.lock",
        ]
        report = eng.compute("p3", workspace_files=files)
        assert report.metrics["dependency"] == 1.0

    def test_baseline_overrides_default(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        # With baseline=2 for authentication, even 2 files saturate the metric
        report = eng.compute(
            "p4",
            workspace_files=["src/auth/login.py", "src/auth/session.py"],
            baseline={"authentication": 2},
        )
        assert report.metrics["authentication"] == 1.0

    def test_findings_boost_business_logic_and_api(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        biz_findings = [
            {"title": "Order total bypass", "description": "Workflow pricing logic"},
            {"title": "Discount stacking", "description": "Payment bypass"},
        ]
        api_findings = [
            {"title": "REST endpoint missing auth", "description": "API route exposed"},
        ]
        report = eng.compute(
            "p5",
            findings=biz_findings + api_findings,
            baseline={"business_logic": 2, "api": 1},
        )
        assert report.metrics["business_logic"] == 1.0
        assert report.metrics["api"] == 1.0

    def test_report_persists_to_disk(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        eng.compute("p6", workspace_files=["src/auth/login.py"] * 3)
        # Reload in a fresh engine
        eng2 = CoverageEngine(base_path=tmp_path)
        loaded = eng2.get("p6")
        assert loaded is not None
        assert loaded.metrics["authentication"] == pytest.approx(0.6, rel=0.01)

    def test_baseline_can_be_set_independently(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        eng.set_baseline("p7", {"authentication": 100})
        loaded = eng.get("p7")
        assert loaded is not None
        assert loaded.details["__baseline__"]["authentication"] == 100

    def test_as_lines_for_report(self, tmp_path: Path):
        eng = CoverageEngine(base_path=tmp_path)
        report = eng.compute("p8", workspace_files=["src/auth/login.py"] * 5)
        lines = report.as_lines()
        # 7 dimensions + 1 overall
        assert len(lines) == 8
        assert any("Authentication" in l for l in lines)
        assert any("Overall" in l for l in lines)


# ---------------------------------------------------------------------------
# Agent Model Registry (persistent file)
# ---------------------------------------------------------------------------


class TestAgentModelRegistry:
    def test_creates_file_with_defaults(self, tmp_path: Path):
        path = tmp_path / "agent_models.json"
        reg = AgentModelRegistry(path)
        assert path.exists()
        agents = reg.list()
        assert len(agents) >= 10  # we seed many agents
        # Check a known agent
        recon = reg.get("recon")
        assert recon is not None
        assert recon.model  # non-empty
        assert recon.purpose in ("reasoning", "code", "report")

    def test_assign_persists(self, tmp_path: Path):
        path = tmp_path / "agent_models.json"
        reg = AgentModelRegistry(path)
        reg.assign("recon", "llama3.1:70b", "code")
        # Reload from disk in a new instance
        reg2 = AgentModelRegistry(path)
        a = reg2.get("recon")
        assert a is not None
        assert a.model == "llama3.1:70b"
        assert a.purpose == "code"

    def test_bulk_assign(self, tmp_path: Path):
        path = tmp_path / "agent_models.json"
        reg = AgentModelRegistry(path)
        reg.bulk_assign({
            "recon":       {"model": "m1", "purpose": "reasoning"},
            "code_review": {"model": "m2", "purpose": "code"},
        })
        reg2 = AgentModelRegistry(path)
        assert reg2.get("recon").model == "m1"
        assert reg2.get("code_review").model == "m2"

    def test_reset_restores_defaults(self, tmp_path: Path):
        path = tmp_path / "agent_models.json"
        reg = AgentModelRegistry(path)
        reg.assign("recon", "custom-model", "code")
        reg.reset()
        recon = reg.get("recon")
        assert recon.model == DEFAULT_AGENT_MODELS["recon"]["model"]
        assert recon.purpose == DEFAULT_AGENT_MODELS["recon"]["purpose"]

    def test_assign_validates_inputs(self, tmp_path: Path):
        path = tmp_path / "agent_models.json"
        reg = AgentModelRegistry(path)
        with pytest.raises(ValueError):
            reg.assign("", "x")
        with pytest.raises(ValueError):
            reg.assign("recon", "")

    def test_persisted_file_has_schema_version(self, tmp_path: Path):
        path = tmp_path / "agent_models.json"
        AgentModelRegistry(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["schema_version"] == SCHEMA_VERSION
        assert "updated_at" in data
        assert "agents" in data
        # Every default agent present
        for agent in DEFAULT_AGENT_MODELS:
            assert agent in data["agents"]
            assert "model" in data["agents"][agent]
            assert "purpose" in data["agents"][agent]
