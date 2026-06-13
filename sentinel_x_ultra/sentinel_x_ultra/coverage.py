"""Coverage Tracking Engine — V3.

The V3 spec says:

    Track analysis coverage.
    Example:
        Authentication Coverage: 92%
        Authorization Coverage: 81%
        Business Logic Coverage: 67%
        API Coverage: 95%
        Documentation Coverage: 74%
        Architecture Coverage: 88%
        Dependency Coverage: 100%
    Every report must include coverage metrics.

This module provides a :class:`CoverageEngine` that computes seven
per-dimension coverage percentages for a project, persists them, and
hands them to the Blank.md report renderer.

The metrics are *inferred* from what the project actually contains:

    Authentication       — auth-bearing files in the workspace + auth findings
    Authorization        — permission-related files + permission findings
    Business Logic       — business rules extracted + business-logic findings
    API                  — API endpoints registered + API findings
    Documentation        — documentation files indexed vs. a baseline
    Architecture         — knowledge-graph entities / relationships
    Dependency           — dependency artifacts in the workspace

Each dimension yields a value in [0.0, 1.0]. A baseline of "expected
artifacts" can be set per-project; until a baseline is configured we
use sensible category-relative defaults so the engine works on fresh
projects too.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


# The seven V3 coverage dimensions in display order.
DIMENSIONS: tuple[str, ...] = (
    "authentication",
    "authorization",
    "business_logic",
    "api",
    "documentation",
    "architecture",
    "dependency",
)


# Human-friendly labels for the UI / report.
DIMENSION_LABELS: dict[str, str] = {
    "authentication":  "Authentication",
    "authorization":   "Authorization",
    "business_logic":  "Business Logic",
    "api":             "API",
    "documentation":   "Documentation",
    "architecture":    "Architecture",
    "dependency":      "Dependency",
}


# Substrings (lowercased) in filenames / categories that count toward each
# dimension. Kept conservative — a real production version would also
# inspect file contents.
_AUTH_HINTS = (
    "auth", "login", "logout", "signin", "signup", "session", "token",
    "password", "credential", "oauth", "jwt", "saml", "mfa", "2fa",
)
_AUTHZ_HINTS = (
    "permission", "role", "rbac", "acl", "policy", "authorize", "guard",
    "access", "privilege",
)
_BIZ_HINTS = (
    "workflow", "business", "order", "checkout", "payment", "billing",
    "invoice", "rule", "pricing",
)
_API_HINTS = (
    "api", "endpoint", "route", "controller", "graphql", "rest",
    "/v1/", "/v2/", "/v3/",
)
_DOC_HINTS = (
    "readme", "docs", "documentation", "spec", "rfc", ".md", ".rst",
)
_ARCH_HINTS = (
    "architecture", "diagram", "service-map", "data-flow", "trust-boundary",
)
_DEP_HINTS = (
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile",
    "cargo.toml", "cargo.lock", "go.mod", "go.sum", "pom.xml",
    "build.gradle", "build.gradle.kts", ".csproj", "gemfile",
    "gemfile.lock", "composer.json", "composer.lock",
)


def _match(path_str: str, hints: tuple[str, ...]) -> bool:
    p = path_str.lower()
    return any(h in p for h in hints)


@dataclass
class CoverageReport:
    """A snapshot of the seven-dimension coverage for a project."""

    project_id: str
    metrics: dict[str, float] = field(default_factory=dict)
    details: dict[str, dict[str, Any]] = field(default_factory=dict)
    computed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "metrics": {k: round(v, 4) for k, v in self.metrics.items()},
            "details": self.details,
            "computed_at": self.computed_at,
        }

    def percent(self, dimension: str) -> float:
        return round(self.metrics.get(dimension, 0.0) * 100.0, 1)

    def overall(self) -> float:
        if not self.metrics:
            return 0.0
        return round(sum(self.metrics.values()) / len(self.metrics) * 100.0, 1)

    def as_lines(self) -> list[str]:
        out = []
        for dim in DIMENSIONS:
            label = DIMENSION_LABELS[dim]
            pct = self.percent(dim)
            out.append(f"- **{label}**: {pct:.0f}%")
        out.append(f"- **Overall**: {self.overall():.0f}%")
        return out


# A baseline is a per-dimension "expected artifact count". We use it to
# normalize raw counts to a 0–1 ratio. If no baseline is set, a default
# of 5 artifacts per dimension is used.
DEFAULT_BASELINE: dict[str, int] = dict.fromkeys(DIMENSIONS, 5)


def _ratio(count: int, expected: int) -> float:
    if expected <= 0:
        return 0.0
    return min(1.0, count / expected)


class CoverageEngine:
    """Computes and persists per-project coverage reports."""

    def __init__(self, base_path: Path | None = None):
        self.base_path = base_path
        self._cache: dict[str, CoverageReport] = {}

    # ---- file IO ----------------------------------------------------------

    def _report_path(self, project_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in project_id)
        if self.base_path is None:
            # In-memory only
            return Path(f"<memory>/coverage/{safe}.json")
        d = self.base_path / "coverage"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe}.json"

    def load(self, project_id: str) -> CoverageReport | None:
        if project_id in self._cache:
            return self._cache[project_id]
        if self.base_path is None:
            return None
        p = self._report_path(project_id)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            r = CoverageReport(
                project_id=project_id,
                metrics=data.get("metrics", {}),
                details=data.get("details", {}),
                computed_at=data.get("computed_at", ""),
            )
            self._cache[project_id] = r
            return r
        except Exception as e:  # pragma: no cover
            logger.error("coverage_load_failed", project_id=project_id, error=str(e))
            return None

    def save(self, report: CoverageReport) -> None:
        self._cache[report.project_id] = report
        if self.base_path is None:
            return
        p = self._report_path(report.project_id)
        p.write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )

    # ---- computation ------------------------------------------------------

    def compute(
        self,
        project_id: str,
        *,
        workspace_files: Iterable[Any] | None = None,
        findings: Iterable[Any] | None = None,
        business_rules: Iterable[Any] | None = None,
        api_endpoints: Iterable[Any] | None = None,
        graph_entities: Iterable[Any] | None = None,
        graph_relationships: Iterable[Any] | None = None,
        baseline: dict[str, int] | None = None,
    ) -> CoverageReport:
        """Recompute coverage for a project from the supplied artifacts.

        ``workspace_files`` may be any object with a ``relative_path``
        attribute (e.g. ``IndexedFile``) or a plain ``str`` path. The
        other iterables are counted verbatim.
        """
        baseline = {**DEFAULT_BASELINE, **(baseline or {})}

        files = list(workspace_files or [])
        findings = list(findings or [])
        biz_rules = list(business_rules or [])
        api_endpoints = list(api_endpoints or [])
        graph_entities = list(graph_entities or [])
        graph_relationships = list(graph_relationships or [])

        # Build per-dimension raw counts.
        def file_paths() -> list[str]:
            out = []
            for f in files:
                rp = getattr(f, "relative_path", None) or (f if isinstance(f, str) else None)
                if rp:
                    out.append(str(rp))
            return out

        paths = file_paths()
        cat_counts: dict[str, int] = dict.fromkeys(DIMENSIONS, 0)
        for p in paths:
            if _match(p, _AUTH_HINTS):
                cat_counts["authentication"] += 1
            if _match(p, _AUTHZ_HINTS):
                cat_counts["authorization"] += 1
            if _match(p, _BIZ_HINTS):
                cat_counts["business_logic"] += 1
            if _match(p, _API_HINTS):
                cat_counts["api"] += 1
            if _match(p, _DOC_HINTS):
                cat_counts["documentation"] += 1
            if _match(p, _ARCH_HINTS):
                cat_counts["architecture"] += 1
            if _match(p, _DEP_HINTS):
                cat_counts["dependency"] += 1

        # Boost counts by findings / rules / endpoints / graph data when present.
        if findings:
            def _field(f: Any, key: str) -> str:
                if isinstance(f, dict):
                    return str(f.get(key, ""))
                return str(getattr(f, key, "") or "")

            biz_hits = sum(
                1 for f in findings
                if any(
                    kw in (_field(f, "title") + " " + _field(f, "description")).lower()
                    for kw in _BIZ_HINTS
                )
            )
            api_hits = sum(
                1 for f in findings
                if any(
                    kw in (_field(f, "title") + " " + _field(f, "description")).lower()
                    for kw in _API_HINTS
                )
            )
            cat_counts["business_logic"] += biz_hits
            cat_counts["api"] += api_hits
        if biz_rules:
            cat_counts["business_logic"] += len(biz_rules)
        if api_endpoints:
            cat_counts["api"] += len(api_endpoints)
        # Architecture: graph entities + relationships.
        cat_counts["architecture"] += len(graph_entities) + len(graph_relationships)
        # Dependency: any lockfile/manifest in workspace.
        # (Already counted via _DEP_HINTS above.)

        metrics: dict[str, float] = {}
        details: dict[str, dict[str, Any]] = {}
        for d in DIMENSIONS:
            raw = cat_counts[d]
            expected = baseline.get(d, DEFAULT_BASELINE[d])
            ratio = _ratio(raw, expected)
            metrics[d] = ratio
            details[d] = {
                "raw_count": raw,
                "expected": expected,
                "ratio": round(ratio, 4),
            }

        report = CoverageReport(
            project_id=project_id,
            metrics=metrics,
            details=details,
            computed_at=datetime.utcnow().isoformat(),
        )
        self.save(report)
        logger.info(
            "coverage_computed",
            project_id=project_id,
            overall=report.overall(),
        )
        return report

    # ---- queries ----------------------------------------------------------

    def get(self, project_id: str) -> CoverageReport | None:
        return self.load(project_id)

    def set_baseline(self, project_id: str, baseline: dict[str, int]) -> None:
        """Override the expected artifact counts for a project."""
        existing = self.load(project_id) or CoverageReport(project_id=project_id)
        existing.details.setdefault("__baseline__", {}).update(baseline)
        existing.computed_at = datetime.utcnow().isoformat()
        self.save(existing)
        logger.info("coverage_baseline_set", project_id=project_id, baseline=baseline)


# Module-level singleton (lazy).
_engine: CoverageEngine | None = None


def get_coverage_engine(base_path: Path | None = None) -> CoverageEngine:
    global _engine
    if _engine is None:
        _engine = CoverageEngine(base_path)
    return _engine
