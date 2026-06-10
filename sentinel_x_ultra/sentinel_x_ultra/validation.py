"""Finding Validation Pipeline — V3.

The V3 spec mandates the following pipeline for every candidate finding::

    Candidate Finding
        ↓
    Evidence Retrieval
        ↓
    Debate Engine
        ↓
    Self Critique
        ↓
    Correlation Analysis
        ↓
    Confidence Engine
        ↓
    QA Review
        ↓
    Report Inclusion

    If any stage fails → move finding to REVIEW_QUEUE.

This module is the deterministic orchestrator. The "Debate Engine" and
"Confidence Engine" stages are pluggable so callers can wire in their
own LLM-backed implementations later. By default they use conservative
heuristics so the pipeline is testable end-to-end without an LLM.

The Golden Rule: **evidence is more important than model confidence.**
A low-confidence finding with strong evidence is more valuable than a
high-confidence finding with weak evidence. The pipeline enforces this
by requiring every promoted finding to carry a non-empty evidence list
with at least one piece of evidence whose source is *not* a methodology
reference.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable

import structlog

from .methodology import MethodologyReferenceEngine

logger = structlog.get_logger()


class PipelineStage(str, Enum):
    EVIDENCE = "evidence_retrieval"
    DEBATE = "debate_engine"
    CRITIQUE = "self_critique"
    CORRELATION = "correlation_analysis"
    CONFIDENCE = "confidence_engine"
    QA = "qa_review"
    REPORT = "report_inclusion"


PIPELINE_ORDER: tuple[PipelineStage, ...] = (
    PipelineStage.EVIDENCE,
    PipelineStage.DEBATE,
    PipelineStage.CRITIQUE,
    PipelineStage.CORRELATION,
    PipelineStage.CONFIDENCE,
    PipelineStage.QA,
    PipelineStage.REPORT,
)


# ---- Data model --------------------------------------------------------------

class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    IN_REVIEW = "in_review"
    PROMOTED = "promoted"
    REVIEW_QUEUE = "review_queue"
    REJECTED = "rejected"


@dataclass
class EvidenceItem:
    """A single piece of evidence backing a finding.

    Per V3 spec each claim must have: Source, Location, Confidence, Context.
    """

    source: str
    location: str = ""
    confidence: str = "medium"  # high | medium | low
    context: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceItem":
        return cls(**data)


@dataclass
class CandidateFinding:
    """A finding submitted for validation."""

    finding_id: str
    title: str
    description: str
    severity: str = "Medium"  # Critical | High | Medium | Low | Informational
    confidence: str = "Medium"
    evidence: list[EvidenceItem] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)
    source_agent: str = ""
    related_finding_ids: list[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [e.to_dict() if hasattr(e, "to_dict") else e for e in self.evidence]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CandidateFinding":
        ev = [EvidenceItem.from_dict(e) for e in data.get("evidence", [])]
        data = dict(data)
        data["evidence"] = ev
        return cls(**data)


@dataclass
class StageResult:
    """Outcome of one pipeline stage."""

    stage: PipelineStage
    passed: bool
    notes: str = ""
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationOutcome:
    finding_id: str
    status: FindingStatus
    stage_results: list[StageResult] = field(default_factory=list)
    final_notes: str = ""
    promoted_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "stage_results": [r.to_dict() for r in self.stage_results],
            "final_notes": self.final_notes,
            "promoted_at": self.promoted_at,
        }


# ---- Pluggable stage hooks ----------------------------------------------------
# Each stage has a default heuristic implementation. Callers can override any
# stage by passing a callable `(finding, ctx) -> StageResult` to the pipeline.

StageHook = Callable[["CandidateFinding", "ValidationContext"], StageResult]


@dataclass
class ValidationContext:
    """Mutable context passed between stages."""

    methodology: MethodologyReferenceEngine
    correlation_index: dict[str, list[str]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


# ---- Default stage implementations -------------------------------------------

def _evidence_stage(finding: CandidateFinding, ctx: ValidationContext) -> StageResult:
    """Enforce: every claim must have evidence. If missing → INSUFFICIENT_EVIDENCE."""
    if not finding.evidence:
        return StageResult(
            stage=PipelineStage.EVIDENCE,
            passed=False,
            notes="INSUFFICIENT_EVIDENCE: no evidence attached to finding",
            score=0.0,
        )
    # Each evidence item must have source + location + confidence + context
    missing = []
    for e in finding.evidence:
        if not e.source:
            missing.append("source")
        if not e.location:
            missing.append("location")
        if e.confidence not in ("high", "medium", "low"):
            missing.append(f"confidence:{e.confidence}")
        if not e.context:
            missing.append("context")
    if missing:
        return StageResult(
            stage=PipelineStage.EVIDENCE,
            passed=False,
            notes=(
                f"INSUFFICIENT_EVIDENCE: items missing required fields: "
                f"{sorted(set(missing))}"
            ),
            score=0.0,
        )
    # Golden Rule: at least one evidence source must NOT be a methodology ref.
    real = [e for e in finding.evidence if ctx.methodology.is_evidence(e.source)]
    if not real:
        return StageResult(
            stage=PipelineStage.EVIDENCE,
            passed=False,
            notes=(
                "INSUFFICIENT_EVIDENCE: all evidence comes from methodology "
                "references; evidence must come from the analyzed target"
            ),
            score=0.0,
        )
    return StageResult(
        stage=PipelineStage.EVIDENCE,
        passed=True,
        notes=f"{len(real)} target-sourced evidence item(s) accepted",
        score=min(1.0, len(real) / 2.0),
    )


def _debate_stage(finding: CandidateFinding, ctx: ValidationContext) -> StageResult:
    """Adversarial check: would a skeptic challenge this finding?"""
    skeptic_challenges: list[str] = []
    # Empty description or title is easy to challenge
    if len(finding.title.strip()) < 5:
        skeptic_challenges.append("title is too vague")
    if len(finding.description.strip()) < 20:
        skeptic_challenges.append("description is too thin to reproduce")
    if not finding.affected_components:
        skeptic_challenges.append("no affected components identified")
    if skeptic_challenges:
        return StageResult(
            stage=PipelineStage.DEBATE,
            passed=False,
            notes="skeptic challenges: " + "; ".join(skeptic_challenges),
            score=0.0,
        )
    return StageResult(
        stage=PipelineStage.DEBATE,
        passed=True,
        notes="skeptic challenges addressed",
        score=1.0,
    )


def _critique_stage(finding: CandidateFinding, ctx: ValidationContext) -> StageResult:
    """Self-critique: check internal consistency."""
    # Severity / confidence should be in allowed set
    if finding.severity not in ("Critical", "High", "Medium", "Low", "Informational"):
        return StageResult(
            stage=PipelineStage.CRITIQUE,
            passed=False,
            notes=f"unknown severity: {finding.severity}",
            score=0.0,
        )
    if finding.confidence not in (
        "Verified", "High", "Medium", "Low", "Informational"
    ):
        return StageResult(
            stage=PipelineStage.CRITIQUE,
            passed=False,
            notes=f"unknown confidence: {finding.confidence}",
            score=0.0,
        )
    return StageResult(
        stage=PipelineStage.CRITIQUE, passed=True, notes="internally consistent", score=1.0
    )


def _correlation_stage(finding: CandidateFinding, ctx: ValidationContext) -> StageResult:
    """Link to other findings where possible."""
    bucket = ctx.correlation_index.setdefault(finding.finding_id, [])
    for rid in finding.related_finding_ids:
        if rid and rid not in bucket:
            bucket.append(rid)
    return StageResult(
        stage=PipelineStage.CORRELATION,
        passed=True,
        notes=f"{len(bucket)} related finding(s) linked",
        score=min(1.0, len(bucket) / 2.0),
    )


def _confidence_stage(finding: CandidateFinding, ctx: ValidationContext) -> StageResult:
    """Combine evidence strength + model confidence (evidence wins)."""
    high_ev = sum(1 for e in finding.evidence if e.confidence == "high")
    med_ev = sum(1 for e in finding.evidence if e.confidence == "medium")
    ev_score = min(1.0, (high_ev * 1.0 + med_ev * 0.5) / 2.0)
    model_score = {
        "Verified": 1.0,
        "High": 0.85,
        "Medium": 0.6,
        "Low": 0.4,
        "Informational": 0.2,
    }.get(finding.confidence, 0.5)
    # Golden Rule: weight evidence more than model confidence.
    combined = 0.7 * ev_score + 0.3 * model_score
    return StageResult(
        stage=PipelineStage.CONFIDENCE,
        passed=combined >= 0.3,
        notes=(
            f"evidence_score={ev_score:.2f} model_score={model_score:.2f} "
            f"combined={combined:.2f}"
        ),
        score=combined,
    )


def _qa_stage(finding: CandidateFinding, ctx: ValidationContext) -> StageResult:
    """Final QA: title present, description present, evidence present."""
    ok = bool(finding.title and finding.description and finding.evidence)
    return StageResult(
        stage=PipelineStage.QA,
        passed=ok,
        notes="report-ready" if ok else "missing required fields for reporting",
        score=1.0 if ok else 0.0,
    )


# ---- Pipeline ----------------------------------------------------------------

DEFAULT_STAGES: dict[PipelineStage, StageHook] = {
    PipelineStage.EVIDENCE: _evidence_stage,
    PipelineStage.DEBATE: _debate_stage,
    PipelineStage.CRITIQUE: _critique_stage,
    PipelineStage.CORRELATION: _correlation_stage,
    PipelineStage.CONFIDENCE: _confidence_stage,
    PipelineStage.QA: _qa_stage,
}


class FindingValidationPipeline:
    """Runs a candidate finding through the V3 validation stages."""

    def __init__(
        self,
        methodology: MethodologyReferenceEngine | None = None,
        stage_hooks: dict[PipelineStage, StageHook] | None = None,
    ):
        self.methodology = methodology or MethodologyReferenceEngine()
        self.stage_hooks = {**DEFAULT_STAGES, **(stage_hooks or {})}
        # REVIEW_QUEUE: findings that failed a stage, awaiting human review.
        self.review_queue: dict[str, tuple[CandidateFinding, ValidationOutcome]] = {}
        # Promoted: passed all stages, ready for report inclusion.
        self.promoted: dict[str, tuple[CandidateFinding, ValidationOutcome]] = {}

    # ---- public API -------------------------------------------------------

    def submit(self, finding: CandidateFinding) -> ValidationOutcome:
        if not finding.finding_id:
            finding.finding_id = str(uuid.uuid4())
        if not finding.created_at:
            finding.created_at = datetime.utcnow().isoformat()

        ctx = ValidationContext(methodology=self.methodology)
        results: list[StageResult] = []
        for stage in PIPELINE_ORDER:
            if stage == PipelineStage.REPORT:
                continue  # Inclusion is recorded by the orchestrator after QA
            hook = self.stage_hooks[stage]
            result = hook(finding, ctx)
            results.append(result)
            if not result.passed:
                outcome = ValidationOutcome(
                    finding_id=finding.finding_id,
                    status=FindingStatus.REVIEW_QUEUE,
                    stage_results=results,
                    final_notes=(
                        f"Failed at stage '{stage.value}': {result.notes}"
                    ),
                )
                self.review_queue[finding.finding_id] = (finding, outcome)
                logger.warning(
                    "finding_moved_to_review_queue",
                    finding_id=finding.finding_id,
                    stage=stage.value,
                    notes=result.notes,
                )
                return outcome

        # All stages passed
        outcome = ValidationOutcome(
            finding_id=finding.finding_id,
            status=FindingStatus.PROMOTED,
            stage_results=results,
            final_notes="All validation stages passed",
            promoted_at=datetime.utcnow().isoformat(),
        )
        self.promoted[finding.finding_id] = (finding, outcome)
        logger.info(
            "finding_promoted",
            finding_id=finding.finding_id,
            title=finding.title,
        )
        return outcome

    def get_review_queue(self) -> list[ValidationOutcome]:
        return [o for _, o in self.review_queue.values()]

    def get_promoted(self) -> list[ValidationOutcome]:
        return [o for _, o in self.promoted.values()]

    def retry(self, finding_id: str) -> ValidationOutcome | None:
        pair = self.review_queue.pop(finding_id, None)
        if pair is None:
            return None
        finding, _ = pair
        return self.submit(finding)


# Module-level singleton (created lazily).
_pipeline: FindingValidationPipeline | None = None


def get_validation_pipeline() -> FindingValidationPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = FindingValidationPipeline()
    return _pipeline
