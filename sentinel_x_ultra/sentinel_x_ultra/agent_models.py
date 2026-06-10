"""Agent Model Registry — V3.

Persists which model is used by every agent in the system to a
single JSON file on disk. This gives operators a clear, auditable
record of model assignments per agent (recon, code review, debate,
threat modeling, the Phase 5 agents, the V3 agents, etc.) and lets
the UI render a "model map" so it's obvious which LLM backs which
agent.

The file lives at ``<storage>/agent_models.json`` and looks like::

    {
      "schema_version": 1,
      "updated_at": "2025-...",
      "agents": {
        "recon":              {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
        "code_review":        {"model": "llama-3.3-70b-versatile", "purpose": "code"},
        "threat_modeling":    {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
        ...
        "threat_intelligence":{"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
        "supply_chain":       {"model": "llama-3.3-70b-versatile", "purpose": "code"},
        "api_security":       {"model": "llama-3.3-70b-versatile", "purpose": "code"},
        ...
      }
    }

A small :class:`AgentModelRegistry` API lets callers list all
assignments, update one, and reset to the system defaults.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import structlog

logger = structlog.get_logger()


# Every agent the system knows about, with a default model and purpose.
# `purpose` is used by the LLM router to pick the right slot
# (reasoning / code / report / embedding).
DEFAULT_AGENT_MODELS: dict[str, dict[str, str]] = {
    # Phase 3 agents
    "recon":              {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "code_review":        {"model": "llama-3.3-70b-versatile", "purpose": "code"},
    "threat_modeling":    {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "dependency":         {"model": "llama-3.3-70b-versatile", "purpose": "code"},
    "debate":             {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    # Phase 4
    "remediation":        {"model": "llama-3.3-70b-versatile", "purpose": "report"},
    "report":             {"model": "llama-3.3-70b-versatile", "purpose": "report"},
    "compliance":         {"model": "llama-3.3-70b-versatile", "purpose": "report"},
    # Phase 5
    "threat_intelligence":{"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "security_operations":{"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "adaptive_defense":   {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "supply_chain":       {"model": "llama-3.3-70b-versatile", "purpose": "code"},
    "api_security":       {"model": "llama-3.3-70b-versatile", "purpose": "code"},
    # V3 agents (the agent-centric knowledge owners)
    "documentation":      {"model": "llama-3.3-70b-versatile", "purpose": "report"},
    "tooling":            {"model": "llama-3.3-70b-versatile", "purpose": "report"},
    "architecture":       {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "business_logic":     {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "evidence":           {"model": "llama-3.3-70b-versatile", "purpose": "code"},
    "correlation":        {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "qa":                 {"model": "llama-3.3-70b-versatile", "purpose": "report"},
    "permission":         {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
    "workflow":           {"model": "llama-3.3-70b-versatile", "purpose": "reasoning"},
}


SCHEMA_VERSION = 1


@dataclass
class AgentModelAssignment:
    agent: str
    model: str
    purpose: str = "reasoning"
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AgentModelRegistry:
    """Persists per-agent model assignments to a single JSON file."""

    def __init__(self, file_path: Path):
        self.file_path = Path(file_path)
        self._cache: dict[str, dict[str, str]] = {}
        self._ensure_file()

    # ---- file IO ----------------------------------------------------------

    def _ensure_file(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists():
            self._cache = {a: dict(v) for a, v in DEFAULT_AGENT_MODELS.items()}
            self._write(
                {
                    "schema_version": SCHEMA_VERSION,
                    "updated_at": datetime.utcnow().isoformat(),
                    "agents": self._cache,
                }
            )
        else:
            self._reload()

    def _reload(self) -> None:
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8"))
            self._cache = {
                a: {"model": v.get("model", ""), "purpose": v.get("purpose", "reasoning")}
                for a, v in (data.get("agents") or {}).items()
            }
        except Exception as e:  # pragma: no cover
            logger.error("agent_models_load_failed", path=str(self.file_path), error=str(e))
            self._cache = dict(DEFAULT_AGENT_MODELS)

    def _write(self, payload: dict[str, Any]) -> None:
        self.file_path.write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    def _flush(self) -> None:
        self._write(
            {
                "schema_version": SCHEMA_VERSION,
                "updated_at": datetime.utcnow().isoformat(),
                "agents": self._cache,
            }
        )

    # ---- public API -------------------------------------------------------

    def list(self) -> list[AgentModelAssignment]:
        return [
            AgentModelAssignment(
                agent=a,
                model=v["model"],
                purpose=v.get("purpose", "reasoning"),
                updated_at=datetime.utcnow().isoformat(),
            )
            for a, v in sorted(self._cache.items())
        ]

    def get(self, agent: str) -> AgentModelAssignment | None:
        v = self._cache.get(agent)
        if v is None:
            return None
        return AgentModelAssignment(
            agent=agent,
            model=v["model"],
            purpose=v.get("purpose", "reasoning"),
            updated_at=datetime.utcnow().isoformat(),
        )

    def assign(self, agent: str, model: str, purpose: str | None = None) -> AgentModelAssignment:
        if not agent or not model:
            raise ValueError("agent and model are required")
        prev = self._cache.get(agent, {})
        self._cache[agent] = {
            "model": model,
            "purpose": purpose or prev.get("purpose") or "reasoning",
        }
        self._flush()
        out = AgentModelAssignment(
            agent=agent,
            model=model,
            purpose=self._cache[agent]["purpose"],
            updated_at=datetime.utcnow().isoformat(),
        )
        logger.info("agent_model_assigned", agent=agent, model=model, purpose=self._cache[agent]["purpose"])
        return out

    def bulk_assign(self, assignments: dict[str, dict[str, str]]) -> None:
        for agent, payload in assignments.items():
            if not agent or "model" not in payload or not payload["model"]:
                continue
            self._cache[agent] = {
                "model": payload["model"],
                "purpose": payload.get("purpose", "reasoning"),
            }
        self._flush()

    def reset(self) -> None:
        self._cache = dict(DEFAULT_AGENT_MODELS)
        self._flush()

    def defaults(self) -> dict[str, dict[str, str]]:
        return {a: dict(v) for a, v in DEFAULT_AGENT_MODELS.items()}
