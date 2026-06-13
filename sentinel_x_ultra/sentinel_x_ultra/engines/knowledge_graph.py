"""Knowledge Graph Engine - Entity mapping and attack path discovery."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EntityType(str, Enum):
    """Types of entities in the knowledge graph."""
    DATA = "data"                      # Sensitive data stores
    SERVICE = "service"                # Microservices/APIs
    ENDPOINT = "endpoint"              # API endpoints
    USER = "user"                      # User roles
    AUTH = "auth"                      # Authentication mechanisms
    PERMISSION = "permission"          # Permissions/authorizations
    EXTERNAL = "external"              # External integrations
    INFRASTRUCTURE = "infrastructure"  # Infrastructure components
    INPUT = "input"                    # User input vectors
    PROCESS = "process"                # Business processes


class RelationshipType(str, Enum):
    """Types of relationships between entities."""
    CALLS = "calls"                    # Service A calls Service B
    ACCESSES = "accesses"              # Accesses data store
    AUTHENTICATES = "authenticates"    # Authentication flow
    AUTHORIZES = "authorizes"          # Authorization check
    INPUT_TO = "input_to"              # User input flows to
    DEPENDS_ON = "depends_on"          # Dependency relationship
    INHERITS = "inherits"              # Inheritance/extension
    EXPOSES = "exposes"                # Exposes endpoint
    STORES = "stores"                  # Stores sensitive data
    TRANSMITS = "transmits"            # Transmits data


class RiskLevel(str, Enum):
    """Risk levels for attack paths."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class EntityNode:
    """Represents an entity in the knowledge graph."""
    id: str
    name: str
    entity_type: EntityType
    component: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    data_classification: str = "public"  # public | internal | confidential | restricted
    trust_level: str = "untrusted"       # trusted | semi-trusted | untrusted
    attack_surface: list[str] = field(default_factory=list)  # entry points
    vulnerability_hints: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "entity_type": self.entity_type.value if isinstance(self.entity_type, EntityType) else self.entity_type,
            "component": self.component,
            "properties": self.properties,
            "data_classification": self.data_classification,
            "trust_level": self.trust_level,
            "attack_surface": self.attack_surface,
            "vulnerability_hints": self.vulnerability_hints,
            "created_at": self.created_at,
        }


@dataclass
class RelationshipEdge:
    """Represents a relationship between entities."""
    id: str
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    properties: dict[str, Any] = field(default_factory=dict)
    bidirectional: bool = False
    risk_factors: list[str] = field(default_factory=list)  # injection, auth-bypass, etc.
    data_flow: str = "none"  # none | read | write | full
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type.value if isinstance(self.relationship_type, RelationshipType) else self.relationship_type,
            "properties": self.properties,
            "bidirectional": self.bidirectional,
            "risk_factors": self.risk_factors,
            "data_flow": self.data_flow,
            "created_at": self.created_at,
        }


@dataclass
class AttackPath:
    """Represents a potential attack path through the system."""
    id: str
    name: str
    entities: list[str]  # Entity IDs in order
    relationships: list[str]  # Relationship IDs in order
    entry_point: str  # Entity ID of entry point
    target: str  # Entity ID of target
    cvss_score: float = 0.0
    cvss_vector: str = ""
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    attack_steps: list[str] = field(default_factory=list)  # Description of each step
    prerequisites: list[str] = field(default_factory=list)
    exploitation_complexity: str = "unknown"
    business_impact: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "entities": self.entities,
            "relationships": self.relationships,
            "entry_point": self.entry_point,
            "target": self.target,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else self.risk_level,
            "attack_steps": self.attack_steps,
            "prerequisites": self.prerequisites,
            "exploitation_complexity": self.exploitation_complexity,
            "business_impact": self.business_impact,
            "created_at": self.created_at,
        }


class KnowledgeGraphEngine:
    """Graph-based knowledge representation for security analysis."""

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or str(uuid.uuid4())
        self._entities: dict[str, EntityNode] = {}
        self._relationships: dict[str, RelationshipEdge] = {}
        self._entities_by_type: dict[EntityType, list[str]] = {}
        self._entities_by_component: dict[str, list[str]] = {}
        self._attack_paths: list[AttackPath] = []

        # Index for quick lookups
        self._adjacency: dict[str, list[str]] = {}  # entity_id -> [target_entity_ids]
        self._reverse_adjacency: dict[str, list[str]] = {}  # entity_id -> [source_entity_ids]

        logger.info("knowledge_graph_initialized", project_id=self.project_id)

    # ============ Entity Management ============

    def add_entity(self, entity: EntityNode) -> str:
        """Add an entity to the graph."""
        self._entities[entity.id] = entity

        # Update type index
        if entity.entity_type not in self._entities_by_type:
            self._entities_by_type[entity.entity_type] = []
        self._entities_by_type[entity.entity_type].append(entity.id)

        # Update component index
        if entity.component:
            if entity.component not in self._entities_by_component:
                self._entities_by_component[entity.component] = []
            self._entities_by_component[entity.component].append(entity.id)

        # Initialize adjacency
        if entity.id not in self._adjacency:
            self._adjacency[entity.id] = []
        if entity.id not in self._reverse_adjacency:
            self._reverse_adjacency[entity.id] = []

        logger.debug("entity_added", entity_id=entity.id, entity_type=entity.entity_type)
        return entity.id

    def get_entity(self, entity_id: str) -> EntityNode | None:
        """Get an entity by ID."""
        return self._entities.get(entity_id)

    def get_entities_by_type(self, entity_type: EntityType) -> list[EntityNode]:
        """Get all entities of a specific type."""
        entity_ids = self._entities_by_type.get(entity_type, [])
        return [self._entities[eid] for eid in entity_ids if eid in self._entities]

    def get_entities_by_component(self, component: str) -> list[EntityNode]:
        """Get all entities for a specific component."""
        entity_ids = self._entities_by_component.get(component, [])
        return [self._entities[eid] for eid in entity_ids if eid in self._entities]

    def get_all_entities(self) -> list[EntityNode]:
        """Get all entities in the graph."""
        return list(self._entities.values())

    # ============ Relationship Management ============

    def add_relationship(self, relationship: RelationshipEdge) -> str:
        """Add a relationship to the graph."""
        self._relationships[relationship.id] = relationship

        # Update adjacency
        if relationship.source_id not in self._adjacency:
            self._adjacency[relationship.source_id] = []
        self._adjacency[relationship.source_id].append(relationship.target_id)

        if relationship.target_id not in self._reverse_adjacency:
            self._reverse_adjacency[relationship.target_id] = []
        self._reverse_adjacency[relationship.target_id].append(relationship.source_id)

        # If bidirectional, add reverse adjacency too
        if relationship.bidirectional:
            if relationship.target_id not in self._adjacency:
                self._adjacency[relationship.target_id] = []
            self._adjacency[relationship.target_id].append(relationship.source_id)

            if relationship.source_id not in self._reverse_adjacency:
                self._reverse_adjacency[relationship.source_id] = []
            self._reverse_adjacency[relationship.source_id].append(relationship.target_id)

        logger.debug("relationship_added",
                     relationship_id=relationship.id,
                     source=relationship.source_id,
                     target=relationship.target_id)
        return relationship.id

    def get_relationship(self, relationship_id: str) -> RelationshipEdge | None:
        """Get a relationship by ID."""
        return self._relationships.get(relationship_id)

    def get_relationships_by_entity(self, entity_id: str) -> list[RelationshipEdge]:
        """Get all relationships for an entity (both incoming and outgoing)."""
        outgoing = [r for r in self._relationships.values() if r.source_id == entity_id]
        incoming = [r for r in self._relationships.values() if r.target_id == entity_id]
        return outgoing + incoming

    def get_neighbors(self, entity_id: str, direction: str = "both") -> list[str]:
        """Get neighboring entity IDs. direction: 'outgoing', 'incoming', 'both'"""
        if direction == "outgoing":
            return self._adjacency.get(entity_id, [])
        elif direction == "incoming":
            return self._reverse_adjacency.get(entity_id, [])
        else:  # both
            outgoing = set(self._adjacency.get(entity_id, []))
            incoming = set(self._reverse_adjacency.get(entity_id, []))
            return list(outgoing | incoming)

    # ============ Attack Path Discovery ============

    def discover_attack_paths(
        self,
        entry_points: list[str] | None = None,
        targets: list[str] | None = None,
        max_depth: int = 5,
    ) -> list[AttackPath]:
        """Discover potential attack paths from entry points to targets."""
        paths = []

        # Default entry points: entities with external attack surface
        if entry_points is None:
            entry_points = [
                e.id for e in self._entities.values()
                if EntityType.INPUT in e.attack_surface or EntityType.EXTERNAL in e.entity_type
            ]

        # Default targets: sensitive data stores
        if targets is None:
            targets = [
                e.id for e in self._entities.values()
                if e.data_classification in ["confidential", "restricted"]
            ]

        # BFS to find paths
        for entry in entry_points:
            for target in targets:
                if entry == target:
                    continue

                discovered_paths = self._find_paths_bfs(entry, target, max_depth)
                for path_entity_ids in discovered_paths:
                    attack_path = self._build_attack_path(path_entity_ids, entry, target)
                    if attack_path:
                        paths.append(attack_path)

        self._attack_paths = paths
        logger.info("attack_paths_discovered", count=len(paths))
        return paths

    def _find_paths_bfs(self, start: str, end: str, max_depth: int) -> list[list[str]]:
        """BFS to find all paths between two entities."""
        paths = []
        queue = [(start, [start])]

        while queue:
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            if current == end:
                paths.append(path)
                continue

            for neighbor in self._adjacency.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def _build_attack_path(
        self,
        entity_ids: list[str],
        entry_point: str,
        target: str,
    ) -> AttackPath | None:
        """Build an AttackPath object from entity IDs."""
        if len(entity_ids) < 2:
            return None

        # Collect relationships used in this path
        path_relationships = []
        attack_steps = []
        risk_factors = []

        for i in range(len(entity_ids) - 1):
            source, target_id = entity_ids[i], entity_ids[i + 1]

            # Find the relationship
            rel = self._find_relationship(source, target_id)
            if rel:
                path_relationships.append(rel.id)
                risk_factors.extend(rel.risk_factors)
                attack_steps.append(
                    f"From {self._entities[source].name} "
                    f"{rel.relationship_type.value} "
                    f"{self._entities[target_id].name}"
                )

        if not attack_steps:
            return None

        # Calculate risk level based on path properties
        risk_level = self._calculate_path_risk(risk_factors, len(entity_ids))

        return AttackPath(
            id=str(uuid.uuid4()),
            name=f"Attack path: {' → '.join([self._entities[e].name for e in entity_ids])}",
            entities=entity_ids,
            relationships=path_relationships,
            entry_point=entry_point,
            target=target,
            risk_level=risk_level,
            attack_steps=attack_steps,
            exploitation_complexity=self._estimate_complexity(risk_factors),
        )

    def _find_relationship(self, source_id: str, target_id: str) -> RelationshipEdge | None:
        """Find relationship between two entities."""
        for rel in self._relationships.values():
            if rel.source_id == source_id and rel.target_id == target_id:
                return rel
        return None

    def _calculate_path_risk(self, risk_factors: list[str], path_length: int) -> RiskLevel:
        """Calculate overall risk level for a path."""
        critical_factors = {"sql-injection", "rce", "auth-bypass", "data-exfiltration"}
        high_factors = {"xss", "csrf", "idor", "path-traversal"}

        factor_set = set(risk_factors)

        if factor_set & critical_factors:
            return RiskLevel.CRITICAL
        elif path_length <= 2 and factor_set:
            return RiskLevel.HIGH
        elif factor_set & high_factors:
            return RiskLevel.MEDIUM
        elif factor_set:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL

    def _estimate_complexity(self, risk_factors: list[str]) -> str:
        """Estimate exploitation complexity."""
        if not risk_factors:
            return "unknown"

        simple_factors = {"idor", "csrf", "xss-stored"}
        complex_factors = {"sql-injection-blind", "rce", "auth-bypass"}

        factor_set = set(risk_factors)

        if factor_set & complex_factors:
            return "high"
        elif factor_set & simple_factors:
            return "low"
        return "medium"

    # ============ Graph Analysis ============

    def find_data_flows(self, source_entity: str, target_entity: str) -> list[list[str]]:
        """Find data flow paths between two entities."""
        paths = self._find_paths_bfs(source_entity, target_entity, max_depth=10)

        # Filter to paths with data flow relationships
        valid_paths = []
        for path in paths:
            has_data_flow = False
            for i in range(len(path) - 1):
                rel = self._find_relationship(path[i], path[i + 1])
                if rel and rel.data_flow != "none":
                    has_data_flow = True
                    break
            if has_data_flow:
                valid_paths.append(path)

        return valid_paths

    def get_entry_points(self) -> list[EntityNode]:
        """Get all entry points (entities with external attack surface)."""
        return [
            e for e in self._entities.values()
            if EntityType.INPUT in e.attack_surface or EntityType.EXTERNAL in e.entity_type
        ]

    def get_sensitive_entities(self) -> list[EntityNode]:
        """Get all sensitive entities (high data classification)."""
        return [
            e for e in self._entities.values()
            if e.data_classification in ["confidential", "restricted"]
        ]

    # ============ Serialization ============

    def to_dict(self) -> dict[str, Any]:
        """Export graph to dictionary."""
        return {
            "project_id": self.project_id,
            "entities": [e.to_dict() for e in self._entities.values()],
            "relationships": [r.to_dict() for r in self._relationships.values()],
            "attack_paths": [p.to_dict() for p in self._attack_paths],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KnowledgeGraphEngine":
        """Import graph from dictionary."""
        engine = cls(project_id=data.get("project_id"))

        for entity_data in data.get("entities", []):
            entity_data_copy = entity_data.copy()
            if "entity_type" in entity_data_copy:
                entity_data_copy["entity_type"] = EntityType(entity_data_copy["entity_type"])
            entity = EntityNode(**entity_data_copy)
            engine.add_entity(entity)

        for rel_data in data.get("relationships", []):
            rel_data_copy = rel_data.copy()
            if "relationship_type" in rel_data_copy:
                rel_data_copy["relationship_type"] = RelationshipType(rel_data_copy["relationship_type"])
            rel = RelationshipEdge(**rel_data_copy)
            engine.add_relationship(rel)

        return engine

    def clear(self):
        """Clear the entire graph."""
        self._entities.clear()
        self._relationships.clear()
        self._entities_by_type.clear()
        self._entities_by_component.clear()
        self._attack_paths.clear()
        self._adjacency.clear()
        self._reverse_adjacency.clear()
        logger.info("knowledge_graph_cleared")
