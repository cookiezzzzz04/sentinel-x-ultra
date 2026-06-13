"""Permission Graph Engine - Authorization modeling and gap detection."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PermissionType(str, Enum):
    """Types of permissions."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    IMPERSONATE = "impersonate"
    TRANSFER = "transfer"


class SubjectType(str, Enum):
    """Types of subjects (who holds permissions)."""
    USER = "user"
    SERVICE = "service"
    ROLE = "role"
    GROUP = "group"
    ANONYMOUS = "anonymous"


class ObjectType(str, Enum):
    """Types of objects (what permissions are applied to)."""
    DATA = "data"
    API_ENDPOINT = "api_endpoint"
    FILE = "file"
    DATABASE = "database"
    QUEUE = "queue"
    SECRET = "secret"
    CONFIG = "config"


@dataclass
class PermissionNode:
    """Represents a subject with permissions."""
    id: str
    subject_id: str
    subject_type: SubjectType
    name: str
    role: str = ""
    trust_level: str = "medium"  # low | medium | high | critical
    properties: dict[str, Any] = field(default_factory=dict)
    inherited_roles: list[str] = field(default_factory=list)
    direct_permissions: list[str] = field(default_factory=list)  # Permission IDs
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type.value if isinstance(self.subject_type, SubjectType) else self.subject_type,
            "name": self.name,
            "role": self.role,
            "trust_level": self.trust_level,
            "properties": self.properties,
            "inherited_roles": self.inherited_roles,
            "direct_permissions": self.direct_permissions,
            "created_at": self.created_at,
        }


@dataclass
class PermissionEdge:
    """Represents a permission grant from subject to object."""
    id: str
    subject_id: str
    object_id: str
    permission: PermissionType
    object_type: ObjectType
    grant_type: str = "direct"  # direct | inherited | implied
    conditions: dict[str, Any] = field(default_factory=dict)  # context restrictions
    reason: str = ""  # Why this permission exists
    is_admin_override: bool = False
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "object_id": self.object_id,
            "permission": self.permission.value if isinstance(self.permission, PermissionType) else self.permission,
            "object_type": self.object_type.value if isinstance(self.object_type, ObjectType) else self.object_type,
            "grant_type": self.grant_type,
            "conditions": self.conditions,
            "reason": self.reason,
            "is_admin_override": self.is_admin_override,
            "created_at": self.created_at,
        }


@dataclass
class GapAnalysis:
    """Analysis of permission gaps found."""
    id: str
    gap_type: str  # overprivileged | underprivileged | unused | privilege_escalation
    severity: str  # critical | high | medium | low
    subject_id: str = ""
    object_id: str = ""
    description: str = ""
    current_permissions: list[str] = field(default_factory=list)
    recommended_permissions: list[str] = field(default_factory=list)
    risk_factors: list[str] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "gap_type": self.gap_type,
            "severity": self.severity,
            "subject_id": self.subject_id,
            "object_id": self.object_id,
            "description": self.description,
            "current_permissions": self.current_permissions,
            "recommended_permissions": self.recommended_permissions,
            "risk_factors": self.risk_factors,
            "created_at": self.created_at,
        }


class PermissionGraphEngine:
    """Graph-based permission and authorization analysis."""

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id or str(uuid.uuid4())
        self._subjects: dict[str, PermissionNode] = {}
        self._objects: dict[str, dict[str, Any]] = {}  # object_id -> object definition
        self._permissions: dict[str, PermissionEdge] = {}
        self._role_hierarchy: dict[str, list[str]] = {}  # role -> parent roles
        self._gaps: list[GapAnalysis] = []

        logger.info("permission_graph_initialized", project_id=self.project_id)

    # ============ Subject Management ============

    def add_subject(self, subject: PermissionNode) -> str:
        """Add a subject (user, service, role) to the permission graph."""
        self._subjects[subject.id] = subject

        # Update role hierarchy
        if subject.role and subject.role not in self._role_hierarchy:
            self._role_hierarchy[subject.role] = []
        for inherited_role in subject.inherited_roles:
            if inherited_role not in self._role_hierarchy:
                self._role_hierarchy[inherited_role] = []
            if subject.role and inherited_role not in self._role_hierarchy[subject.role]:
                self._role_hierarchy[subject.role].append(inherited_role)

        logger.debug("subject_added", subject_id=subject.id, subject_type=subject.subject_type)
        return subject.id

    def get_subject(self, subject_id: str) -> PermissionNode | None:
        """Get a subject by ID."""
        return self._subjects.get(subject_id)

    def get_subjects_by_role(self, role: str) -> list[PermissionNode]:
        """Get all subjects with a specific role."""
        return [s for s in self._subjects.values() if s.role == role]

    def get_all_subjects(self) -> list[PermissionNode]:
        """Get all subjects."""
        return list(self._subjects.values())

    # ============ Object Management ============

    def add_object(
        self,
        object_id: str,
        object_type: ObjectType,
        name: str,
        sensitivity: str = "medium",
        owner: str = "",
        **properties,
    ) -> str:
        """Add an object (resource) to the permission graph."""
        self._objects[object_id] = {
            "id": object_id,
            "object_type": object_type.value if isinstance(object_type, ObjectType) else object_type,
            "name": name,
            "sensitivity": sensitivity,
            "owner": owner,
            "properties": properties,
        }
        logger.debug("object_added", object_id=object_id, object_type=object_type)
        return object_id

    def get_object(self, object_id: str) -> dict[str, Any] | None:
        """Get an object by ID."""
        return self._objects.get(object_id)

    def get_objects_by_type(self, object_type: ObjectType) -> list[dict[str, Any]]:
        """Get all objects of a specific type."""
        return [o for o in self._objects.values() if o["object_type"] == object_type.value]

    def get_all_objects(self) -> list[dict[str, Any]]:
        """Get all objects."""
        return list(self._objects.values())

    # ============ Permission Management ============

    def grant_permission(
        self,
        subject_id: str,
        object_id: str,
        permission: PermissionType,
        object_type: ObjectType,
        grant_type: str = "direct",
        conditions: dict[str, Any] | None = None,
        reason: str = "",
    ) -> str:
        """Grant a permission to a subject for an object."""
        permission_id = str(uuid.uuid4())

        edge = PermissionEdge(
            id=permission_id,
            subject_id=subject_id,
            object_id=object_id,
            permission=permission,
            object_type=object_type,
            grant_type=grant_type,
            conditions=conditions or {},
            reason=reason,
        )

        self._permissions[permission_id] = edge

        # Add to subject's direct permissions
        if subject_id in self._subjects:
            self._subjects[subject_id].direct_permissions.append(permission_id)

        logger.debug("permission_granted",
                     subject_id=subject_id,
                     object_id=object_id,
                     permission=permission)
        return permission_id

    def revoke_permission(self, permission_id: str) -> bool:
        """Revoke a permission."""
        if permission_id in self._permissions:
            del self._permissions[permission_id]
            return True
        return False

    def get_permissions_for_subject(self, subject_id: str) -> list[PermissionEdge]:
        """Get all permissions for a subject (including inherited)."""
        direct = [p for p in self._permissions.values() if p.subject_id == subject_id]

        # Get inherited permissions through role hierarchy
        subject = self._subjects.get(subject_id)
        if subject and subject.role:
            inherited = self._get_inherited_permissions(subject.role)
            # Filter to only include permissions for this subject's inherited roles
            inherited_for_subject = []
            for inherited_perm in inherited:
                # Check if this subject should inherit this permission
                # (simplified - assumes role inheritance)
                inherited_for_subject.append(inherited_perm)
            return direct + inherited_for_subject

        return direct

    def _get_inherited_permissions(self, role: str) -> list[PermissionEdge]:
        """Get permissions inherited through role hierarchy."""
        inherited = []

        # Find parent roles
        parent_roles = self._role_hierarchy.get(role, [])

        for parent_role in parent_roles:
            # Get all subjects with parent role
            parent_subjects = self.get_subjects_by_role(parent_role)
            for parent_subject in parent_subjects:
                # Get permissions for parent subject
                inherited.extend([
                    p for p in self._permissions.values()
                    if p.subject_id == parent_subject.id
                ])

            # Recursively get inherited from parent's parents
            inherited.extend(self._get_inherited_permissions(parent_role))

        return inherited

    def get_permissions_for_object(self, object_id: str) -> list[PermissionEdge]:
        """Get all permissions granted for a specific object."""
        return [p for p in self._permissions.values() if p.object_id == object_id]

    def check_permission(
        self,
        subject_id: str,
        object_id: str,
        permission: PermissionType,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Check if a subject has a specific permission for an object."""
        subject = self._subjects.get(subject_id)
        if not subject:
            return False

        # Check direct permissions
        permissions = self.get_permissions_for_subject(subject_id)

        for perm in permissions:
            if perm.object_id == object_id and perm.permission == permission:
                # Check conditions if any
                if perm.conditions:
                    if not self._evaluate_conditions(perm.conditions, context or {}):
                        continue
                return True

        return False

    def _evaluate_conditions(
        self,
        conditions: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """Evaluate if permission conditions are met."""
        # Simple condition evaluation
        # In production, this would be more sophisticated

        if "time_window" in conditions:
            # Check if current time is within window
            pass  # Simplified

        if "ip_whitelist" in conditions:
            # Check if IP is in whitelist
            pass  # Simplified

        if "require_mfa" in conditions:
            # Check if MFA is satisfied in context
            if not context.get("mfa_verified"):
                return False

        return True

    # ============ Gap Analysis ============

    def analyze_gaps(
        self,
        require_mfa_for_admin: bool = True,
        max_session_duration_hours: int = 8,
    ) -> list[GapAnalysis]:
        """Analyze permission graph for security gaps."""
        gaps = []

        # Check for overprivileged subjects
        gaps.extend(self._find_overprivileged_subjects())

        # Check for underprivileged subjects
        gaps.extend(self._find_underprivileged_subjects())

        # Check for unused permissions
        gaps.extend(self._find_unused_permissions())

        # Check for privilege escalation paths
        gaps.extend(self._find_privilege_escalation())

        # Check for admin permission abuse
        if require_mfa_for_admin:
            gaps.extend(self._check_admin_mfa())

        self._gaps = gaps
        logger.info("permission_gaps_analyzed", count=len(gaps))
        return gaps

    def _find_overprivileged_subjects(self) -> list[GapAnalysis]:
        """Find subjects with excessive permissions."""
        gaps = []

        for subject in self._subjects.values():
            # Check if subject has admin permissions on sensitive objects
            admin_perms = [
                p for p in self._permissions.values()
                if p.subject_id == subject.id and p.permission == PermissionType.ADMIN
            ]

            sensitive_admin = []
            for perm in admin_perms:
                obj = self._objects.get(perm.object_id)
                if obj and obj.get("sensitivity") in ["high", "critical"]:
                    sensitive_admin.append(perm.id)

            if len(sensitive_admin) > 3:
                gaps.append(GapAnalysis(
                    id=str(uuid.uuid4()),
                    gap_type="overprivileged",
                    severity="high",
                    subject_id=subject.id,
                    description=f"Subject {subject.name} has {len(sensitive_admin)} admin permissions on sensitive objects",
                    current_permissions=[p.id for p in admin_perms],
                    recommended_permissions=[],  # Would need LLM analysis
                    risk_factors=["privilege_escalation", "insider_threat"],
                ))

        return gaps

    def _find_underprivileged_subjects(self) -> list[GapAnalysis]:
        """Find subjects with insufficient permissions for their role."""
        gaps = []

        # Check for subjects without required role permissions
        for subject in self._subjects.values():
            if subject.subject_type == SubjectType.SERVICE:
                # Services should have well-defined permissions
                if len(subject.direct_permissions) == 0:
                    gaps.append(GapAnalysis(
                        id=str(uuid.uuid4()),
                        gap_type="underprivileged",
                        severity="medium",
                        subject_id=subject.id,
                        description=f"Service {subject.name} has no direct permissions - may indicate misconfiguration",
                        current_permissions=[],
                        recommended_permissions=["Review service account configuration"],
                    ))

        return gaps

    def _find_unused_permissions(self) -> list[GapAnalysis]:
        """Find permissions that are never used."""
        gaps = []

        # For now, flag admin permissions that are granted but might not be needed
        for perm in self._permissions.values():
            if perm.permission == PermissionType.ADMIN and perm.grant_type == "direct":
                subject = self._subjects.get(perm.subject_id)
                if subject and subject.trust_level != "critical":
                    gaps.append(GapAnalysis(
                        id=str(uuid.uuid4()),
                        gap_type="unused",
                        severity="low",
                        subject_id=perm.subject_id,
                        object_id=perm.object_id,
                        description=f"Admin permission may be overly broad for {subject.name}",
                        current_permissions=[perm.id],
                        recommended_permissions=["Restrict to least privilege principle"],
                    ))

        return gaps

    def _find_privilege_escalation(self) -> list[GapAnalysis]:
        """Find potential privilege escalation paths."""
        gaps = []

        # Check for role hierarchy that allows escalation
        for role, parent_roles in self._role_hierarchy.items():
            if role in parent_roles:
                gaps.append(GapAnalysis(
                    id=str(uuid.uuid4()),
                    gap_type="privilege_escalation",
                    severity="critical",
                    description=f"Circular role inheritance detected in role '{role}'",
                    risk_factors=["privilege_escalation"],
                ))

        return gaps

    def _check_admin_mfa(self) -> list[GapAnalysis]:
        """Check if admin permissions require MFA."""
        gaps = []

        for perm in self._permissions.values():
            if perm.permission == PermissionType.ADMIN and not perm.conditions.get("require_mfa"):
                subject = self._subjects.get(perm.subject_id)
                if subject and subject.trust_level in ["medium", "low"]:
                    gaps.append(GapAnalysis(
                        id=str(uuid.uuid4()),
                        gap_type="overprivileged",
                        severity="high",
                        subject_id=perm.subject_id,
                        object_id=perm.object_id,
                        description=f"Admin permission without MFA for {subject.name}",
                        current_permissions=[perm.id],
                        recommended_permissions=["require_mfa: true"],
                        risk_factors=["account_compromise", "insider_threat"],
                    ))

        return gaps

    def get_gaps_by_severity(self, severity: str) -> list[GapAnalysis]:
        """Get all gaps of a specific severity."""
        return [g for g in self._gaps if g.severity == severity]

    # ============ Serialization ============

    def to_dict(self) -> dict[str, Any]:
        """Export permission graph to dictionary."""
        return {
            "project_id": self.project_id,
            "subjects": [s.to_dict() for s in self._subjects.values()],
            "objects": list(self._objects.values()),
            "permissions": [p.to_dict() for p in self._permissions.values()],
            "role_hierarchy": self._role_hierarchy,
            "gaps": [g.to_dict() for g in self._gaps],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PermissionGraphEngine":
        """Import permission graph from dictionary."""
        engine = cls(project_id=data.get("project_id"))

        for subject_data in data.get("subjects", []):
            subject_data_copy = subject_data.copy()
            if "subject_type" in subject_data_copy:
                subject_data_copy["subject_type"] = SubjectType(subject_data_copy["subject_type"])
            subject = PermissionNode(**subject_data_copy)
            engine.add_subject(subject)

        for obj_data in data.get("objects", []):
            engine._objects[obj_data["id"]] = obj_data

        for perm_data in data.get("permissions", []):
            perm_data_copy = perm_data.copy()
            if "permission" in perm_data_copy:
                perm_data_copy["permission"] = PermissionType(perm_data_copy["permission"])
            if "object_type" in perm_data_copy:
                perm_data_copy["object_type"] = ObjectType(perm_data_copy["object_type"])
            perm = PermissionEdge(**perm_data_copy)
            engine._permissions[perm.id] = perm

        engine._role_hierarchy = data.get("role_hierarchy", {})

        return engine

    def clear(self):
        """Clear the entire permission graph."""
        self._subjects.clear()
        self._objects.clear()
        self._permissions.clear()
        self._role_hierarchy.clear()
        self._gaps.clear()
        logger.info("permission_graph_cleared")
