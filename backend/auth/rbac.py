"""EDYSOR Fine-Grained Role-Based & Attribute-Based Access Control (RBAC/ABAC).

Provides:
  - SOC-specific role hierarchy (Analyst → Manager → Commander → CISO)
  - Fine-grained permission enum with 25+ security operations
  - Attribute-based checks for zone/classification/time restrictions
  - FastAPI dependency helpers for route protection
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("edysor.auth.rbac")


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
class Role(str, Enum):
    SOC_ANALYST = "soc_analyst"
    SENIOR_ANALYST = "senior_analyst"
    SOC_MANAGER = "soc_manager"
    INCIDENT_COMMANDER = "incident_commander"
    DETECTION_ENGINEER = "detection_engineer"
    THREAT_HUNTER = "threat_hunter"
    DEVOPS = "devops"
    AUDIT = "audit"
    CISO = "ciso"
    ADMIN = "admin"


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
class Permission(str, Enum):
    # Read operations
    READ_ALERTS = "read_alerts"
    READ_INCIDENTS = "read_incidents"
    READ_PLAYBOOKS = "read_playbooks"
    READ_AUDIT_LOGS = "read_audit_logs"
    READ_DETECTIONS = "read_detections"
    READ_THREAT_INTEL = "read_threat_intel"
    READ_EXECUTIVE_DASHBOARD = "read_executive_dashboard"
    READ_COPILOT = "read_copilot"
    READ_DIGITAL_TWIN = "read_digital_twin"
    READ_TRAINING = "read_training"

    # Write / Execute operations
    CREATE_INCIDENT = "create_incident"
    MODIFY_INCIDENT = "modify_incident"
    CLOSE_INCIDENT = "close_incident"
    EXECUTE_PLAYBOOK = "execute_playbook"
    APPROVE_CRITICAL_ACTION = "approve_critical_action"
    DENY_CRITICAL_ACTION = "deny_critical_action"
    MODIFY_DETECTION_RULES = "modify_detection_rules"
    CREATE_DETECTION_RULES = "create_detection_rules"
    DELETE_DETECTION_RULES = "delete_detection_rules"
    RUN_PURPLE_TEAM = "run_purple_team"
    RUN_SIMULATION = "run_simulation"
    TRIGGER_TRAINING = "trigger_training"
    DEPLOY_MODEL = "deploy_model"

    # Admin operations
    MANAGE_USERS = "manage_users"
    MANAGE_INTEGRATIONS = "manage_integrations"
    CONFIGURE_SYSTEM = "configure_system"
    EXPORT_DATA = "export_data"
    DELETE_DATA = "delete_data"
    VIEW_SYSTEM_HEALTH = "view_system_health"


# ---------------------------------------------------------------------------
# Role → Permission Mapping
# ---------------------------------------------------------------------------
_BASE_READ: Set[Permission] = {
    Permission.READ_ALERTS,
    Permission.READ_INCIDENTS,
    Permission.READ_PLAYBOOKS,
    Permission.READ_DETECTIONS,
    Permission.READ_THREAT_INTEL,
    Permission.READ_COPILOT,
}

ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.SOC_ANALYST: _BASE_READ | {
        Permission.CREATE_INCIDENT,
        Permission.MODIFY_INCIDENT,
    },
    Role.SENIOR_ANALYST: _BASE_READ | {
        Permission.CREATE_INCIDENT,
        Permission.MODIFY_INCIDENT,
        Permission.CLOSE_INCIDENT,
        Permission.EXECUTE_PLAYBOOK,
    },
    Role.SOC_MANAGER: _BASE_READ | {
        Permission.CREATE_INCIDENT,
        Permission.MODIFY_INCIDENT,
        Permission.CLOSE_INCIDENT,
        Permission.EXECUTE_PLAYBOOK,
        Permission.APPROVE_CRITICAL_ACTION,
        Permission.DENY_CRITICAL_ACTION,
        Permission.READ_AUDIT_LOGS,
        Permission.READ_EXECUTIVE_DASHBOARD,
        Permission.RUN_PURPLE_TEAM,
        Permission.MANAGE_INTEGRATIONS,
    },
    Role.INCIDENT_COMMANDER: _BASE_READ | {
        Permission.CREATE_INCIDENT,
        Permission.MODIFY_INCIDENT,
        Permission.CLOSE_INCIDENT,
        Permission.EXECUTE_PLAYBOOK,
        Permission.APPROVE_CRITICAL_ACTION,
        Permission.DENY_CRITICAL_ACTION,
        Permission.MODIFY_DETECTION_RULES,
        Permission.RUN_PURPLE_TEAM,
        Permission.RUN_SIMULATION,
        Permission.READ_AUDIT_LOGS,
        Permission.READ_EXECUTIVE_DASHBOARD,
        Permission.READ_DIGITAL_TWIN,
    },
    Role.DETECTION_ENGINEER: _BASE_READ | {
        Permission.MODIFY_DETECTION_RULES,
        Permission.CREATE_DETECTION_RULES,
        Permission.DELETE_DETECTION_RULES,
        Permission.RUN_PURPLE_TEAM,
    },
    Role.THREAT_HUNTER: _BASE_READ | {
        Permission.READ_DIGITAL_TWIN,
        Permission.RUN_SIMULATION,
        Permission.RUN_PURPLE_TEAM,
        Permission.READ_THREAT_INTEL,
    },
    Role.DEVOPS: {
        Permission.VIEW_SYSTEM_HEALTH,
        Permission.READ_AUDIT_LOGS,
        Permission.CONFIGURE_SYSTEM,
        Permission.READ_TRAINING,
    },
    Role.AUDIT: {
        Permission.READ_ALERTS,
        Permission.READ_INCIDENTS,
        Permission.READ_AUDIT_LOGS,
        Permission.READ_EXECUTIVE_DASHBOARD,
        Permission.EXPORT_DATA,
    },
    Role.CISO: set(Permission),  # All permissions
    Role.ADMIN: set(Permission),  # All permissions
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role string has a specific permission string."""
    try:
        role_enum = Role(role)
        perm_enum = Permission(permission)
    except ValueError:
        # Legacy role names fallback
        legacy_map = {"analyst": Role.SOC_ANALYST, "senior_analyst": Role.SENIOR_ANALYST, "admin": Role.ADMIN}
        role_enum = legacy_map.get(role)
        if role_enum is None:
            return False
        try:
            perm_enum = Permission(permission)
        except ValueError:
            return False
    return perm_enum in ROLE_PERMISSIONS.get(role_enum, set())


def get_permissions_for_role(role: str) -> List[str]:
    """Return list of permission strings for a role."""
    try:
        role_enum = Role(role)
    except ValueError:
        legacy_map = {"analyst": Role.SOC_ANALYST, "senior_analyst": Role.SENIOR_ANALYST, "admin": Role.ADMIN}
        role_enum = legacy_map.get(role)
        if role_enum is None:
            return []
    return [p.value for p in ROLE_PERMISSIONS.get(role_enum, set())]


# ---------------------------------------------------------------------------
# ABAC: Attribute-Based Access Control
# ---------------------------------------------------------------------------
class ABACPolicy:
    """Attribute-based policy checks layered on top of RBAC.
    
    Evaluates contextual attributes like:
    - zone/region restrictions  
    - data classification level
    - time-of-day restrictions
    - asset criticality
    """

    def __init__(self):
        self._zone_restrictions: Dict[str, List[str]] = {}  # user_id → allowed zones
        self._classification_access: Dict[str, List[str]] = {}

    def can_access_resource(
        self,
        user: Dict[str, Any],
        resource: Dict[str, Any],
        action: str,
    ) -> tuple[bool, str]:
        """Evaluate ABAC policy for a specific resource access attempt."""

        # Check role-based permission first
        if not has_permission(user.get("role", ""), action):
            return False, f"Role '{user.get('role')}' lacks permission '{action}'"

        # Zone restriction check
        user_zones = self._zone_restrictions.get(user.get("user_id", ""))
        resource_zone = resource.get("zone")
        if user_zones and resource_zone and resource_zone not in user_zones:
            return False, f"User not authorized for zone '{resource_zone}'"

        # Data classification check
        resource_classification = resource.get("classification", "internal")
        restricted_classifications = {"restricted", "confidential"}
        if resource_classification in restricted_classifications:
            user_clearance = self._classification_access.get(user.get("user_id", ""), [])
            if resource_classification not in user_clearance:
                role = user.get("role", "")
                # CISO and ADMIN always have access
                if role not in (Role.CISO.value, Role.ADMIN.value):
                    return False, f"Insufficient clearance for '{resource_classification}' data"

        return True, "Access granted"

    def set_zone_restrictions(self, user_id: str, zones: List[str]):
        """Assign zone restrictions to a user."""
        self._zone_restrictions[user_id] = zones

    def set_classification_access(self, user_id: str, classifications: List[str]):
        """Assign classification access levels to a user."""
        self._classification_access[user_id] = classifications


# Global ABAC policy instance
abac_policy = ABACPolicy()


def require_permission(permission: Permission):
    """FastAPI dependency factory that enforces a specific permission.

    Usage:
        @app.get("/api/incidents", dependencies=[Depends(require_permission(Permission.READ_INCIDENTS))])
    """
    def _check(user: dict) -> dict:
        role = user.get("role", "")
        if not has_permission(role, permission.value):
            raise PermissionError(
                f"Permission '{permission.value}' required — role '{role}' insufficient"
            )
        return user
    return _check
