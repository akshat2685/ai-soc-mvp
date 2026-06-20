"""Role-based access control for multi-agent memory access.

Each agent role has a permitted set of operations. This keeps the SOAR agent
from writing lessons learned, the reporting agent from mutating IOCs, etc.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .schemas import MemoryType


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"   # reserved; the platform never truly deletes
    LEARN = "learn"     # may run the continuous-learning engine


# What memory types each role may READ
_READ_SCOPE: dict[str, set[str]] = {
    "triage": {MemoryType.INCIDENT.value, MemoryType.IOC.value, MemoryType.THREAT_INTEL.value, MemoryType.FALSE_POSITIVE.value},
    "threat_intel": {MemoryType.THREAT_INTEL.value, MemoryType.IOC.value, MemoryType.MALWARE_FAMILY.value, MemoryType.CAMPAIGN.value, MemoryType.THREAT_ACTOR.value},
    "investigation": {m.value for m in MemoryType},  # full read
    "hunting": {MemoryType.IOC.value, MemoryType.THREAT_INTEL.value, MemoryType.ATTACK_GRAPH.value, MemoryType.INCIDENT.value, MemoryType.ASSET.value, MemoryType.USER_BEHAVIOR.value},
    "soar": {MemoryType.PLAYBOOK.value, MemoryType.INCIDENT.value, MemoryType.RESPONSE_ACTION.value, MemoryType.AGENT_DECISION.value},
    "reporting": {m.value for m in MemoryType},  # full read
}

# What memory types each role may WRITE
_WRITE_SCOPE: dict[str, set[str]] = {
    "triage": {MemoryType.FALSE_POSITIVE.value, MemoryType.AGENT_DECISION.value},
    "threat_intel": {MemoryType.THREAT_INTEL.value, MemoryType.IOC.value, MemoryType.MALWARE_FAMILY.value, MemoryType.CAMPAIGN.value, MemoryType.THREAT_ACTOR.value},
    "investigation": {MemoryType.INVESTIGATION.value, MemoryType.ATTACK_GRAPH.value, MemoryType.LESSON_LEARNED.value, MemoryType.AGENT_DECISION.value},
    "hunting": {MemoryType.IOC.value, MemoryType.ATTACK_GRAPH.value, MemoryType.AGENT_DECISION.value},
    "soar": {MemoryType.PLAYBOOK.value, MemoryType.RESPONSE_ACTION.value, MemoryType.AGENT_DECISION.value},
    "reporting": {MemoryType.LESSON_LEARNED.value, MemoryType.AGENT_DECISION.value},
}

# Which roles may trigger the learning engine
_LEARN_SCOPE: set[str] = {"investigation", "soar", "reporting"}


@dataclass
class Principal:
    role: str
    identity: str = "agent"
    permissions: set[Permission] = field(default_factory=set)

    @classmethod
    def for_role(cls, role: str, identity: str = "agent") -> "Principal":
        perms: set[Permission] = {Permission.READ}
        if role in _WRITE_SCOPE:
            perms.add(Permission.WRITE)
        if role in _LEARN_SCOPE:
            perms.add(Permission.LEARN)
        return cls(role=role, identity=identity, permissions=perms)


def can_read(principal: Principal, memory_type: str) -> bool:
    return Permission.READ in principal.permissions and memory_type in _READ_SCOPE.get(principal.role, set())


def can_write(principal: Principal, memory_type: str) -> bool:
    return Permission.WRITE in principal.permissions and memory_type in _WRITE_SCOPE.get(principal.role, set())


def can_learn(principal: Principal) -> bool:
    return Permission.LEARN in principal.permissions


def authorize(principal: Principal, perm: Permission, memory_type: str | None = None) -> None:
    """Raise PermissionError if the principal lacks the permission."""
    if perm == Permission.READ and memory_type and not can_read(principal, memory_type):
        raise PermissionError(f"Role '{principal.role}' cannot READ {memory_type}")
    if perm == Permission.WRITE and memory_type and not can_write(principal, memory_type):
        raise PermissionError(f"Role '{principal.role}' cannot WRITE {memory_type}")
    if perm == Permission.LEARN and not can_learn(principal):
        raise PermissionError(f"Role '{principal.role}' cannot run the learning engine")


def describe_roles() -> dict[str, dict[str, Any]]:
    """Human-readable summary for the docs / API."""
    out: dict[str, dict[str, Any]] = {}
    for role in sorted(set(list(_READ_SCOPE) + list(_WRITE_SCOPE))):
        out[role] = {
            "read": sorted(_READ_SCOPE.get(role, set())),
            "write": sorted(_WRITE_SCOPE.get(role, set())),
            "can_learn": role in _LEARN_SCOPE,
        }
    return out
