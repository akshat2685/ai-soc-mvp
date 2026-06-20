"""Pydantic models for every memory object type in the platform.

These schemas are the single source of truth for what a "memory object" looks
like — they are used by the store layer, the modules, the REST API, and the
demo/seed scripts. Keeping them in one place keeps the 16 memory modules thin.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Memory object types
# ---------------------------------------------------------------------------
class MemoryType(str, Enum):
    INCIDENT = "incident"
    INVESTIGATION = "investigation"
    THREAT_INTEL = "threat_intel"
    IOC = "ioc"
    USER_BEHAVIOR = "user_behavior"
    ASSET = "asset"
    DETECTION = "detection"
    PLAYBOOK = "playbook"
    FALSE_POSITIVE = "false_positive"
    LESSON_LEARNED = "lesson_learned"
    ATTACK_GRAPH = "attack_graph"
    AGENT_DECISION = "agent_decision"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    MALWARE_FAMILY = "malware_family"
    RESPONSE_ACTION = "response_action"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AgentRole(str, Enum):
    """Roles that may access memory (used by the RBAC layer)."""

    TRIAGE = "triage"
    THREAT_INTEL = "threat_intel"
    INVESTIGATION = "investigation"
    HUNTING = "hunting"
    SOAR = "soar"
    REPORTING = "reporting"


# ---------------------------------------------------------------------------
# Scoring envelope (applies to every memory object)
# ---------------------------------------------------------------------------
class MemoryScores(BaseModel):
    """All scores live in [0.0, 1.0]."""

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    trust: float = Field(default=0.5, ge=0.0, le=1.0)
    recency: float = Field(default=1.0, ge=0.0, le=1.0)
    usage: float = Field(default=0.0, ge=0.0, le=1.0)
    impact: float = Field(default=0.5, ge=0.0, le=1.0)
    importance: float = Field(default=0.5, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Concrete memory objects
# ---------------------------------------------------------------------------
class MemoryObject(BaseModel):
    """Base envelope — every memory record carries these fields."""

    id: Optional[str] = None
    type: MemoryType
    timestamp: datetime = Field(default_factory=utc_now)
    source: str = "system"  # who/what created it
    scores: MemoryScores = Field(default_factory=MemoryScores)
    reference_count: int = 0
    tags: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)


class IncidentMemory(MemoryObject):
    type: MemoryType = MemoryType.INCIDENT
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # incident_id, severity, confidence, alert_source, attack_type,
            # mitre_mapping, affected_assets[], affected_users[],
            # investigation_summary, root_cause, response_actions[],
            # resolution, analyst_feedback
        }
    )


class InvestigationMemory(MemoryObject):
    type: MemoryType = MemoryType.INVESTIGATION
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # incident_id, evidence[], artifacts[], logs[], queries[],
            # reasoning_steps[], conclusions[], recommended_actions[]
        }
    )


class ThreatIntelMemory(MemoryObject):
    type: MemoryType = MemoryType.THREAT_INTEL
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # entity (actor/campaign/malware), ttps[], first_seen, last_seen,
            # frequency, confidence, source_reliability
        }
    )


class IocMemory(MemoryObject):
    type: MemoryType = MemoryType.IOC
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # ioc_type (ip/domain/url/hash/email/registry_key/process),
            # value, times_seen, incidents_linked[], threat_actors_linked[],
            # severity_history[], resolution_history[], risk_score
        }
    )


class UserBehaviorMemory(MemoryObject):
    type: MemoryType = MemoryType.USER_BEHAVIOR
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # user_id, typical_login_time, typical_location, typical_devices[],
            # typical_apps[], typical_activity_level, baseline, drift_score
        }
    )


class AssetMemory(MemoryObject):
    type: MemoryType = MemoryType.ASSET
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # asset_id, kind (server/endpoint/db/app/container/cloud),
            # criticality, owner, vulnerabilities[], patch_history[],
            # incident_history[], risk_score
        }
    )


class DetectionMemory(MemoryObject):
    type: MemoryType = MemoryType.DETECTION
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # rule_id, rule_type (sigma/yara/custom/ml), logic,
            # true_positives, false_positives, false_negatives, coverage, precision
        }
    )


class PlaybookMemory(MemoryObject):
    type: MemoryType = MemoryType.PLAYBOOK
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # playbook_id, name, steps[], triggers[], success_rate,
            # failure_rate, avg_execution_time, analyst_feedback[]
        }
    )


class FalsePositiveMemory(MemoryObject):
    type: MemoryType = MemoryType.FALSE_POSITIVE
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # detection_trigger, investigation_outcome, reason, suppression_key
        }
    )


class LessonLearnedMemory(MemoryObject):
    type: MemoryType = MemoryType.LESSON_LEARNED
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # incident_id, what_happened, why_it_happened,
            # what_worked, what_failed, recommendations[]
        }
    )


class AttackGraphMemory(MemoryObject):
    type: MemoryType = MemoryType.ATTACK_GRAPH
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # incident_id, nodes[], edges[], mermaid_code, summary
        }
    )


class AgentDecisionMemory(MemoryObject):
    type: MemoryType = MemoryType.AGENT_DECISION
    payload: dict[str, Any] = Field(
        default_factory=lambda: {
            # agent_role, decision, reasoning, tool_calls[], outcome,
            # confidence, success (bool)
        }
    )


# ---------------------------------------------------------------------------
# Retrieval / context package
# ---------------------------------------------------------------------------
class RecallRequest(BaseModel):
    """Submitted when a new alert arrives — drives the retrieval pipeline."""

    alert: dict[str, Any]  # arbitrary alert fields (attacker_ip, user_id, attack_type...)
    query_text: Optional[str] = None  # natural-language description
    top_k: int = 5
    agent_role: AgentRole = AgentRole.TRIAGE


class ContextPackage(BaseModel):
    """What gets handed to the LLM so it never investigates without memory."""

    alert: dict[str, Any]
    similar_incidents: list[dict[str, Any]] = Field(default_factory=list)
    related_threat_actors: list[dict[str, Any]] = Field(default_factory=list)
    related_iocs: list[dict[str, Any]] = Field(default_factory=list)
    affected_assets: list[dict[str, Any]] = Field(default_factory=list)
    recommended_playbook: Optional[dict[str, Any]] = None
    graph_context: dict[str, Any] = Field(default_factory=dict)
    blast_radius: list[dict[str, Any]] = Field(default_factory=list)
    lessons: list[dict[str, Any]] = Field(default_factory=list)
    rendered_context: str = ""  # token-budgeted, LLM-ready text
    sources_queried: list[str] = Field(default_factory=list)
    token_estimate: int = 0
