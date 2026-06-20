"""EDYSOR Explainability Engine — Transparent & Auditable AI Decisions.

Provides:
  - Step-by-step reasoning trace for every AI decision
  - Evidence collection and citation
  - Alternative interpretation generation
  - Full audit trail for compliance
  - Human-readable decision summaries
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("edysor.ai.explainability")


@dataclass
class ReasoningStep:
    """A single step in the AI's reasoning process."""
    step_number: int
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence_contribution: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "description": self.description,
            "evidence": self.evidence,
            "confidence_contribution": round(self.confidence_contribution, 4),
            "timestamp": self.timestamp,
        }


@dataclass
class ExplainableDecision:
    """A fully explainable AI decision with reasoning trace."""
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decision: str = ""
    confidence: float = 0.0
    reasoning_steps: List[ReasoningStep] = field(default_factory=list)
    supporting_evidence: Dict[str, Any] = field(default_factory=dict)
    alternative_interpretations: List[str] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    created_by: str = "edysor_ai"

    def add_reasoning_step(self, description: str, evidence: Dict[str, Any] = None, contribution: float = 0.0):
        """Add a reasoning step to the decision trace."""
        step = ReasoningStep(
            step_number=len(self.reasoning_steps) + 1,
            description=description,
            evidence=evidence or {},
            confidence_contribution=contribution,
        )
        self.reasoning_steps.append(step)
        self.audit_trail.append({
            "action": "reasoning_step_added",
            "step": step.step_number,
            "description": description,
            "timestamp": time.time(),
        })

    def add_evidence(self, key: str, value: Any):
        """Add supporting evidence."""
        self.supporting_evidence[key] = value
        self.audit_trail.append({
            "action": "evidence_added",
            "key": key,
            "timestamp": time.time(),
        })

    def add_alternative(self, interpretation: str):
        """Add an alternative interpretation."""
        self.alternative_interpretations.append(interpretation)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision": self.decision,
            "confidence": round(self.confidence, 4),
            "reasoning_steps": [s.to_dict() for s in self.reasoning_steps],
            "supporting_evidence": self.supporting_evidence,
            "alternative_interpretations": self.alternative_interpretations,
            "audit_trail": self.audit_trail,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "created_by": self.created_by,
        }

    def to_human_readable(self) -> str:
        """Generate a human-readable summary of the decision."""
        lines = [
            f"## Decision: {self.decision}",
            f"**Confidence:** {self.confidence:.1%}",
            "",
            "### Reasoning Steps:",
        ]
        for step in self.reasoning_steps:
            lines.append(f"  {step.step_number}. {step.description}")
            if step.evidence:
                for k, v in step.evidence.items():
                    lines.append(f"     - {k}: {v}")

        if self.alternative_interpretations:
            lines.append("")
            lines.append("### Alternative Interpretations:")
            for alt in self.alternative_interpretations:
                lines.append(f"  - {alt}")

        return "\n".join(lines)


class ExplainabilityEngine:
    """Generate transparent, auditable explanations for AI decisions."""

    def __init__(self):
        self._decision_store: Dict[str, ExplainableDecision] = {}

    def create_decision(self, decision_type: str = "") -> ExplainableDecision:
        """Create a new explainable decision context."""
        decision = ExplainableDecision()
        self._decision_store[decision.decision_id] = decision
        return decision

    def explain_threat_classification(
        self,
        alert_data: Dict[str, Any],
        indicators: List[str],
        patterns_matched: List[str],
        confidence: float,
        classification: str,
    ) -> ExplainableDecision:
        """Build a complete explanation for a threat classification."""
        decision = self.create_decision()
        decision.decision = f"Classified as: {classification}"
        decision.confidence = confidence

        # Step 1: Initial alert analysis
        decision.add_reasoning_step(
            f"Analyzed alert from source '{alert_data.get('source_system', 'unknown')}' "
            f"with severity '{alert_data.get('severity', 'unknown')}'",
            evidence={"source": alert_data.get("source_system"), "severity": alert_data.get("severity")},
            contribution=0.1,
        )

        # Step 2: Indicator extraction
        decision.add_reasoning_step(
            f"Extracted {len(indicators)} threat indicators from alert data",
            evidence={"indicators": indicators[:5], "total_count": len(indicators)},
            contribution=0.25,
        )

        # Step 3: Pattern matching
        decision.add_reasoning_step(
            f"Matched {len(patterns_matched)} known attack patterns",
            evidence={"patterns": patterns_matched[:5]},
            contribution=0.3,
        )

        # Step 4: Context analysis
        asset = alert_data.get("affected_asset", "unknown")
        decision.add_reasoning_step(
            f"Assessed context risk for affected asset '{asset}'",
            evidence={"asset": asset, "zone": alert_data.get("zone", "unknown")},
            contribution=0.15,
        )

        # Step 5: Classification decision
        decision.add_reasoning_step(
            f"Final classification: '{classification}' with {confidence:.1%} confidence",
            evidence={"classification": classification, "confidence": confidence},
            contribution=0.2,
        )

        # Add evidence
        decision.add_evidence("alert_data", {k: v for k, v in alert_data.items() if k != "raw_log"})
        decision.add_evidence("indicators", indicators)
        decision.add_evidence("patterns_matched", patterns_matched)

        # Alternative interpretations
        if confidence < 0.8:
            decision.add_alternative(
                f"Low confidence ({confidence:.1%}) — could be a false positive or benign anomaly"
            )
        if "lateral_movement" in classification.lower():
            decision.add_alternative("Could be legitimate admin activity or automated tooling")
        if "data_exfiltration" in classification.lower():
            decision.add_alternative("Could be a large backup operation or data sync")

        return decision

    def explain_remediation_choice(
        self,
        incident_id: str,
        chosen_action: str,
        confidence: float,
        alternatives_considered: List[str],
        reasoning: str,
    ) -> ExplainableDecision:
        """Explain why a specific remediation action was chosen."""
        decision = self.create_decision()
        decision.decision = f"Remediation: {chosen_action}"
        decision.confidence = confidence

        decision.add_reasoning_step(
            f"Evaluated incident {incident_id} for remediation options",
            evidence={"incident_id": incident_id},
            contribution=0.2,
        )

        decision.add_reasoning_step(
            f"Considered {len(alternatives_considered)} alternative actions",
            evidence={"alternatives": alternatives_considered},
            contribution=0.3,
        )

        decision.add_reasoning_step(
            f"Selected '{chosen_action}' based on: {reasoning}",
            evidence={"chosen": chosen_action, "reasoning": reasoning},
            contribution=0.5,
        )

        for alt in alternatives_considered:
            if alt != chosen_action:
                decision.add_alternative(f"Could have chosen: {alt}")

        return decision

    def get_decision(self, decision_id: str) -> Optional[ExplainableDecision]:
        """Retrieve a stored decision by ID."""
        return self._decision_store.get(decision_id)

    def get_recent_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent decisions as dicts."""
        decisions = sorted(
            self._decision_store.values(),
            key=lambda d: d.created_at,
            reverse=True,
        )[:limit]
        return [d.to_dict() for d in decisions]

    def get_statistics(self) -> Dict[str, Any]:
        """Get explainability statistics."""
        if not self._decision_store:
            return {"total_decisions": 0}

        confidences = [d.confidence for d in self._decision_store.values()]
        steps_counts = [len(d.reasoning_steps) for d in self._decision_store.values()]

        return {
            "total_decisions": len(self._decision_store),
            "avg_confidence": round(sum(confidences) / len(confidences), 4),
            "avg_reasoning_steps": round(sum(steps_counts) / len(steps_counts), 2),
            "low_confidence_decisions": sum(1 for c in confidences if c < 0.7),
        }


# Global explainability engine
explainability_engine = ExplainabilityEngine()
