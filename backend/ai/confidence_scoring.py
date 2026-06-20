"""EDYSOR Confidence Scoring — AI Decision Confidence Assessment.

Provides:
  - Multi-factor confidence scoring (evidence, patterns, context, FP risk)
  - Action execution thresholds per action type
  - Auto-execute vs. human-approval routing
  - Historical confidence tracking
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("edysor.ai.confidence")


@dataclass
class ConfidenceScore:
    """Multi-dimensional confidence assessment."""
    overall: float = 0.0           # 0.0 – 1.0 composite score
    evidence_strength: float = 0.0  # How strong is the evidence?
    pattern_match: float = 0.0      # Does it match known attack patterns?
    contextual_relevance: float = 0.0  # Is the target high-risk?
    false_positive_risk: float = 0.0   # Historical FP rate for this pattern
    indicator_count: int = 0
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": round(self.overall, 4),
            "evidence_strength": round(self.evidence_strength, 4),
            "pattern_match": round(self.pattern_match, 4),
            "contextual_relevance": round(self.contextual_relevance, 4),
            "false_positive_risk": round(self.false_positive_risk, 4),
            "indicator_count": self.indicator_count,
            "reasoning": self.reasoning,
        }


# ---------------------------------------------------------------------------
# Execution Thresholds (higher = more confidence required)
# ---------------------------------------------------------------------------
EXECUTION_THRESHOLDS: Dict[str, float] = {
    # Critical actions — very high confidence required
    "block_user": 0.95,
    "lock_account": 0.95,
    "isolate_host": 0.90,
    "disable_account": 0.95,
    "block_ip_firewall": 0.90,
    "block_domain_firewall": 0.90,

    # High-impact actions
    "rotate_credentials": 0.85,
    "quarantine_file": 0.85,
    "revoke_access": 0.90,
    "terminate_session": 0.85,

    # Medium-impact actions
    "escalate_incident": 0.70,
    "create_incident": 0.65,
    "send_notification": 0.60,
    "update_severity": 0.70,

    # Low-impact actions
    "add_tag": 0.50,
    "add_note": 0.40,
    "enrich_alert": 0.30,
}

# Weight configuration for composite scoring
SCORE_WEIGHTS = {
    "evidence_strength": 0.30,
    "pattern_match": 0.30,
    "contextual_relevance": 0.25,
    "false_positive_inverse": 0.15,
}


class ConfidenceScorer:
    """Score confidence of AI decisions and route to auto-execute or approval."""

    def __init__(self):
        self._score_history: List[Dict[str, Any]] = []

    def score_threat_detection(
        self,
        indicators: List[str],
        pattern_matches: int = 0,
        total_patterns_checked: int = 1,
        asset_criticality: float = 0.5,
        historical_fp_rate: float = 0.1,
        mitre_techniques_matched: int = 0,
    ) -> ConfidenceScore:
        """Calculate confidence score for a threat detection.
        
        Args:
            indicators: List of IOC indicators found
            pattern_matches: How many detection patterns matched
            total_patterns_checked: Total patterns evaluated
            asset_criticality: 0.0 (low) to 1.0 (critical asset)
            historical_fp_rate: Historical false positive rate for this type
            mitre_techniques_matched: Number of MITRE ATT&CK techniques aligned
        """
        # Evidence strength: more indicators = higher confidence
        indicator_count = len(indicators)
        evidence_strength = min(1.0, indicator_count / 10.0)

        # Pattern match ratio
        pattern_match = pattern_matches / max(total_patterns_checked, 1)

        # MITRE technique alignment bonus
        mitre_bonus = min(0.2, mitre_techniques_matched * 0.05)
        pattern_match = min(1.0, pattern_match + mitre_bonus)

        # Contextual relevance = asset criticality
        contextual_relevance = asset_criticality

        # False positive risk (lower is better)
        false_positive_risk = min(1.0, historical_fp_rate)

        # Composite score
        overall = (
            evidence_strength * SCORE_WEIGHTS["evidence_strength"] +
            pattern_match * SCORE_WEIGHTS["pattern_match"] +
            contextual_relevance * SCORE_WEIGHTS["contextual_relevance"] +
            (1.0 - false_positive_risk) * SCORE_WEIGHTS["false_positive_inverse"]
        )

        reasoning_parts = []
        if evidence_strength > 0.7:
            reasoning_parts.append(f"{indicator_count} strong indicators")
        if pattern_match > 0.5:
            reasoning_parts.append(f"{pattern_matches}/{total_patterns_checked} patterns matched")
        if mitre_techniques_matched > 0:
            reasoning_parts.append(f"{mitre_techniques_matched} MITRE techniques aligned")
        if asset_criticality > 0.7:
            reasoning_parts.append("high-criticality asset")
        if false_positive_risk < 0.1:
            reasoning_parts.append("low historical FP rate")

        score = ConfidenceScore(
            overall=round(overall, 4),
            evidence_strength=round(evidence_strength, 4),
            pattern_match=round(pattern_match, 4),
            contextual_relevance=round(contextual_relevance, 4),
            false_positive_risk=round(false_positive_risk, 4),
            indicator_count=indicator_count,
            reasoning="; ".join(reasoning_parts) if reasoning_parts else "Insufficient evidence",
        )

        self._score_history.append({
            "timestamp": time.time(),
            "score": score.to_dict(),
        })

        return score

    def can_auto_execute(
        self,
        action: str,
        confidence: ConfidenceScore,
    ) -> Tuple[bool, str]:
        """Determine if action can be auto-executed based on confidence.
        
        Returns (can_execute, reason).
        """
        threshold = EXECUTION_THRESHOLDS.get(action, 0.85)

        if confidence.overall >= threshold:
            return True, (
                f"Confidence {confidence.overall:.2f} meets threshold {threshold:.2f} — "
                f"auto-execution permitted"
            )
        else:
            return False, (
                f"Confidence {confidence.overall:.2f} below threshold {threshold:.2f} — "
                f"requires human approval"
            )

    def get_threshold(self, action: str) -> float:
        """Get the execution threshold for an action."""
        return EXECUTION_THRESHOLDS.get(action, 0.85)

    def get_score_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent confidence scoring history."""
        return self._score_history[-limit:]

    def get_score_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics on confidence scores."""
        if not self._score_history:
            return {"count": 0}

        scores = [h["score"]["overall"] for h in self._score_history]
        return {
            "count": len(scores),
            "mean": round(sum(scores) / len(scores), 4),
            "min": round(min(scores), 4),
            "max": round(max(scores), 4),
            "above_threshold": sum(1 for s in scores if s >= 0.85),
            "below_threshold": sum(1 for s in scores if s < 0.85),
        }


# Global confidence scorer
confidence_scorer = ConfidenceScorer()
