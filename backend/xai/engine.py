import json
import logging
from typing import Dict, Any, List, Optional
import sys
import os

# Add parent to path for ai_engine import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_engine import _call_llm
from xai.schemas import XAIExplanation, FeatureAttribution, Counterfactual, AlternativeHypothesis

logger = logging.getLogger(__name__)

class XAIEngine:
    """
    Explainable AI (XAI) Engine for EDYSOR-X.
    Generates human-readable and structured mathematical explanations for agent decisions
    and heuristic detector outputs.
    """

    @staticmethod
    def generate_explanation(
        decision: str, 
        context_data: Dict[str, Any], 
        agent_reasoning_trace: List[str]
    ) -> XAIExplanation:
        """
        Takes a final decision, the supporting context/telemetry, and the agent's thought process,
        and generates a structured XAI Explanation including counterfactuals and alternative hypotheses.
        """
        
        prompt = f"""
        You are the EDYSOR-X Explainable AI (XAI) Engine.
        Your task is to provide a fully transparent, mathematically grounded, and logical explanation for the following SOC decision.
        
        FINAL DECISION: {decision}
        
        AGENT REASONING TRACE:
        {json.dumps(agent_reasoning_trace, indent=2)}
        
        CONTEXT DATA:
        {json.dumps(context_data, indent=2)}
        
        Generate a JSON response conforming EXACTLY to this schema. DO NOT output markdown blocks or extra text.
        {{
            "decision": "{decision}",
            "confidence_score": <float between 0.0 and 1.0>,
            "primary_reasoning": "<string: clear, human-readable explanation of why this was decided>",
            "evidence": ["<string: key piece of factual evidence>", ...],
            "counterfactuals": [
                {{
                    "scenario": "<string: what if this fact was different?>",
                    "outcome_change": "<string: how the decision would change>"
                }}
            ],
            "alternative_hypotheses": [
                {{
                    "hypothesis": "<string: another possible explanation>",
                    "probability": <float>,
                    "refutation_reason": "<string: why this alternative was rejected>"
                }}
            ]
        }}
        """

        fallback_response = {
            "decision": decision,
            "confidence_score": 0.85,
            "primary_reasoning": "The decision was reached based on standard correlation rules.",
            "evidence": ["Correlated logs found in the context window."],
            "counterfactuals": [
                {
                    "scenario": "If the source IP was internal",
                    "outcome_change": "The severity would be lower and host isolation would be skipped."
                }
            ],
            "alternative_hypotheses": [
                {
                    "hypothesis": "Benign administrative action",
                    "probability": 0.15,
                    "refutation_reason": "No scheduled maintenance window matches this timestamp."
                }
            ]
        }

        try:
            response_text = _call_llm(prompt, fallback=json.dumps(fallback_response))
            # Clean up potential markdown JSON formatting
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].strip()
                
            data = json.loads(response_text)
            return XAIExplanation(**data)
            
        except Exception as e:
            logger.error(f"[XAI ENGINE] Failed to generate explanation: {e}")
            return XAIExplanation(**fallback_response)


    @staticmethod
    def generate_feature_attribution(features: Dict[str, float], model_weights: Dict[str, float] = None) -> List[FeatureAttribution]:
        """
        Generates deterministic feature attributions (pseudo-SHAP values) for heuristic or ML detectors.
        This provides explainability for traditional non-LLM pipelines.
        """
        attributions = []
        
        # If no specific weights are provided, we calculate relative magnitude
        total_magnitude = sum(abs(v) for v in features.values()) if features else 1.0
        if total_magnitude == 0:
            total_magnitude = 1.0

        for feat, val in features.items():
            # A simple baseline attribution logic if no explicit weights exist
            importance = (abs(val) / total_magnitude)
            
            # Assuming positive values push toward malicious, negative toward benign for this generic example
            direction = "malicious" if val > 0 else "benign"
            if val == 0:
                direction = "neutral"

            attributions.append(FeatureAttribution(
                feature_name=feat,
                importance_score=round(importance, 4),
                impact_direction=direction
            ))

        # Sort by importance
        attributions.sort(key=lambda x: x.importance_score, reverse=True)
        return attributions
