from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class FeatureAttribution(BaseModel):
    feature_name: str = Field(..., description="The name of the feature (e.g., 'login_failures', 'bytes_out')")
    importance_score: float = Field(..., description="The SHAP value or relative importance score (-1.0 to 1.0)")
    impact_direction: str = Field(..., description="Indicates if this feature pushed the decision toward 'malicious' or 'benign'")

class Counterfactual(BaseModel):
    scenario: str = Field(..., description="A hypothetical change to the scenario")
    outcome_change: str = Field(..., description="How the decision would have changed in this scenario")

class AlternativeHypothesis(BaseModel):
    hypothesis: str = Field(..., description="An alternative explanation for the observed events")
    probability: float = Field(..., description="Estimated probability of this alternative (0.0 to 1.0)")
    refutation_reason: str = Field(..., description="Why this alternative was not selected as the primary conclusion")

class XAIExplanation(BaseModel):
    decision: str = Field(..., description="The final decision or recommendation being explained")
    confidence_score: float = Field(..., description="Confidence in the decision (0.0 to 1.0)")
    primary_reasoning: str = Field(..., description="Plain-text, human-readable explanation of 'Why this decision?'")
    evidence: List[str] = Field(..., description="List of key factual evidence supporting the decision")
    feature_attributions: Optional[List[FeatureAttribution]] = Field(default=None, description="SHAP-like feature importance scores")
    counterfactuals: List[Counterfactual] = Field(..., description="Counterfactual scenarios (what-if analysis)")
    alternative_hypotheses: List[AlternativeHypothesis] = Field(..., description="Other considered explanations")
