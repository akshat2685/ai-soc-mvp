from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List
from xai.schemas import XAIExplanation, FeatureAttribution
from xai.engine import XAIEngine

router = APIRouter()

class XAIRequest(BaseModel):
    decision: str
    context_data: Dict[str, Any]
    agent_reasoning_trace: List[str]

class FeatureAttributionRequest(BaseModel):
    features: Dict[str, float]
    model_weights: Dict[str, float] = None

@router.post("/explain", response_model=XAIExplanation)
async def generate_explanation(request: XAIRequest):
    """
    Generate an Explainable AI (XAI) payload with counterfactuals and hypotheses.
    """
    try:
        explanation = XAIEngine.generate_explanation(
            decision=request.decision,
            context_data=request.context_data,
            agent_reasoning_trace=request.agent_reasoning_trace
        )
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/feature-attribution", response_model=List[FeatureAttribution])
async def get_feature_attributions(request: FeatureAttributionRequest):
    """
    Generate SHAP-like feature attributions for heuristic or ML-based detectors.
    """
    try:
        attributions = XAIEngine.generate_feature_attribution(
            features=request.features,
            model_weights=request.model_weights
        )
        return attributions
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
