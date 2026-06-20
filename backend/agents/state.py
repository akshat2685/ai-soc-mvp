from typing import TypedDict, Annotated, Sequence, List, Dict, Any
import operator

class AgentState(TypedDict):
    """
    State shared across the multi-agent framework.
    """
    task: str
    tenant_id: str
    messages: Annotated[Sequence[str], operator.add]
    findings: dict
    subtasks: List[str]
    current_subtask_index: int
    next_agent: str
    confidence_score: float
    reflection_count: int
    max_reflections: int
    consensus_debate: List[str]
