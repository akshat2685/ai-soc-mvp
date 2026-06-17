from typing import TypedDict, Annotated, Sequence
import operator

class AgentState(TypedDict):
    """
    State shared across the multi-agent framework.
    """
    task: str
    messages: Annotated[Sequence[str], operator.add]
    findings: dict
    next_step: str
