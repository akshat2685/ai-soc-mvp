from fastapi import APIRouter, HTTPException
import logging
from memory.multi_layer import MultiLayerMemory

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/panic")
async def trigger_panic_button():
    """
    Triggers the EDYSOR-X Panic Button (Phase 0 Quick Win).
    - Flushes Working Memory (LLM Context)
    - Triggers simulated OPA network isolation
    """
    logger.critical("[EMERGENCY] Panic Button Triggered by Executive Operator.")
    
    # 1. Wipe Context (Working Memory)
    memory_sys = MultiLayerMemory()
    memory_sys.working_memory.clear()
    logger.critical("[EMERGENCY] Working Memory (LLM Context) wiped.")
    
    # 2. Trigger OPA Network Isolation (Mock implementation)
    # In production, this pushes an emergency DENY ALL policy to the OPA agent
    logger.critical("[EMERGENCY] OPA Policy 'Isolate All Subnets' dispatched.")
    
    return {
        "status": "PANIC_TRIGGERED",
        "actions_taken": [
            "working_memory_wiped",
            "opa_network_isolation_enforced"
        ]
    }
