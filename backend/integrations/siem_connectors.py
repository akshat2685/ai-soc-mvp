import logging
from fastapi import APIRouter, Request, BackgroundTasks
from typing import Dict, Any
from .parsers import SIEMParser
from kafka_producer import publish_log
from models import TelemetryLog

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/splunk")
async def ingest_splunk_webhook(request: Request, background_tasks: BackgroundTasks):
    """Webhook endpoint to receive pushed alerts from Splunk."""
    try:
        payload = await request.json()
        logger.info("[SIEM CONNECTOR] Received Splunk Webhook payload.")
        
        normalized_data = SIEMParser.parse_splunk(payload)
        
        # Validate against Pydantic schema
        log_entry = TelemetryLog(**normalized_data)
        
        # Push to Kafka pipeline for real-time AI ingestion
        background_tasks.add_task(publish_log, log_entry)
        
        return {"status": "success", "message": "Splunk log normalized and queued for processing."}
    except Exception as e:
        logger.error(f"[SIEM CONNECTOR] Failed to process Splunk payload: {e}")
        return {"status": "error", "message": str(e)}

@router.post("/crowdstrike")
async def ingest_crowdstrike_webhook(request: Request, background_tasks: BackgroundTasks):
    """Webhook endpoint to receive pushed alerts from CrowdStrike Falcon."""
    try:
        payload = await request.json()
        logger.info("[SIEM CONNECTOR] Received CrowdStrike Falcon Webhook payload.")
        
        normalized_data = SIEMParser.parse_crowdstrike(payload)
        
        # Validate against Pydantic schema
        log_entry = TelemetryLog(**normalized_data)
        
        # Push to Kafka pipeline for real-time AI ingestion
        background_tasks.add_task(publish_log, log_entry)
        
        return {"status": "success", "message": "CrowdStrike alert normalized and queued for processing."}
    except Exception as e:
        logger.error(f"[SIEM CONNECTOR] Failed to process CrowdStrike payload: {e}")
        return {"status": "error", "message": str(e)}
