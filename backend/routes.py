from fastapi import APIRouter, Request, Response, HTTPException
from models import LogEntry, BatchLogIngestion
import json
import logging
import asyncio

router = APIRouter(prefix="/api/v1", tags=["logs"])
logger = logging.getLogger(__name__)

from streaming.producer import event_producer

async def send_to_kafka(topic: str, value: dict):
    # Ensure timestamp is serialized properly
    if 'timestamp' in value and hasattr(value['timestamp'], 'isoformat'):
        value['timestamp'] = value['timestamp'].isoformat()
    await event_producer.publish(topic, value)
@router.post("/logs")
async def ingest_log(log_entry: LogEntry, request: Request):
    """
    Ingest a single log entry with full validation.
    """
    try:
        logger.info(
            "Log ingested successfully",
            extra={
                "user_id": log_entry.user_id,
                "event_type": log_entry.event_type,
                "source_ip": log_entry.source_ip,
                "timestamp": log_entry.timestamp.isoformat()
            }
        )
        
        await send_to_kafka(
            topic="security-logs",
            value=log_entry.model_dump(exclude_unset=True)
        )
        
        return {"status": "success", "message": "Log ingested"}
    except ValueError as e:
        logger.warning("Validation error", extra={"error": str(e), "source_ip": request.client.host})
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Unexpected error during log ingestion", extra={"error": str(e)}, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/logs/batch")
async def ingest_batch(batch: BatchLogIngestion, request: Request):
    """
    Ingest multiple logs in a single request.
    """
    log_count = len(batch.logs)
    
    try:
        kafka_futures = []
        for log in batch.logs:
            future = send_to_kafka(topic="security-logs", value=log.model_dump(exclude_unset=True))
            kafka_futures.append(future)
            
        await asyncio.gather(*kafka_futures)
        logger.info("Batch ingested", extra={"count": log_count, "source_ip": request.client.host})
        return {"status": "success", "count": log_count}
    except Exception as e:
        logger.error("Batch ingestion failed", extra={"error": str(e), "count": log_count}, exc_info=True)
        raise HTTPException(status_code=500, detail="Batch processing failed")
