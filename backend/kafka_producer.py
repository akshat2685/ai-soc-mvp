"""Kafka producer client for publishing ingested security logs."""
import os
import json
import socket
import logging
from kafka import KafkaProducer

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "security-logs"

_kafka_producer = None
_kafka_enabled = None

def check_kafka_status() -> bool:
    global _kafka_enabled
    if _kafka_enabled is not None:
        return _kafka_enabled
    
    try:
        host, port = KAFKA_BOOTSTRAP_SERVERS.split(":")
        # 0.5 second socket check to avoid blocking
        s = socket.create_connection((host, int(port)), timeout=0.5)
        s.close()
        _kafka_enabled = True
        logger.info("Kafka broker is reachable.")
    except Exception:
        _kafka_enabled = False
        logger.warning(f"Kafka broker not reachable at {KAFKA_BOOTSTRAP_SERVERS}. Using local fallback.")
    return _kafka_enabled

def get_kafka_producer():
    global _kafka_producer
    if not check_kafka_status():
        return None
        
    if _kafka_producer is not None:
        return _kafka_producer
    
    try:
        _kafka_producer = KafkaProducer(
            bootstrap_servers=[KAFKA_BOOTSTRAP_SERVERS],
            value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
            acks='all',
            retries=3,
            max_block_ms=1000  # Fail fast
        )
        logger.info(f"Connected to Kafka successfully ({KAFKA_BOOTSTRAP_SERVERS}).")
        return _kafka_producer
    except Exception as e:
        logger.warning(f"Failed to instantiate KafkaProducer: {e}. Disabling Kafka.")
        return None

def publish_log(log_data: dict):
    """Publish a log message to the Kafka ingestion topic."""
    producer = get_kafka_producer()
    if not producer:
        # Local fallback: when Kafka is off, we run ingestion synchronously
        from clickhouse_client import insert_logs_batch
        from detection import check_for_abuse
        logger.info("[KAFKA FALLBACK] Ingesting log synchronously.")
        # Insert to ClickHouse / local relational DB fallback
        insert_logs_batch([log_data])
        # Run detection checks
        check_for_abuse(
            source_ip=log_data.get("source_ip", "0.0.0.0"),
            user_id=log_data.get("user_id"),
            device_id=log_data.get("device_id"),
            user_agent=log_data.get("user_agent"),
            headers=log_data.get("headers")
        )
        return

    try:
        producer.send(KAFKA_TOPIC, value=log_data)
        logger.info(f"Published event to Kafka topic '{KAFKA_TOPIC}'.")
    except Exception as e:
        logger.error(f"Failed to publish event to Kafka: {e}")
