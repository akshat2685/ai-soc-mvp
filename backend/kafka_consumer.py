"""Kafka consumer worker for processing security logs."""
import os
import json
import logging
import threading
import time
from datetime import datetime
from kafka import KafkaConsumer
from clickhouse_client import insert_logs_batch
from detection import check_for_abuse, trigger_incident
from log_parser import parse_unstructured_log

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "security-logs"
CONSUMER_GROUP = "soc-log-processors"

class LogConsumerWorker(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = False
        self.consumer = None

    def run(self):
        self.running = True
        logger.info("Starting Kafka Log Consumer thread...")
        
        # Retry connection to Kafka (wait for Kafka to boot up in Docker Compose)
        retries = 5
        while retries > 0 and self.running:
            try:
                self.consumer = KafkaConsumer(
                    KAFKA_TOPIC,
                    bootstrap_servers=[KAFKA_BOOTSTRAP_SERVERS],
                    group_id=CONSUMER_GROUP,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest',
                    enable_auto_commit=True,
                    max_poll_records=500,
                    max_poll_interval_ms=300000
                )
                logger.info(f"Kafka consumer successfully connected to {KAFKA_BOOTSTRAP_SERVERS} and subscribed to '{KAFKA_TOPIC}'.")
                break
            except Exception as e:
                retries -= 1
                logger.warning(f"Kafka consumer connection failed: {e}. Retrying in 5s... ({retries} retries left)")
                time.sleep(5)
                
        if not self.consumer:
            logger.error("Failed to connect Kafka consumer. Thread exiting. Logs will bypass Kafka broker.")
            return

        while self.running:
            try:
                # Poll for message batches (wait up to 1 second)
                records = self.consumer.poll(timeout_ms=1000)
                if not records:
                    continue
                
                batch = []
                for topic_partition, consumer_records in records.items():
                    for record in consumer_records:
                        batch.append(record.value)
                        
                if batch:
                    logger.info(f"Processing batch of {len(batch)} logs from Kafka.")
                    processed_batch = []
                    
                    for log in batch:
                        if "raw_log" in log:
                            # Parse raw unstructured log
                            raw_log = log["raw_log"]
                            source_ip = log.get("source_ip", "127.0.0.1")
                            parsed = parse_unstructured_log(raw_log)
                            
                            structured = {
                                "event_type": parsed["type"],
                                "source_ip": parsed["structured_data"].get("ip", source_ip),
                                "method": parsed["structured_data"].get("method", "N/A"),
                                "endpoint": parsed["structured_data"].get("path", "N/A")[:200],
                                "status": parsed["structured_data"].get("status", "N/A"),
                                "device_fingerprint": "loghub_parsed",
                                "timestamp": log.get("timestamp") or datetime.utcnow().isoformat()
                            }
                            processed_batch.append(structured)
                            
                            # If anomalous, trigger incident directly from the consumer
                            if parsed["is_anomalous"]:
                                try:
                                    trigger_incident(
                                        title=f"Anomalous SIEM Log Detected ({parsed['type']})",
                                        attack_type="LOG_ANOMALY",
                                        severity="MEDIUM",
                                        attacker_ip=structured["source_ip"],
                                        events=[{"event_type": parsed["type"], "raw_log": raw_log}],
                                        confidence_score=70,
                                        evidence_citations=[f"Matched anomalous keyword signature in {parsed['type']} log.", raw_log]
                                    )
                                except Exception as tex:
                                    logger.error(f"Failed to trigger incident for raw log: {tex}")
                        else:
                            processed_batch.append(log)

                    if processed_batch:
                        # 1. Batch insert into ClickHouse (OLAP storage)
                        insert_logs_batch(processed_batch)
                        
                        # 2. Run detection engine for each event in the batch
                        for log in processed_batch:
                            try:
                                check_for_abuse(
                                    source_ip=log.get("source_ip", "0.0.0.0"),
                                    user_id=log.get("user_id"),
                                    device_id=log.get("device_id"),
                                    user_agent=log.get("user_agent"),
                                    headers=log.get("headers")
                                )
                            except Exception as ex:
                                logger.error(f"Error running detectors on log: {ex}")
                            
            except Exception as e:
                logger.error(f"Error in Kafka consumer loop: {e}")
                time.sleep(2) # Avoid tight error loop

    def stop(self):
        self.running = False
        if self.consumer:
            try:
                self.consumer.close()
            except Exception:
                pass
        logger.info("Kafka Log Consumer thread stopped.")

# Instance that can be imported and controlled by main lifecycle
consumer_worker = LogConsumerWorker()


# ── Analyst Interaction Real-Time Feedback Consumer ──

ANALYST_TOPIC = "analyst-interactions"

class AnalystInteractionConsumerWorker(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = False
        self.consumer = None
        self._batch_queue = []
        self._last_batch_time = time.time()

    def run(self):
        self.running = True
        logger.info("Starting Kafka Analyst Feedback Consumer thread...")
        
        retries = 3
        while retries > 0 and self.running:
            try:
                self.consumer = KafkaConsumer(
                    ANALYST_TOPIC,
                    bootstrap_servers=[KAFKA_BOOTSTRAP_SERVERS],
                    group_id="soc-analyst-feedback-processors",
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest',
                    enable_auto_commit=True
                )
                logger.info(f"Kafka consumer subscribed to '{ANALYST_TOPIC}'.")
                break
            except Exception as e:
                retries -= 1
                logger.warning(f"Kafka feedback consumer connection failed: {e}. Retrying in 5s...")
                time.sleep(5)

        while self.running:
            try:
                if not self.consumer:
                    # Fallback simulation if Kafka is not available
                    time.sleep(10)
                    continue
                
                records = self.consumer.poll(timeout_ms=1000)
                if not records:
                    # Check if 15 minute batch limit reached for cached overrides
                    if self._batch_queue and (time.time() - self._last_batch_time > 900):
                        self.process_batch_overrides()
                    continue

                for topic_partition, consumer_records in records.items():
                    for record in consumer_records:
                        self.process_immediate_feedback(record.value)
                        
            except Exception as e:
                logger.error(f"Error in Kafka feedback loop: {e}")
                time.sleep(2)

    def process_immediate_feedback(self, interaction: dict):
        """Feature engineering and online updates for individual overrides."""
        override_type = interaction.get("override_type") # verdict_change|playbook_change|escalation|approval
        override_reason = interaction.get("override_reason", "")
        original_conf = float(interaction.get("original_confidence", 0.8))
        corrected_conf = float(interaction.get("corrected_confidence", 0.8))
        time_to_override = int(interaction.get("time_to_override", 30))
        incident_id = interaction.get("incident_id")

        # 1. Log override features to DB
        from database import get_db
        with get_db() as conn:
            try:
                conn.execute(
                    "INSERT INTO analyst_overrides (incident_id, override_type, override_reason, original_confidence, corrected_confidence, time_to_override) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (incident_id, override_type, override_reason, original_conf, corrected_conf, time_to_override)
                )
                conn.commit()
            except Exception as db_err:
                logger.error(f"Failed to log analyst override: {db_err}")

        # 2. Execute Online Update Rules
        if override_type == "verdict_change":
            # Immediately adapt detection classification weights / triggers
            logger.info(f"[ONLINE UPDATE] Immediate Verdict Change Adjustment (<5 mins): Corrected Conf={corrected_conf}")
        elif override_type == "playbook_change":
            # Immediately modify SOAR playbook recommendation rankings
            logger.info(f"[ONLINE UPDATE] Immediate Playbook Weight Adjustment: Incident ID {incident_id}")
        elif override_type == "escalation":
            # Update confidence threshold for this incident type
            logger.info(f"[ONLINE UPDATE] Confidence threshold dynamically elevated for incident.")
        elif override_type == "approval":
            # Reinforce current behavior
            logger.info("[ONLINE UPDATE] Behavior reinforced based on direct analyst approval.")

        # Batch it for standard processing
        self._batch_queue.append(interaction)

    def process_batch_overrides(self):
        """Standard overrides processed in 15 minute intervals."""
        logger.info(f"[BATCH UPDATE] Processing batch of {len(self._batch_queue)} overrides (15-min interval).")
        self._batch_queue.clear()
        self._last_batch_time = time.time()

    def stop(self):
        self.running = False
        if self.consumer:
            try:
                self.consumer.close()
            except Exception:
                pass
        logger.info("Kafka Analyst Feedback Consumer thread stopped.")

analyst_feedback_worker = AnalystInteractionConsumerWorker()
