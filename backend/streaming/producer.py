import json
import logging
from typing import Dict, Any, Optional
from aiokafka import AIOKafkaProducer

logger = logging.getLogger(__name__)

class KafkaEventProducer:
    """
    High-performance asynchronous Kafka Producer.
    Fire-and-forget raw telemetry publishing to decouple API from AI analysis.
    """
    
    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self.producer: Optional[AIOKafkaProducer] = None
        
    async def start(self):
        """Initialize and start the producer."""
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                # Acks=1 is a good balance between throughput and durability for SOC telemetry
                acks=1
            )
            await self.producer.start()
            logger.info(f"Kafka Producer connected to {self.bootstrap_servers}")
        except Exception as e:
            logger.error(f"Failed to start Kafka Producer: {e}")
            self.producer = None
            
    async def stop(self):
        """Stop the producer and flush buffers."""
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka Producer stopped gracefully")
            
    async def publish(self, topic: str, event: Dict[str, Any]):
        """Publish an event asynchronously."""
        if not self.producer:
            # Fallback for local testing if Kafka isn't running
            logger.debug(f"[MOCK KAFKA] Published to {topic}: {event.get('event_type')}")
            return
            
        try:
            # Send without waiting for acknowledgement (high throughput)
            await self.producer.send_and_wait(topic, event)
        except Exception as e:
            logger.error(f"Failed to publish to Kafka topic {topic}: {e}")

# Global instance
import os
event_producer = KafkaEventProducer(bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"))
