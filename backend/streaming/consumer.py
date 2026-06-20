import json
import logging
import asyncio
from typing import Optional
from aiokafka import AIOKafkaConsumer

logger = logging.getLogger(__name__)

class KafkaEventConsumer:
    """
    High-performance asynchronous Kafka Consumer.
    Pulls raw telemetry off the wire, executes AI models, and pushes to alerts.
    """
    
    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self.consumer: Optional[AIOKafkaConsumer] = None
        self._running = False
        self._task = None
        
    async def start(self):
        """Initialize and start consuming."""
        try:
            self.consumer = AIOKafkaConsumer(
                'raw-telemetry',
                bootstrap_servers=self.bootstrap_servers,
                group_id="soc-ai-detection-group",
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset="earliest"
            )
            await self.consumer.start()
            self._running = True
            self._task = asyncio.create_task(self._consume_loop())
            logger.info(f"Kafka Consumer connected to {self.bootstrap_servers}")
        except Exception as e:
            logger.error(f"Failed to start Kafka Consumer: {e}")
            self.consumer = None
            
    async def stop(self):
        """Stop consuming."""
        self._running = False
        if self._task:
            self._task.cancel()
        if self.consumer:
            await self.consumer.stop()
            logger.info("Kafka Consumer stopped gracefully")
            
    async def _consume_loop(self):
        """Background loop to process messages."""
        if not self.consumer:
            return
            
        try:
            async for msg in self.consumer:
                if not self._running:
                    break
                # Fire off background task so we don't block the consumer loop
                asyncio.create_task(self.process_event(msg.value))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Consumer loop crashed: {e}", exc_info=True)
            
    async def process_event(self, event: dict):
        """Pass event into the detection engine pipeline."""
        try:
            # Here we would call the ML Correlation Engine and AI Triage
            # For now, we just log it received.
            # print(f"Processing event: {event}")
            pass
        except Exception as e:
            logger.error(f"Event processing failed: {e}")

# Global instance
event_consumer = KafkaEventConsumer()
