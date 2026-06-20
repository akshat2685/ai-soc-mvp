import logging
import json
import os
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class CloudDataLake:
    """
    Unified Security Training Corpus pipeline (Phase 3).
    Dumps Labeled Incidents, Synthetic Attacks, and Threat Intel into GCP Cloud Storage.
    Formats data as JSONL (convertible to Parquet) for Mistral-7B / PyTorch training.
    """
    def __init__(self, bucket_name: str = "edysor-x-training-corpus"):
        self.bucket_name = bucket_name
        self.use_mock = os.getenv("MOCK_GCP", "true").lower() == "true"
        
        if not self.use_mock:
            try:
                from google.cloud import storage
                self.client = storage.Client()
                self.bucket = self.client.bucket(self.bucket_name)
            except ImportError:
                logger.error("[DATA LAKE] google-cloud-storage not installed. Falling back to mock.")
                self.use_mock = True

    def export_training_batch(self, batch_data: List[Dict[str, Any]], data_type: str) -> str:
        """
        Exports a batch of training data (e.g., 'labeled_incidents' or 'synthetic_attacks').
        Partitioned by date in the bucket: gs://bucket/data_type/YYYY-MM-DD/batch_id.jsonl
        """
        if not batch_data:
            return "No data to export."

        date_str = datetime.now().strftime("%Y-%m-%d")
        timestamp = datetime.now().strftime("%H%M%S")
        blob_name = f"{data_type}/{date_str}/batch_{timestamp}.jsonl"

        # Convert to JSONL string
        jsonl_content = "\n".join([json.dumps(record) for record in batch_data])

        if self.use_mock:
            logger.info(f"[DATA LAKE MOCK] Simulated upload of {len(batch_data)} records to gs://{self.bucket_name}/{blob_name}")
            return f"gs://{self.bucket_name}/{blob_name}"

        # Actual GCP Upload
        try:
            blob = self.bucket.blob(blob_name)
            blob.upload_from_string(jsonl_content, content_type="application/jsonl")
            logger.info(f"[DATA LAKE] Successfully uploaded {len(batch_data)} records to gs://{self.bucket_name}/{blob_name}")
            return f"gs://{self.bucket_name}/{blob_name}"
        except Exception as e:
            logger.error(f"[DATA LAKE] GCP Upload failed: {e}")
            raise
