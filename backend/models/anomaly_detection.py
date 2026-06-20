import logging
import numpy as np
from typing import List, Dict, Any
import os
import joblib

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    IsolationForest = None
    StandardScaler = None

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Unsupervised Machine Learning for Zero-Day Threat Detection.
    Uses an Isolation Forest to flag behavior that statistically deviates from normal patterns.
    """
    
    def __init__(self, model_path: str = "isolation_forest.joblib"):
        self.model_path = os.path.join(os.path.dirname(__file__), "..", "data", model_path)
        self.scaler = None
        self.model = None
        self._load_model()

    def _load_model(self):
        if not IsolationForest:
            logger.warning("scikit-learn not installed. AnomalyDetector disabled.")
            return
            
        if os.path.exists(self.model_path):
            try:
                state = joblib.load(self.model_path)
                self.model = state["model"]
                self.scaler = state["scaler"]
                logger.info(f"Loaded existing IsolationForest from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
        else:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.01,  # Expecting 1% of traffic to be genuinely anomalous zero-days
                random_state=42
            )
            self.scaler = StandardScaler()
            logger.info("Initialized new, untrained IsolationForest.")

    def _extract_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """Extract mathematical features from raw JSON logs."""
        features = []
        for log in logs:
            # Simple heuristic feature extraction
            failed_attempts = int(log.get("failed_attempts", 0))
            is_new_device = 1 if log.get("device_fingerprint") else 0
            geo_distance = float(log.get("geo_distance_km", 0.0))
            
            # Time of day anomaly (business hours vs 3 AM)
            # Assuming timestamp is ISO8601
            unusual_hours = 0
            try:
                if "timestamp" in log:
                    from datetime import datetime
                    # Parse basic ISO 8601
                    dt = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
                    if dt.hour < 6 or dt.hour > 20:
                        unusual_hours = 1
            except Exception:
                pass
                
            features.append([failed_attempts, is_new_device, geo_distance, unusual_hours])
            
        return np.array(features)

    def train(self, normal_logs: List[Dict[str, Any]]):
        """Train the Isolation Forest on a baseline of 'normal' traffic."""
        if not self.model or not normal_logs:
            return
            
        logger.info(f"Training IsolationForest on {len(normal_logs)} baseline events...")
        X = self._extract_features(normal_logs)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        
        # Save state
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.model_path)
        logger.info("Model trained and saved successfully.")

    def detect(self, logs: List[Dict[str, Any]]) -> List[bool]:
        """
        Returns True for Anomalous, False for Normal.
        """
        if not self.model or not hasattr(self.model, "estimators_") or len(self.model.estimators_) == 0:
            logger.warning("IsolationForest not trained yet. Defaulting to False.")
            return [False] * len(logs)
            
        X = self._extract_features(logs)
        X_scaled = self.scaler.transform(X)
        
        # IsolationForest returns -1 for anomaly, 1 for normal
        predictions = self.model.predict(X_scaled)
        return [True if p == -1 else False for p in predictions]
