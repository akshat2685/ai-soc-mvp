import logging
import numpy as np
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class BehavioralAnomalyDetector:
    """
    Hybrid AI Pipeline: Unsupervised Behavioral Baselining (Phase 3).
    Uses Isolation Forest to score user/entity activity against normal baselines.
    """
    def __init__(self):
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
            self.is_trained = False
        except ImportError:
            logger.error("[ISOLATION FOREST] scikit-learn not installed. Mocking predictions.")
            self.model = None
            self.is_trained = False

    def train_baseline(self, historical_features: List[List[float]]):
        """Trains the Isolation Forest on a matrix of historical behavior features."""
        if not historical_features:
            return
            
        if self.model:
            X = np.array(historical_features)
            self.model.fit(X)
            self.is_trained = True
            logger.info(f"[ISOLATION FOREST] Trained behavioral baseline on {len(historical_features)} events.")

    def score_event(self, features: List[float], event_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scores a single real-time event. 
        Returns an anomaly score between 0-100 (higher = more anomalous).
        """
        if not self.model or not self.is_trained:
            # Fallback to mock scoring if sklearn isn't installed or model isn't trained
            mock_score = 95.0 if event_context.get("destination_ip") == "185.15.5.5" else 5.0
            is_anomaly = mock_score > 80.0
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": mock_score,
                "model": "isolation_forest_mock"
            }

        # Predict returns -1 for outliers and 1 for inliers.
        # decision_function returns average anomaly score (lower is more abnormal).
        X = np.array([features])
        prediction = self.model.predict(X)[0]
        raw_score = self.model.decision_function(X)[0]
        
        # Normalize score to 0-100 (where 100 is highly anomalous)
        # decision_function typically ranges from -0.5 (very abnormal) to 0.5 (normal)
        normalized_score = max(0, min(100, (0.5 - raw_score) * 100))
        
        is_anomaly = prediction == -1
        
        if is_anomaly:
            logger.warning(f"[ISOLATION FOREST] Detected behavioral anomaly! Score: {normalized_score:.1f}")
            
        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": round(normalized_score, 2),
            "model": "isolation_forest"
        }
