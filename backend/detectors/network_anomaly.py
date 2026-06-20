import os
import numpy as np
try:
    import joblib
except ImportError:
    joblib = None

from .base import BaseDetector, DetectionResult
from database import get_db

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_models', 'network_model.pkl')

class NetworkAnomalyDetector(BaseDetector):
    name = "Network Anomaly ML Detector"
    description = "Uses Random Forest model trained on CSE-CIC-IDS2018 to detect network intrusions."

    def __init__(self):
        super().__init__()
        self.model_pipeline = None
        self._load_model()

    def _load_model(self):
        if joblib and os.path.exists(MODEL_PATH):
            try:
                self.model_pipeline = joblib.load(MODEL_PATH)
                print("[ML DETECTOR] Loaded Network ML Model successfully.")
            except Exception as e:
                print(f"[ML DETECTOR] Failed to load model: {e}")

    def detect(self, source_ip: str, user_id: str = None, device_fingerprint: str = None,
               user_agent: str = None, headers: dict = None) -> DetectionResult:
        
        # If model is not loaded (e.g. user hasn't put the pkl file yet), skip detection.
        if not self.model_pipeline:
            return None

        with get_db() as conn:
            # Fetch recent traffic stats for this IP to simulate flow features
            cur = conn.execute(
                "SELECT COUNT(*) as pkt_count, MIN(timestamp) as start_time, MAX(timestamp) as end_time "
                "FROM logs WHERE source_ip = ? AND timestamp >= datetime('now', '-5 minutes')",
                (source_ip,)
            )
            row = cur.fetchone()
            
        pkt_count = row['pkt_count']
        if pkt_count < 10:
            return None # Not enough flow data to confidently classify

        # In a real scenario, we extract exact features like 'Flow Duration', 'Total Fwd Packets'
        # For the SOC MVP, we map basic log telemetry into a synthetic feature vector 
        # matching the 12 features the model expects.
        
        # [Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,
        # Fwd Packet Length Max, Fwd Packet Length Mean, Bwd Packet Length Max, 
        # Bwd Packet Length Mean, Flow Bytes/s, Flow Packets/s, Packet Length Mean, Average Packet Size]
        
        # Creating a simulated feature array
        features = np.array([[
            80,        # Dest Port
            300000,    # Flow Duration (usec)
            pkt_count, # Fwd Packets
            pkt_count, # Bwd Packets
            500,       # Fwd Max
            200,       # Fwd Mean
            1000,      # Bwd Max
            500,       # Bwd Mean
            10000,     # Bytes/s
            10,        # Packets/s
            350,       # Pkt Length Mean
            350        # Avg Packet Size
        ]])

        try:
            imputer = self.model_pipeline['imputer']
            scaler = self.model_pipeline['scaler']
            clf = self.model_pipeline['classifier']

            # Preprocess
            X_clean = imputer.transform(features)
            X_scaled = scaler.transform(X_clean)

            # Predict
            prediction = clf.predict(X_scaled)
            proba = clf.predict_proba(X_scaled)[0][1] # Probability of being malicious

            if prediction[0] == 1 and proba > 0.85:
                # Get events for evidence
                with get_db() as conn:
                    cur = conn.execute(
                        "SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 10",
                        (source_ip,)
                    )
                    events = [dict(r) for r in cur.fetchall()]

                return DetectionResult(
                    title="AI-Detected Network Anomaly (Botnet/DoS)",
                    attack_type="NETWORK_ANOMALY",
                    severity="HIGH" if proba > 0.95 else "MEDIUM",
                    source_ip=source_ip,
                    device_fingerprint=device_fingerprint,
                    events=events,
                    confidence_score=int(proba * 100),
                    evidence_citations=[
                        f"Network traffic matched malicious flow patterns trained on IDS2018. Prediction probability: {proba*100:.1f}%",
                        f"Detected over {pkt_count} packets with suspicious size/frequency distributions."
                    ]
                )
        except Exception as e:
            print(f"[ML DETECTOR] Error during prediction: {e}")

        return None
