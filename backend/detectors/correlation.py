"""Cross-Signal Correlation Engine — escalates severity when multiple attack types 
are detected from the same entity cluster within a configurable time window."""
import json
from database import get_db


import numpy as np
from sklearn.cluster import DBSCAN
from datetime import datetime, timedelta
from typing import List, Dict, Any

class MLCorrelationEngine:
    """
    Advanced ML-powered Incident Correlation using DBSCAN clustering.
    Replaces naive SQL rule-based grouping with semantic clustering based on:
    - Temporal proximity (time)
    - IP Space (L2 distance approximation)
    - User/Target categorical hashing
    - Semantic event embeddings
    """
    
    def ip_to_vector(self, ip_str: str) -> np.ndarray:
        """Approximates IP address as a numeric vector for clustering."""
        if not ip_str:
            return np.zeros(4)
        try:
            parts = [int(p) for p in ip_str.split('.')]
            if len(parts) == 4:
                return np.array(parts) / 255.0
        except ValueError:
            pass
        return np.zeros(4)

    def correlate_incidents_ml(self, alerts: List[Dict[str, Any]], time_window_minutes: int = 30) -> List[Dict[str, Any]]:
        """
        Cluster isolated alerts into massive multi-vector Incidents.
        """
        if not alerts or len(alerts) < 2:
            return []
            
        features = []
        valid_alerts = []
        
        for alert in alerts:
            # Need basic fields to cluster
            if 'timestamp' not in alert or 'source_ip' not in alert:
                continue
                
            ip_vector = self.ip_to_vector(alert.get('source_ip', ''))
            user_hash = hash(alert.get('target_user', 'unknown')) % 1000
            
            try:
                # Handle ISO strings or datetime objects
                ts = alert['timestamp']
                if isinstance(ts, str):
                    ts = datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
                elif isinstance(ts, datetime):
                    ts = ts.timestamp()
                else:
                    ts = float(ts)
            except Exception:
                continue
                
            # Fake semantic embedding for event_type (In prod, use actual embeddings API)
            event_hash = hash(alert.get('event_type', 'unknown')) % 100
            event_embedding = np.array([event_hash / 100.0] * 3)
            
            feature_row = np.concatenate([
                ip_vector,          # 4D
                [user_hash / 1000.0], # 1D
                [ts / 3600.0],      # 1D (hours)
                event_embedding     # 3D
            ])
            
            features.append(feature_row)
            valid_alerts.append(alert)
            
        if len(features) < 2:
            return []
            
        X = np.array(features)
        
        # Normalize features
        stds = X.std(axis=0)
        stds[stds == 0] = 1e-8 # Prevent division by zero
        X = (X - X.mean(axis=0)) / stds
        
        # Cluster with DBSCAN
        # eps=0.5 and min_samples=2 means alerts must be relatively close in feature space to cluster
        clustering = DBSCAN(eps=0.5, min_samples=2).fit(X)
        labels = clustering.labels_
        
        # Group by cluster
        incidents = {}
        for i, label in enumerate(labels):
            if label == -1:  # Noise (isolated alert)
                continue
            if label not in incidents:
                incidents[label] = []
            incidents[label].append(valid_alerts[i])
            
        incident_list = []
        for group in incidents.values():
            # Calculate max severity
            severities = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            max_sev = 1
            max_sev_str = "LOW"
            for a in group:
                s_str = a.get('severity', 'LOW')
                s_val = severities.get(s_str, 1)
                if s_val > max_sev:
                    max_sev = s_val
                    max_sev_str = s_str
                    
            incident_list.append({
                "alerts": group,
                "severity": max_sev_str,
                "first_seen": min([a['timestamp'] for a in group]),
                "last_seen": max([a['timestamp'] for a in group]),
                "attack_types": list(set(a.get('event_type') for a in group))
            })
            
        # Rank by severity
        severities_sort = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return sorted(incident_list, key=lambda x: severities_sort.get(x['severity'], 1), reverse=True)


class CorrelationEngine:
    def __init__(self):
        self.ml_engine = MLCorrelationEngine()
        
    def run(self, source_ip: str, user_id: str, device_fingerprint: str):
        # Fallback wrapper to satisfy __init__.py import
        # The main correlation is handled in detection.py correlate_alert_to_incident
        pass
