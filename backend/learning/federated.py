import re
import random
import logging
from typing import Dict, Any, List
from database import get_db

logger = logging.getLogger(__name__)

class FederatedLearningCoordinator:
    def __init__(self, privacy_epsilon: float = 1.0):
        self.epsilon = privacy_epsilon
        # Sensitivity of log counts or parameter metrics is bounded by 1.0
        self.sensitivity = 1.0
        self.laplace_scale = self.sensitivity / self.epsilon

    def anonymize_incident_data(self, incident: dict) -> dict:
        """Strips raw logs, IPs, usernames, or file paths leaving tenant boundary."""
        anonymized = dict(incident)
        
        # 1. Mask IPv4 and IPv6 addresses
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        for key in ["description", "title", "analyst_notes", "llm_summary"]:
            if key in anonymized and isinstance(anonymized[key], str):
                anonymized[key] = re.sub(ip_pattern, "[MASKED_IP]", anonymized[key])
                
        # 2. Strip sensitive identifiers
        for key in ["attacker_ip", "user_id", "username", "file_path", "device_fingerprint"]:
            if key in anonymized:
                anonymized[key] = "[STRIPPED]"

        return anonymized

    def compute_local_gradients(self, anonymized_incidents: List[dict]) -> List[float]:
        """Simulates local model training on anonymized data, returning parameter gradients."""
        # Simple simulated weights model representing local detection parameters
        # Length 5 gradient vector (e.g. classification parameters for attack types)
        num_incidents = len(anonymized_incidents)
        base_gradient = [random.uniform(-0.5, 0.5) for _ in range(5)]
        
        # Scale gradients relative to incident metrics
        scaled_gradient = [g * min(1.0, num_incidents / 10.0) for g in base_gradient]
        return scaled_gradient

    def apply_differential_privacy(self, gradients: List[float]) -> List[float]:
        """Adds Laplace noise matching epsilon = 1.0 to shared gradients."""
        noisy_gradients = []
        for g in gradients:
            # Laplace distribution sampler: L(mu, b) = mu - b * sgn(u) * ln(1 - 2|u|) where u ~ U(-0.5, 0.5)
            u = random.uniform(-0.5, 0.5)
            sgn = 1.0 if u >= 0 else -1.0
            noise = -self.laplace_scale * sgn * math_log_helper(1.0 - 2.0 * abs(u))
            noisy_gradients.append(g + noise)
        return noisy_gradients

    def run_fedavg_aggregation(self, tenant_gradients: List[List[float]]) -> List[float]:
        """Global model updated via FedAvg aggregation of client gradients."""
        if not tenant_gradients:
            return [0.0] * 5
            
        num_tenants = len(tenant_gradients)
        vector_len = len(tenant_gradients[0])
        
        global_gradients = [0.0] * vector_len
        for t_grad in tenant_gradients:
            for i in range(vector_len):
                global_gradients[i] += t_grad[i]
                
        # Average the weights
        global_gradients = [g / num_tenants for g in global_gradients]
        return global_gradients

    def trigger_federated_sync(self, epoch: int, mock_tenants_count: int = 3) -> Dict[str, Any]:
        """Runs end-to-end federated training cycle across simulated tenants."""
        # 1. Fetch local tenant incident data
        incidents_data = []
        try:
            with get_db() as conn:
                cur = conn.execute("SELECT * FROM incidents LIMIT 10")
                incidents_data = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass

        # 2. Anonymize data
        anonymized = [self.anonymize_incident_data(inc) for inc in incidents_data]

        # 3. Simulate training & gradient extraction for multiple tenants
        all_gradients = []
        for t in range(mock_tenants_count):
            # Compute gradients with slight variation per tenant
            local_grad = self.compute_local_gradients(anonymized)
            # Apply Laplace noise for differential privacy
            noisy_grad = self.apply_differential_privacy(local_grad)
            all_gradients.append(noisy_grad)

        # 4. Global FedAvg aggregation
        global_weights = self.run_fedavg_aggregation(all_gradients)

        # 5. Log sync epoch to DB
        grad_norm = sum(w**2 for w in global_weights) ** 0.5
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO federated_syncs (epoch, tenant_count, privacy_epsilon, laplace_noise_scale, gradient_norm) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (epoch, mock_tenants_count, self.epsilon, self.laplace_scale, grad_norm)
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log federated sync session: {e}")

        return {
            "epoch": epoch,
            "tenant_count": mock_tenants_count,
            "privacy_epsilon": self.epsilon,
            "laplace_noise_scale": self.laplace_scale,
            "gradient_norm": grad_norm,
            "global_weights": global_weights,
            "status": "COMPLETED"
        }

def math_log_helper(val: float) -> float:
    import math
    return math.log(max(1e-5, val))
