import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class FederatedMesh:
    """
    Implements Federated Defense Mesh (OBJ 18).
    Allows multiple EDYSOR-X instances (e.g., across tenants or organizations) to share 
    anonymized DPO preferences and embeddings using Federated Averaging (FedAvg).
    """
    
    def __init__(self):
        self.global_weights = {
            "credential_stuffing": 0.5,
            "prompt_injection": 0.5,
            "anomalous_login": 0.5
        }
        self.peer_updates = []
        
    def receive_anonymized_update(self, peer_id: str, local_weights: Dict[str, float]):
        """
        Receives an anonymized weight update from a peer node.
        """
        logger.info(f"[FEDERATED MESH] Received weight update from peer {peer_id}")
        self.peer_updates.append(local_weights)
        
    def execute_fedavg(self):
        """
        Executes Federated Averaging (FedAvg) across all received peer updates.
        Updates the global model weights safely without exposing raw data.
        """
        if not self.peer_updates:
            logger.info("[FEDERATED MESH] No peer updates to average.")
            return self.global_weights
            
        logger.info(f"[FEDERATED MESH] Executing FedAvg across {len(self.peer_updates)} peer nodes.")
        
        # Simple FedAvg implementation
        for key in self.global_weights.keys():
            total = sum(update.get(key, 0.5) for update in self.peer_updates)
            # Average the peer updates with our current global weight
            self.global_weights[key] = round((total + self.global_weights[key]) / (len(self.peer_updates) + 1), 3)
            
        # Clear peer updates after averaging
        self.peer_updates = []
        logger.info(f"[FEDERATED MESH] New Global Weights: {self.global_weights}")
        return self.global_weights
