import os
import time
import base64
import logging
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger(__name__)

# Cache of agent keypairs to simulate persistent SPIFFE identity
_agent_keys = {}

def get_agent_keypair(agent_name: str) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates or retrieves short-lived RSA keypair for an agent SPIFFE identity."""
    global _agent_keys
    if agent_name in _agent_keys:
        return _agent_keys[agent_name]
        
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    _agent_keys[agent_name] = (private_key, public_key)
    return private_key, public_key

def sign_agent_message(agent_name: str, message: str) -> str:
    """Signs an agent message using its SPIFFE identity private key."""
    private_key, _ = get_agent_keypair(agent_name)
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_agent_signature(agent_name: str, message: str, signature_b64: str) -> bool:
    """Verifies the signature of a peer agent node message."""
    try:
        _, public_key = get_agent_keypair(agent_name)
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"[Zero-Trust Identity] Signature verification failed for agent '{agent_name}': {e}")
        return False

def get_spiffe_id(agent_name: str, tenant_id: str = "default") -> str:
    """Formats standard SPIFFE identity URI for an agent node."""
    return f"spiffe://edysor.mesh/ns/soc/tenant/{tenant_id}/agent/{agent_name}"
