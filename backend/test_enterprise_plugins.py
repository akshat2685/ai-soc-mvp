import sys

from plugins.base_plugin import PluginRegistry
import plugins.confidential_compute
import plugins.neuromorphic
import plugins.swarm_robotics
from security.quantum_crypto import QuantumCryptoEngine

def test_part4_enterprise_plugins():
    print("--- Testing Part 4: Enterprise Plugin Architecture ---")
    
    # 1. Test Quantum Crypto (Real or Fallback)
    print("\n[Test] Quantum-Resistant Cryptography")
    crypto_engine = QuantumCryptoEngine()
    
    kem_keys = crypto_engine.generate_kem_keypair()
    print(f"Kyber Public Key: {kem_keys['public_key'][:30]}...")
    
    encap = crypto_engine.encapsulate_secret(kem_keys['public_key'])
    print(f"Kyber Ciphertext: {encap['ciphertext'][:30]}...")
    
    decap = crypto_engine.decapsulate_secret(encap['ciphertext'], kem_keys['secret_key'])
    print(f"Decapsulated Secret matches: {decap == encap['shared_secret']}")
    assert decap == encap['shared_secret']
    
    sig = crypto_engine.sign_message("EDYSOR-X SECURE COMMS")
    print(f"Dilithium Signature: {sig['signature'][:30]}...")
    assert "EDYSOR" in sig['message']

    # 2. Test Enterprise Hardware Plugin Registry
    print("\n[Test] Enterprise Plugin Registry")
    
    amd_plugin = PluginRegistry.get_plugin("confidential_compute")
    enclave = amd_plugin.seal_memory_enclave("super_secret_context_123")
    print(f"Attested Enclave: {enclave}")
    assert "SEALED" in enclave
    
    loihi_plugin = PluginRegistry.get_plugin("neuromorphic")
    score = loihi_plugin.score_anomaly_on_snn([1.1, 2.2])
    print(f"SNN Anomaly Score: {score}")
    assert score > 0
    
    robot_plugin = PluginRegistry.get_plugin("swarm_robotics")
    success = robot_plugin.physical_isolate_server("RACK-42", "10.0.0.99")
    print(f"Robot Isolation Dispatched: {success}")
    assert success is True
    
    print("\nAll Enterprise Frameworks Verified!")

if __name__ == "__main__":
    test_part4_enterprise_plugins()
