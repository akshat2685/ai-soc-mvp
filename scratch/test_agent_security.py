import os
import sys
import unittest

# Add backend directory to sys.path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from security.agent_identity import sign_agent_message, verify_agent_signature, get_spiffe_id
from security.policy_engine import OPAPolicyEngine
from security.trust_manager import AgentTrustManager
from security.tool_permissions import AgentToolPermissions
from observability.tracing import start_agent_span
from observability.metrics import get_observability_metrics, record_token_cost
from observability.token_usage import calculate_llm_cost
from observability.agent_profiler import AgentPerformanceProfiler

class TestAgentSecurityAndObservability(unittest.TestCase):
    def test_agent_identity_signing(self):
        """Verify RSA signing and signature verification."""
        msg = "Log record telemetry"
        sig = sign_agent_message("threat_hunter", msg)
        self.assertIsNotNone(sig)
        self.assertTrue(verify_agent_signature("threat_hunter", msg, sig))
        
        # Verify SPIFFE formatting
        spiffe = get_spiffe_id("threat_hunter", "tenantA")
        self.assertEqual(spiffe, "spiffe://edysor.mesh/ns/soc/tenant/tenantA/agent/threat_hunter")

    def test_opa_policy_engine(self):
        """Verify context risk-limits and tenant OPA evaluations."""
        # 1. Success case
        ctx = {"tenant_id": "tenant1", "risk_score": 0.3}
        allowed, reason = OPAPolicyEngine.evaluate_authorization("threat_hunter", "read_logs", ctx)
        self.assertTrue(allowed)

        # 2. Risk score too high
        ctx_high = {"tenant_id": "tenant1", "risk_score": 0.95}
        allowed_high, reason_high = OPAPolicyEngine.evaluate_authorization("threat_hunter", "read_logs", ctx_high)
        self.assertFalse(allowed_high)
        self.assertIn("risk score", reason_high)

        # 3. Action not allowed
        allowed_bad, reason_bad = OPAPolicyEngine.evaluate_authorization("threat_hunter", "execute_containment", ctx)
        self.assertFalse(allowed_bad)

        # 4. Tenant boundary breach
        ctx_breach = {"tenant_id": "tenant1", "resource_tenant_id": "tenant2"}
        allowed_br, reason_br = OPAPolicyEngine.evaluate_authorization("threat_hunter", "read_logs", ctx_breach)
        self.assertFalse(allowed_br)
        self.assertIn("Tenant Boundary Breach", reason_br)

    def test_trust_manager_penalize(self):
        """Verify trust penalty degradation."""
        self.assertEqual(AgentTrustManager.get_trust_score("knowledge"), 1.0)
        AgentTrustManager.penalize_trust("knowledge", 0.6)
        self.assertEqual(AgentTrustManager.get_trust_score("knowledge"), 0.4)

    def test_tool_permissions(self):
        """Verify least privilege tool boundaries."""
        self.assertTrue(AgentToolPermissions.is_tool_authorized("threat_hunter", "clickhouse_logs"))
        self.assertFalse(AgentToolPermissions.is_tool_authorized("threat_hunter", "playbooks_run"))

    def test_observability_metrics_and_spans(self):
        """Verify OTEL spans, metric logging, and token cost estimators."""
        # Trace span exit check
        with start_agent_span("threat_hunter", "Test task description") as span:
            self.assertEqual(span.agent_name, "threat_hunter")
            
        # Cost check
        cost = calculate_llm_cost("Hello world prompt", "Response completes")
        self.assertGreater(cost, 0.0)
        record_token_cost("threat_hunter", cost)
        
        metrics = get_observability_metrics()
        self.assertIn("threat_hunter", metrics["agent_durations"])
        self.assertIn("threat_hunter", metrics["agent_token_costs"])

        # Profiler checks
        AgentPerformanceProfiler.record_invocation("threat_hunter")
        profiles = AgentPerformanceProfiler.get_all_profiles()
        self.assertGreater(profiles["threat_hunter"]["invocations"], 0)

if __name__ == "__main__":
    unittest.main()
