import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add backend directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.telemetry import record_latency, record_tokens, record_error, record_hallucination, trace_and_time
from backend.alerts.notifier import send_alert, check_metrics_and_notify, send_slack_alert

class TestObservability(unittest.TestCase):
    
    def test_metrics_no_exception(self):
        # Verify recording metrics executes without throwing exceptions
        record_latency("test_action", 1.25)
        record_tokens("gemini-3.5-flash", 100, 50)
        record_error("test_component")
        record_hallucination("gemini-3.5-flash", 0.05)
        
    def test_trace_and_time_context_manager(self):
        # Verify the custom trace_and_time context manager runs successfully
        with trace_and_time("test_component", "test_operation") as span:
            span.set_attribute("test_attr", "test_value")
            
    @patch('requests.post')
    def test_slack_alert_sending(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        # Patch environment variable for Slack
        with patch.dict(os.environ, {"ALERT_SLACK_WEBHOOK": "http://mock-webhook"}):
            import backend.alerts.notifier as notifier
            # Re-read webhook to ensure it is mocked
            notifier.SLACK_WEBHOOK_URL = "http://mock-webhook"
            res = notifier.send_slack_alert("Test Subject", "Test Message", "CRITICAL")
            
            self.assertTrue(res)
            mock_post.assert_called_once()
            
    @patch('backend.alerts.notifier.send_alert')
    def test_threshold_check(self, mock_send_alert):
        # Trigger critical error rate alert
        check_metrics_and_notify("test_api", error_count=15, latency_avg=0.5)
        mock_send_alert.assert_called_with(
            "High Error Rate Detected in test_api",
            "Component 'test_api' has registered 15 errors in the current window. This exceeds the threshold of 10.",
            level="CRITICAL"
        )
        
        # Trigger warning latency alert
        mock_send_alert.reset_mock()
        check_metrics_and_notify("test_api", error_count=1, latency_avg=5.5)
        mock_send_alert.assert_called_with(
            "Latency Spike Detected in test_api",
            "Component 'test_api' average latency has reached 5.50s, exceeding the limit of 3.0s.",
            level="WARNING"
        )

if __name__ == "__main__":
    unittest.main()
