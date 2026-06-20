import pytest
from unittest.mock import patch
from backend.ai_engine.triage import generate_alert_summary

@patch('backend.ai_engine.triage.call_llm')
def test_alert_summary_with_mock(mock_call_llm):
    """Test that the triage engine correctly formats the prompt and handles the LLM response."""
    
    # Mock the LLM returning a specific string
    mock_call_llm.return_value = "Confidence: 95/100 — AI Triage: Detected high-confidence Brute Force Attack."
    
    alert = generate_alert_summary(
        alert_title="Brute Force Attack",
        evidence={"attacker_ip": "1.2.3.4", "confidence_score": 95},
        related_logs=[{"id": 101, "timestamp": "2023-10-10", "event_type": "login", "source_ip": "1.2.3.4", "status": "failed"}]
    )
    
    # Assert LLM wrapper was called
    mock_call_llm.assert_called_once()
    args, kwargs = mock_call_llm.call_args
    prompt = args[0]
    
    # Check if the prompt was formulated correctly with the IP and Log ID
    assert "1.2.3.4" in prompt
    assert "[LOG-101]" in prompt
    
    # Check the final output
    assert "95/100" in alert
    assert "Brute Force Attack" in alert
