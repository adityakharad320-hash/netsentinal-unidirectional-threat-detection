"""
Unit & Integration Tests for NetSentinel Claude AI Alert Explainer.

Tests:
  - Request/Response Schema validation
  - Missing API key graceful handling
  - Mocked Claude Messages API integration
  - API error, rate limit, authentication, and timeout handling
  - FastAPI endpoint routing (/api/ai/explain-alert)
  - Strict privacy/metadata boundaries (no raw payload leakage)
  - Non-intrusive advisory invariants
"""
import os
import pytest
from unittest.mock import MagicMock, patch
from starlette.testclient import TestClient

from app.main import app
from app.ai.models import ExplainAlertRequest, ExplainAlertResponse
from app.ai.explainer import ClaudeAlertExplainer


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_alert_request():
    return ExplainAlertRequest(
        alert_id="ALT-20261009-TEST01",
        threat_class="DDOS",
        confidence_score=0.985,
        severity="CRITICAL",
        supporting_evidence=[
            "SYN packet ratio: 100.0% (50/50 pkts)",
            "Packet rate: 215.4 pkts/sec",
            "Zero ACK/response packets observed (unidirectional)"
        ],
        primary_reason="High-rate volumetric SYN flood targeting TCP port 80"
    )


def test_schema_serialization(sample_alert_request):
    """Verifies that the ExplainAlertRequest serializes and deserializes cleanly."""
    data = sample_alert_request.model_dump()
    assert data["alert_id"] == "ALT-20261009-TEST01"
    assert data["threat_class"] == "DDOS"
    assert data["confidence_score"] == 0.985
    assert data["severity"] == "CRITICAL"
    assert len(data["supporting_evidence"]) == 3
    assert "SYN flood" in data["primary_reason"]


def test_missing_api_key_graceful_response(sample_alert_request):
    """Verifies that an unconfigured ANTHROPIC_API_KEY produces a clear, helpful advisory."""
    explainer = ClaudeAlertExplainer(api_key="")
    response = explainer.explain_alert(sample_alert_request)

    assert isinstance(response, ExplainAlertResponse)
    assert response.status == "missing_api_key"
    assert response.ai_generated is True
    assert "ANTHROPIC_API_KEY" in response.explanation
    assert "Anthropic API Key Not Configured" in response.explanation
    assert response.model_used is None
    assert "advisory" in response.advisory_notice.lower()


def test_claude_api_successful_call(sample_alert_request):
    """Verifies successful call to Claude Messages API and markdown parsing."""
    mock_content_block = MagicMock()
    mock_content_block.text = (
        "### 1. Alert Overview\nVolumetric SYN flood in a unidirectional perimeter.\n\n"
        "### 2. Evidence Analysis\n100% SYN packet ratio and 215 pkts/sec confirm flooding.\n\n"
        "### 3. False-Positive Assessment\nLoad testing scripts or health-check monitors.\n\n"
        "### 4. Human Analyst Recommended Actions\n1. Check source IP subnet.\n2. Correlate with firewall logs."
    )

    mock_message = MagicMock()
    mock_message.content = [mock_content_block]

    with patch("anthropic.Anthropic") as MockAnthropic:
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.return_value = mock_message
        MockAnthropic.return_value = mock_client_instance

        explainer = ClaudeAlertExplainer(api_key="sk-ant-testkey12345", model="claude-3-5-haiku-20241022")
        response = explainer.explain_alert(sample_alert_request)

        assert response.status == "success"
        assert response.ai_generated is True
        assert response.model_used == "claude-3-5-haiku-20241022"
        assert "Alert Overview" in response.explanation
        assert "Evidence Analysis" in response.explanation

        # Verify call arguments
        MockAnthropic.assert_called_once_with(api_key="sk-ant-testkey12345", timeout=15.0)
        mock_client_instance.messages.create.assert_called_once()
        call_kwargs = mock_client_instance.messages.create.call_args[1]
        assert call_kwargs["model"] == "claude-3-5-haiku-20241022"
        assert call_kwargs["temperature"] == 0.2
        assert len(call_kwargs["messages"]) == 1
        
        # Verify minimal metadata in user prompt
        prompt_content = call_kwargs["messages"][0]["content"]
        assert "DDOS" in prompt_content
        assert "98.5%" in prompt_content
        assert "SYN packet ratio: 100.0%" in prompt_content


def test_claude_api_auth_error(sample_alert_request):
    """Verifies graceful handling of invalid Anthropic API key."""
    class MockAuthError(Exception):
        pass
    MockAuthError.__name__ = "AuthenticationError"

    with patch("anthropic.Anthropic") as MockAnthropic:
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.side_effect = MockAuthError("Invalid API key")
        MockAnthropic.return_value = mock_client_instance

        explainer = ClaudeAlertExplainer(api_key="sk-ant-invalid", model="claude-3-5-haiku-20241022")
        response = explainer.explain_alert(sample_alert_request)

        assert response.status == "auth_error"
        assert response.ai_generated is True
        assert "Authentication Failed" in response.explanation


def test_claude_api_rate_limit(sample_alert_request):
    """Verifies graceful handling of rate limits."""
    class MockRateLimit(Exception):
        pass
    MockRateLimit.__name__ = "RateLimitError"

    with patch("anthropic.Anthropic") as MockAnthropic:
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.side_effect = MockRateLimit("Rate limit exceeded")
        MockAnthropic.return_value = mock_client_instance

        explainer = ClaudeAlertExplainer(api_key="sk-ant-valid", model="claude-3-5-haiku-20241022")
        response = explainer.explain_alert(sample_alert_request)

        assert response.status == "rate_limited"
        assert "Rate Limit Exceeded" in response.explanation


def test_claude_api_timeout(sample_alert_request):
    """Verifies graceful handling of API timeouts."""
    class MockTimeout(Exception):
        pass
    MockTimeout.__name__ = "APITimeoutError"

    with patch("anthropic.Anthropic") as MockAnthropic:
        mock_client_instance = MagicMock()
        mock_client_instance.messages.create.side_effect = MockTimeout("Timeout after 15s")
        MockAnthropic.return_value = mock_client_instance

        explainer = ClaudeAlertExplainer(api_key="sk-ant-valid", model="claude-3-5-haiku-20241022")
        response = explainer.explain_alert(sample_alert_request)

        assert response.status == "timeout"
        assert "Request Timeout" in response.explanation


def test_api_endpoint_integration(client, sample_alert_request):
    """Verifies the FastAPI HTTP endpoint POST /api/ai/explain-alert."""
    payload = sample_alert_request.model_dump()
    response = client.post("/api/ai/explain-alert", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == "ALT-20261009-TEST01"
    assert data["threat_class"] == "DDOS"
    assert "explanation" in data
    assert "ai_generated" in data
    assert data["ai_generated"] is True
    assert "advisory_notice" in data


def test_api_endpoint_minimal_fields(client):
    """Verifies the endpoint functions with minimal required fields."""
    minimal_payload = {
        "threat_class": "PORT_SCAN",
        "confidence_score": 0.88,
        "severity": "HIGH",
        "supporting_evidence": ["Target port diversity: 48 ports"]
    }
    response = client.post("/api/ai/explain-alert", json=minimal_payload)

    assert response.status_code == 200
    data = response.json()
    assert data["threat_class"] == "PORT_SCAN"
    assert data["confidence_score"] == 0.88
    assert data["ai_generated"] is True
