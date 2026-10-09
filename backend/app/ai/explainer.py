"""
NetSentinel Claude AI Alert Explainer Service.

Integrates with Anthropic's official Claude Messages API to provide concise,
objective advisory explanations for passively observed cybersecurity alerts.
Strictly adheres to passive network security constraints:
  - Transmits only minimal telemetry metadata (no raw PCAPs, payloads, or credentials)
  - Purely advisory: never mutates detection models, confidence, or severity
  - Gracefully handles missing API keys, rate limits, timeouts, and network faults
"""
import os
import logging
from typing import Optional

from app.ai.models import ExplainAlertRequest, ExplainAlertResponse

logger = logging.getLogger("claude_explainer")

DEFAULT_CLAUDE_MODEL = "claude-3-5-haiku-20241022"
API_TIMEOUT_SECONDS = 15.0

SYSTEM_PROMPT = """You are NetSentinel Security Analyst Assistant, an expert in unidirectional network security, hardware data diodes, and passive traffic analysis.
You explain passively observed cyber threat alerts to human SOC operators in a concise, factual, and actionable manner.

Your response must be formatted as clean Markdown with exactly these 4 sections:
### 1. Alert Overview
Briefly describe what this threat class means in an air-gapped or unidirectional perimeter context.

### 2. Evidence Analysis
Explain how the observed telemetry indicators (such as packet rates, entropy, TCP flag distributions, or domain characteristics) substantiate this classification.

### 3. False-Positive Assessment
Identify common benign administrative actions, network diagnostics, or unusual legitimate application traffic that could trigger similar telemetry patterns.

### 4. Human Analyst Recommended Actions
Provide 3 to 4 concrete, actionable triage steps for the SOC operator to manually verify the source and context without assuming active inline blocking capabilities.

Keep your explanation technical, objective, and under 350 words. Do not speculate beyond the provided evidence."""


class ClaudeAlertExplainer:
    """
    Service wrapper for Anthropic Claude Messages API.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.model = model or os.getenv("ANTHROPIC_MODEL", DEFAULT_CLAUDE_MODEL).strip() or DEFAULT_CLAUDE_MODEL

    def _build_user_prompt(self, req: ExplainAlertRequest) -> str:
        evidence_formatted = "\n".join([f"- {ev}" for ev in req.supporting_evidence]) if req.supporting_evidence else "- (No specific heuristic evidence strings attached)"
        
        return f"""Please provide an advisory analysis for the following passively observed security alert:

• Alert ID: {req.alert_id or 'N/A'}
• Threat Category: {req.threat_class}
• Confidence Score: {req.confidence_score * 100:.1f}%
• Severity Level: {req.severity}
• Primary Detection Rationale: {req.primary_reason or 'None provided'}
• Observed Evidence:
{evidence_formatted}
"""

    def explain_alert(self, req: ExplainAlertRequest) -> ExplainAlertResponse:
        """
        Generates an advisory explanation for a security alert using Anthropic Claude API.
        """
        # 1. Graceful check for missing API key
        if not self.api_key:
            return ExplainAlertResponse(
                alert_id=req.alert_id,
                threat_class=req.threat_class,
                severity=req.severity,
                confidence_score=req.confidence_score,
                explanation=(
                    "**Anthropic API Key Not Configured**\n\n"
                    "The `ANTHROPIC_API_KEY` environment variable is not set. "
                    "To enable live Claude explanations for security alerts:\n\n"
                    "1. Obtain an API key from the [Anthropic Console](https://console.anthropic.com/).\n"
                    "2. Set the environment variable:\n"
                    "   ```bash\n"
                    "   export ANTHROPIC_API_KEY=\"sk-ant-...\"\n"
                    "   ```\n"
                    "   *(Or configure it in your `.env` file)*\n"
                    "3. Restart the NetSentinel backend or dashboard."
                ),
                status="missing_api_key",
                model_used=None,
                ai_generated=True
            )

        # 2. Invoke Anthropic Claude Messages API
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key, timeout=API_TIMEOUT_SECONDS)
            user_prompt = self._build_user_prompt(req)

            message = client.messages.create(
                model=self.model,
                max_tokens=800,
                temperature=0.2,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            # Extract text response from content blocks
            explanation_parts = []
            for block in message.content:
                if hasattr(block, "text") and block.text:
                    explanation_parts.append(block.text)

            explanation_text = "\n".join(explanation_parts).strip()
            if not explanation_text:
                explanation_text = "No explanation content was returned by the model."

            return ExplainAlertResponse(
                alert_id=req.alert_id,
                threat_class=req.threat_class,
                severity=req.severity,
                confidence_score=req.confidence_score,
                explanation=explanation_text,
                model_used=self.model,
                status="success",
                ai_generated=True
            )

        except ModuleNotFoundError:
            logger.error("The 'anthropic' package is not installed.")
            return ExplainAlertResponse(
                alert_id=req.alert_id,
                threat_class=req.threat_class,
                severity=req.severity,
                confidence_score=req.confidence_score,
                explanation="The `anthropic` Python SDK is required for Claude alert explanations. Install it via `pip install anthropic`.",
                status="error",
                model_used=self.model,
                ai_generated=True
            )
        except Exception as e:
            # Handle specific Anthropic exceptions dynamically if imported
            error_type = type(e).__name__
            logger.warning(f"Claude API exception ({error_type}): {e}")

            if "AuthenticationError" in error_type:
                return ExplainAlertResponse(
                    alert_id=req.alert_id,
                    threat_class=req.threat_class,
                    severity=req.severity,
                    confidence_score=req.confidence_score,
                    explanation="**Anthropic Authentication Failed**: The configured `ANTHROPIC_API_KEY` was rejected by Anthropic. Please verify that your API key is valid.",
                    status="auth_error",
                    model_used=self.model,
                    ai_generated=True
                )
            elif "RateLimitError" in error_type:
                return ExplainAlertResponse(
                    alert_id=req.alert_id,
                    threat_class=req.threat_class,
                    severity=req.severity,
                    confidence_score=req.confidence_score,
                    explanation="**Rate Limit Exceeded**: Anthropic API rate limit reached. Please wait a moment before requesting another explanation.",
                    status="rate_limited",
                    model_used=self.model,
                    ai_generated=True
                )
            elif "APITimeoutError" in error_type:
                return ExplainAlertResponse(
                    alert_id=req.alert_id,
                    threat_class=req.threat_class,
                    severity=req.severity,
                    confidence_score=req.confidence_score,
                    explanation="**Request Timeout**: The Claude API request timed out after 15 seconds. Please verify network connectivity and retry.",
                    status="timeout",
                    model_used=self.model,
                    ai_generated=True
                )
            elif "APIConnectionError" in error_type:
                return ExplainAlertResponse(
                    alert_id=req.alert_id,
                    threat_class=req.threat_class,
                    severity=req.severity,
                    confidence_score=req.confidence_score,
                    explanation="**Connection Error**: Unable to reach the Anthropic API servers. Check firewall/outbound internet access from this host.",
                    status="connection_error",
                    model_used=self.model,
                    ai_generated=True
                )
            else:
                return ExplainAlertResponse(
                    alert_id=req.alert_id,
                    threat_class=req.threat_class,
                    severity=req.severity,
                    confidence_score=req.confidence_score,
                    explanation=f"**API Error**: {str(e)}",
                    status="error",
                    model_used=self.model,
                    ai_generated=True
                )
