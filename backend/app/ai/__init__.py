"""
NetSentinel AI Module.
Provides Claude-powered security alert explanations for human SOC operators.
"""
from app.ai.models import ExplainAlertRequest, ExplainAlertResponse
from app.ai.explainer import ClaudeAlertExplainer

__all__ = [
    "ExplainAlertRequest",
    "ExplainAlertResponse",
    "ClaudeAlertExplainer"
]
