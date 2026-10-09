"""
Data models and schemas for NetSentinel AI Advisory Explainer.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ExplainAlertRequest(BaseModel):
    """
    Minimal factual metadata required to generate an advisory alert explanation.
    Strictly excludes raw packet payloads, PCAPs, and sensitive internal credentials.
    """
    alert_id: Optional[str] = Field(default=None, description="Alert identifier reference e.g. ALT-20260828-XXXX")
    threat_class: str = Field(..., description="Threat category e.g. DDOS, PORT_SCAN, DGA_DNS_TUNNELLING, C2_BEACONING, DATA_EXFILTRATION, ENCRYPTED_MALWARE, UNKNOWN_ANOMALY, BENIGN")
    confidence_score: float = Field(..., description="Normalized confidence score [0.0 - 1.0]")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    supporting_evidence: List[str] = Field(default_factory=list, description="Factual evidence strings derived from telemetry")
    primary_reason: Optional[str] = Field(default=None, description="Summary detection rationale")


class ExplainAlertResponse(BaseModel):
    """
    Structured AI advisory response for SOC analysts.
    """
    alert_id: Optional[str] = Field(default=None, description="Associated alert reference ID")
    threat_class: str = Field(..., description="Analyzed threat category")
    severity: str = Field(..., description="Observed severity level")
    confidence_score: float = Field(..., description="Observed confidence score")
    explanation: str = Field(..., description="Structured markdown explanation for human operators")
    model_used: Optional[str] = Field(default=None, description="Claude model identifier or null if offline")
    status: str = Field(default="success", description="Status code: 'success', 'missing_api_key', 'auth_error', 'rate_limited', 'timeout', 'error'")
    ai_generated: bool = Field(default=True, description="Strictly true: designates output as AI-generated")
    advisory_notice: str = Field(
        default="AI-generated advisory interpretation. This advisory does not modify detection results, severity, or trigger automated network actions.",
        description="Statutory advisory disclosure"
    )
