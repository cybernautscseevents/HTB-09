from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Literal

InputType = Literal["prompt", "document", "email", "web"]
SUPPORTED_POLICY_FLAGS = frozenset({
    "prompt_injection", "indirect_injection", "jailbreak", "pii", "secrets", "sanitization",
})
MANDATORY_POLICY_FLAGS = SUPPORTED_POLICY_FLAGS


def validate_policy_settings(value):
    if not isinstance(value, dict):
        raise ValueError("Policies must be an object of supported boolean settings.")
    unknown = set(value) - SUPPORTED_POLICY_FLAGS
    if unknown:
        raise ValueError("Policies contain unsupported settings.")
    if any(type(enabled) is not bool for enabled in value.values()):
        raise ValueError("Policy settings must be booleans.")
    disabled = MANDATORY_POLICY_FLAGS.intersection(key for key, enabled in value.items() if enabled is False)
    if disabled:
        raise ValueError("Mandatory security policies cannot be disabled.")
    return value


class PolicyRequest(BaseModel):
    policies: dict[str, bool] = Field(default_factory=dict)

    @field_validator("policies", mode="before")
    @classmethod
    def enforce_policy_boundary(cls, value):
        return validate_policy_settings(value)


class ScanRequest(PolicyRequest):
    content: str = Field(min_length=1, max_length=50_000)
    input_type: InputType = "prompt"


class ScanResponse(BaseModel):
    threat_detected: bool
    threat_type: str
    risk_score: int
    severity: str
    action: str
    reasons: list[str]
    sanitized_content: str | None = None
    detections: list[str] = Field(default_factory=list)
    risk_breakdown: list[dict] = Field(default_factory=list)
    explanation: str = ""


class BatchItem(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=50_000)
    input_type: InputType = "prompt"


class BatchScanRequest(PolicyRequest):
    items: list[BatchItem] = Field(min_length=1, max_length=5_000)

    @model_validator(mode="after")
    def limit_total_content(self):
        if sum(len(item.content) for item in self.items) > 5_000_000:
            raise ValueError("Batch content exceeds the 5,000,000 character limit")
        return self


class ChatRequest(PolicyRequest):
    content: str = Field(min_length=1, max_length=50_000)
    input_type: InputType = "prompt"
