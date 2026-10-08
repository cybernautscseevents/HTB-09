from pydantic import BaseModel, Field, model_validator
from typing import Literal

InputType = Literal["prompt", "document", "email", "web"]


class ScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=50_000)
    input_type: InputType = "prompt"
    policies: dict[str, bool] = Field(default_factory=dict)


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


class BatchScanRequest(BaseModel):
    items: list[BatchItem] = Field(min_length=1, max_length=5_000)
    policies: dict[str, bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def limit_total_content(self):
        if sum(len(item.content) for item in self.items) > 5_000_000:
            raise ValueError("Batch content exceeds the 5,000,000 character limit")
        return self


class ChatRequest(BaseModel):
    content: str = Field(min_length=1, max_length=50_000)
    input_type: InputType = "prompt"
    policies: dict[str, bool] = Field(default_factory=dict)
