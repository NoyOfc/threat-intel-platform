from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"  # no provider returned intelligence; not the same as "safe"


class RiskFactor(BaseModel):
    signal: str
    points: int
    detail: str
    providers: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    score: int | None = Field(ge=0, le=100)
    level: RiskLevel
    summary: str
    factors: list[RiskFactor]
    providers_considered: int
    providers_flagged: int
    simulated: bool
