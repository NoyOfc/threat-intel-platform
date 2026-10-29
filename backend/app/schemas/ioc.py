from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.provider import ProviderResult
from app.schemas.risk import RiskAssessment
from app.services.ioc import IOC, IOCType, NetworkScope

MAX_BULK_IOCS = 500
# Generous transport cap. The IOC engine enforces the real limit (MAX_IOC_LENGTH)
# so oversized values get a consistent "too_long" error instead of a schema error.
MAX_FIELD_LENGTH = 8192

IOCInput = Annotated[str, Field(max_length=MAX_FIELD_LENGTH)]


class IOCOut(BaseModel):
    type: IOCType
    value: str
    original: str
    refanged: bool
    network_scope: NetworkScope | None
    is_internal: bool = Field(
        description="Non-public address or hostname. Valid IOC data; ThreatScope never "
        "connects to it (or to any submitted IOC)."
    )

    @classmethod
    def from_ioc(cls, ioc: IOC) -> IOCOut:
        return cls(
            type=ioc.type,
            value=ioc.value,
            original=ioc.original,
            refanged=ioc.refanged,
            network_scope=ioc.network_scope,
            is_internal=ioc.is_internal,
        )


class InvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc: IOCInput


EnrichmentStatus = Literal["completed", "partial", "failed", "no_providers"]


class EnrichmentOut(BaseModel):
    status: EnrichmentStatus
    simulated: bool = Field(description="True if any result is DEMO_MODE sample data.")
    results: list[ProviderResult]


class InvestigationResponse(BaseModel):
    id: UUID
    created_at: datetime
    status: Literal["completed"] = "completed"
    ioc: IOCOut
    enrichment: EnrichmentOut
    risk: RiskAssessment


class BulkInvestigateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iocs: list[IOCInput] = Field(min_length=1, max_length=MAX_BULK_IOCS)


class BulkItemError(BaseModel):
    code: str
    message: str
    suspected_type: IOCType | None = None


class BulkItem(BaseModel):
    index: int
    input: str
    valid: bool
    ioc: IOCOut | None = None
    error: BulkItemError | None = None


class BulkSummary(BaseModel):
    total: int
    valid: int
    invalid: int
    by_type: dict[IOCType, int]


class BulkInvestigateResponse(BaseModel):
    items: list[BulkItem]
    summary: BulkSummary
