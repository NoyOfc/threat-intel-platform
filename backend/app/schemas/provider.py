from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from app.services.ioc import IOCType


class ProviderStatus(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    NOT_SUPPORTED = "not_supported"
    SKIPPED = "skipped"
    NOT_CONFIGURED = "not_configured"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


# The provider answered (with or without data about the IOC).
RESPONDED_STATUSES = frozenset({ProviderStatus.OK, ProviderStatus.NOT_FOUND})
# A lookup was attempted and failed.
FAILED_STATUSES = frozenset(
    {
        ProviderStatus.RATE_LIMITED,
        ProviderStatus.AUTH_ERROR,
        ProviderStatus.TIMEOUT,
        ProviderStatus.UNAVAILABLE,
        ProviderStatus.ERROR,
    }
)


class Reputation(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


MetadataValue = str | int | float | bool | None


class ProviderResult(BaseModel):
    """One provider's answer, normalized. Only an allowlisted subset of the
    provider response is kept; full raw responses are never stored or returned."""

    provider: str
    display_name: str
    status: ProviderStatus
    simulated: bool = False
    message: str | None = None
    reputation: Reputation = Reputation.UNKNOWN
    malicious_count: int | None = None
    suspicious_count: int | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    report_count: int | None = None
    pulse_count: int | None = None
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    country: str | None = None
    asn: int | None = None
    organization: str | None = None
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    raw_metadata_safe_subset: dict[str, MetadataValue] = Field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        return self.reputation in (Reputation.MALICIOUS, Reputation.SUSPICIOUS)


class ProviderAvailability(StrEnum):
    CONFIGURED = "configured"
    NOT_CONFIGURED = "not_configured"
    UNAVAILABLE = "unavailable"


class ProviderStatusOut(BaseModel):
    name: str
    display_name: str
    status: ProviderAvailability
    mode: Literal["live", "simulated"]
    api_host: str
    api_key_env: str
    supported_types: list[IOCType]
    last_result: ProviderStatus | None
    last_checked_at: datetime | None
    detail: str


class ProvidersStatusResponse(BaseModel):
    demo_mode: bool
    providers: list[ProviderStatusOut]
