from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.services.ioc import IOCType

FeedWindow = Literal["24h", "7d", "30d"]
MAX_NOTES_LENGTH = 5000


class ThreatCategory(StrEnum):
    EXPLOITED_VULNERABILITY = "exploited_vulnerability"
    ADVISORY = "advisory"
    THREAT_RESEARCH = "threat_research"
    INCIDENT_REPORT = "incident_report"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AnalystStatus(StrEnum):
    RELEVANT = "relevant"
    MONITORING = "monitoring"
    NOT_RELEVANT = "not_relevant"


class FeedIOC(BaseModel):
    type: IOCType
    value: str


class KEVDetails(BaseModel):
    """Fields exactly as published in the CISA KEV catalog."""

    cve: str
    vendor: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: date | None = None
    required_action: str | None = None
    due_date: date | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str | None = None
    cwes: list[str] = Field(default_factory=list)


class ThreatEventData(BaseModel):
    """Normalized output of a feed adapter. Empty means "not provided", never "none"."""

    source: str
    external_id: str
    title: str
    summary: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    severity: Severity | None = None
    severity_basis: str | None = None
    category: ThreatCategory
    known_exploited: bool = False
    kev: KEVDetails | None = None
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    industries: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    iocs: list[FeedIOC] = Field(default_factory=list)


class ThreatEventOut(ThreatEventData):
    id: str
    source_name: str
    collected_at: datetime
    updated_at: datetime
    analyst_status: AnalystStatus | None = None
    analyst_notes: str | None = None
    analyst_updated_at: datetime | None = None


class RelatedEvent(BaseModel):
    id: str
    title: str
    source_name: str
    published_at: datetime | None
    shared: list[str]


class ThreatEventDetail(ThreatEventOut):
    related: list[RelatedEvent]
    kev_cves: list[str] = Field(
        description="CVEs in this event confirmed in the locally collected CISA KEV catalog."
    )


class FacetValue(BaseModel):
    value: str
    count: int


class FeedFacets(BaseModel):
    sources: list[FacetValue]
    severities: list[FacetValue]
    categories: list[FacetValue]
    threat_actors: list[FacetValue]
    malware_families: list[FacetValue]


class FeedListResponse(BaseModel):
    window: FeedWindow
    total: int
    items: list[ThreatEventOut]
    facets: FeedFacets


class AnalystUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AnalystStatus | None = None
    notes: str | None = Field(default=None, max_length=MAX_NOTES_LENGTH)


class TrendingResponse(BaseModel):
    window: FeedWindow
    scope: str
    events_considered: int
    cves: list[FacetValue]
    malware_families: list[FacetValue]
    threat_actors: list[FacetValue]
    attack_techniques: list[FacetValue]
    affected_products: list[FacetValue]


SourceRefreshStatus = Literal[
    "updated", "not_modified", "fresh", "planned", "rate_limited", "timeout", "unavailable", "error"
]


class SourceRefreshResult(BaseModel):
    source: str
    source_name: str
    status: SourceRefreshStatus
    fetched: int = 0
    new: int = 0
    updated: int = 0
    message: str | None = None


class RefreshResponse(BaseModel):
    started_at: datetime
    finished_at: datetime
    sources: list[SourceRefreshResult]


class FeedSourceOut(BaseModel):
    name: str
    display_name: str
    endpoint: str
    category: ThreatCategory
    refresh_minutes: int
    planned_reason: str | None
    event_count: int
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_status: str | None
    last_error: str | None
