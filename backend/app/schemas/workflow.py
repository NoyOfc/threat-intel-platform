from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.ioc import IOCInput, IOCOut
from app.schemas.risk import RiskLevel
from app.services.ioc import IOCType

MAX_NOTE_LENGTH = 5000
MAX_TAG_LENGTH = 64


class RelationType(StrEnum):
    RESOLVES_TO = "resolves_to"  # domain → IP
    ASN = "asn"  # IP → ASN
    MALWARE = "malware"  # hash → malware family
    THREAT_ACTOR = "threat_actor"  # IOC → threat actor
    CAMPAIGN = "campaign"  # IOC → campaign


class WatchlistStatus(StrEnum):
    MONITORING = "monitoring"
    INVESTIGATING = "investigating"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=MAX_NOTE_LENGTH)


class NoteOut(BaseModel):
    id: int
    body: str
    created_at: datetime


class TagCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=MAX_TAG_LENGTH)


class TagOut(BaseModel):
    name: str
    origin: str = Field(description='"analyst", or the provider whose live data supplied it')


class RelationshipCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relation: RelationType
    target: str = Field(min_length=1, max_length=2048)


class RelationshipOut(BaseModel):
    id: int
    direction: Literal["outgoing", "incoming"]
    relation: RelationType
    ioc_id: int
    ioc_type: IOCType
    ioc_value: str
    target_value: str
    target_ioc_id: int | None
    label: str | None
    origin: str
    evidence: str | None
    investigation_id: str | None
    created_at: datetime
    last_observed_at: datetime


class InvestigationSummary(BaseModel):
    id: str
    created_at: datetime
    ioc_id: int
    ioc_type: IOCType
    ioc_value: str
    risk_score: int | None
    risk_level: RiskLevel
    simulated: bool
    enrichment_status: str


class InvestigationList(BaseModel):
    total: int
    items: list[InvestigationSummary]


class ThreatEventRef(BaseModel):
    id: str
    title: str
    source_name: str
    published_at: datetime | None


class WatchlistRef(BaseModel):
    id: int
    status: WatchlistStatus


class IOCContext(BaseModel):
    """Everything stored about one IOC across the analyst workflow."""

    ioc: IOCOut
    tags: list[TagOut]
    relationships: list[RelationshipOut]
    watchlist: WatchlistRef | None
    investigations: list[InvestigationSummary]
    threat_events: list[ThreatEventRef]


class WatchlistCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc: IOCInput
    status: WatchlistStatus = WatchlistStatus.MONITORING
    tags: list[str] = Field(default_factory=list, max_length=20)
    note: str | None = Field(default=None, max_length=MAX_NOTE_LENGTH)


class WatchlistUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: WatchlistStatus


class WatchlistEntryOut(BaseModel):
    id: int
    status: WatchlistStatus
    created_at: datetime
    updated_at: datetime
    ioc: IOCOut
    tags: list[TagOut]
    notes: list[NoteOut]
    latest_investigation: InvestigationSummary | None


class WatchlistList(BaseModel):
    total: int
    items: list[WatchlistEntryOut]
