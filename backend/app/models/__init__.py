"""SQLAlchemy ORM models. Import each model here so Base.metadata sees it."""

from app.db.base import Base
from app.models.feed import (
    ThreatAnalystStatus,
    ThreatEvent,
    ThreatEventCVE,
    ThreatEventEntity,
    ThreatEventIOC,
    ThreatEventRelationship,
    ThreatEventTag,
    ThreatSource,
)
from app.models.investigation import Investigation, ProviderResult
from app.models.ioc import IOC, IOCRelationship, IOCTag, Tag
from app.models.workflow import AnalystNote, WatchlistEntry

__all__ = [
    "IOC",
    "AnalystNote",
    "Base",
    "IOCRelationship",
    "IOCTag",
    "Investigation",
    "ProviderResult",
    "Tag",
    "ThreatAnalystStatus",
    "ThreatEvent",
    "ThreatEventCVE",
    "ThreatEventEntity",
    "ThreatEventIOC",
    "ThreatEventRelationship",
    "ThreatEventTag",
    "ThreatSource",
    "WatchlistEntry",
]
