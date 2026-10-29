from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.ioc import IOC, Tag
from app.models.workflow import AnalystNote

# ThreatEventEntity.kind values, mapped from ThreatEventData list fields.
ENTITY_FIELDS = {
    "threat_actors": "threat_actor",
    "malware_families": "malware",
    "campaigns": "campaign",
    "attack_techniques": "technique",
    "affected_products": "product",
    "industries": "industry",
    "countries": "country",
}


class ThreatSource(Base):
    """A feed source: descriptive fields synced from code, plus fetch bookkeeping."""

    __tablename__ = "threat_sources"

    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(100))
    endpoint: Mapped[str] = mapped_column(String(500))
    category: Mapped[str] = mapped_column(String(40))
    etag: Mapped[str | None] = mapped_column(String(300))
    last_modified: Mapped[str | None] = mapped_column(String(100))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(20))
    last_error: Mapped[str | None] = mapped_column(String(300))
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ThreatEvent(Base):
    """A collected report. Child rows hold its CVEs, IOCs, tags, and other entities."""

    __tablename__ = "threat_events"
    __table_args__ = (UniqueConstraint("source", "external_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(ForeignKey("threat_sources.name"), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str | None] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str | None] = mapped_column(String(20), index=True)
    severity_basis: Mapped[str | None] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(40), index=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, index=True)
    kev: Mapped[dict[str, Any] | None] = mapped_column(JSON)  # CISA KEV fields as published
    fingerprint: Mapped[str] = mapped_column(String(64))

    cves: Mapped[list[ThreatEventCVE]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    entities: Mapped[list[ThreatEventEntity]] = relationship(
        cascade="all, delete-orphan", lazy="selectin"
    )
    tag_links: Mapped[list[ThreatEventTag]] = relationship(
        cascade="all, delete-orphan", lazy="selectin"
    )
    ioc_links: Mapped[list[ThreatEventIOC]] = relationship(
        cascade="all, delete-orphan", lazy="selectin"
    )
    analyst_status: Mapped[ThreatAnalystStatus | None] = relationship(
        cascade="all, delete-orphan", lazy="selectin"
    )
    notes: Mapped[list[AnalystNote]] = relationship(
        cascade="all, delete-orphan", order_by="AnalystNote.created_at", lazy="selectin"
    )


class ThreatEventCVE(Base):
    __tablename__ = "threat_event_cves"

    event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), primary_key=True
    )
    cve: Mapped[str] = mapped_column(String(20), primary_key=True, index=True)


class ThreatEventEntity(Base):
    """Actors, malware, campaigns, ATT&CK techniques, products, industries, countries."""

    __tablename__ = "threat_event_entities"
    __table_args__ = (Index("ix_threat_event_entities_kind_value", "kind", "value"),)

    event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(String(20), primary_key=True)
    value: Mapped[str] = mapped_column(String(200), primary_key=True)
    position: Mapped[int] = mapped_column(default=0)


class ThreatEventTag(Base):
    __tablename__ = "threat_event_tags"

    event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
    position: Mapped[int] = mapped_column(default=0)

    tag: Mapped[Tag] = relationship(lazy="joined")


class ThreatEventIOC(Base):
    """An IOC the report explicitly provides, linked to the shared IOC table."""

    __tablename__ = "threat_event_iocs"

    event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), primary_key=True
    )
    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    position: Mapped[int] = mapped_column(default=0)

    ioc: Mapped[IOC] = relationship(lazy="joined")


class ThreatEventRelationship(Base):
    """Two events sharing a literal CVE, actor, malware family, technique, or campaign.

    Stored once per pair with event_id < related_event_id; query both columns.
    """

    __tablename__ = "threat_event_relationships"
    __table_args__ = (
        UniqueConstraint(
            "event_id",
            "related_event_id",
            "basis",
            "value",
            name="uq_threat_event_relationships_pair",
        ),
        CheckConstraint("event_id < related_event_id", name="ordered_pair"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), index=True
    )
    related_event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), index=True
    )
    basis: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(String(200))


class ThreatAnalystStatus(Base):
    """Kept apart from ThreatEvent so re-collection can never overwrite analyst state."""

    __tablename__ = "threat_analyst_statuses"

    event_id: Mapped[str] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(20), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
