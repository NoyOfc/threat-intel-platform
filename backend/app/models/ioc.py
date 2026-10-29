from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

ANALYST_ORIGIN = "analyst"


class Tag(Base):
    """Shared tag vocabulary for IOCs and threat events. Names are normalized lowercase."""

    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)


class IOC(Base):
    """One row per normalized indicator, shared by investigations, the watchlist,
    relationships, and threat events. Network scope is recomputed from the value."""

    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(10), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    tags: Mapped[list[IOCTag]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan", lazy="selectin"
    )
    relationships: Mapped[list[IOCRelationship]] = relationship(
        foreign_keys="IOCRelationship.ioc_id", back_populates="ioc", cascade="all, delete-orphan"
    )


class IOCTag(Base):
    """IOC → Tag. `origin` is "analyst" or the provider whose live data supplied the tag."""

    __tablename__ = "ioc_tags"

    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)
    origin: Mapped[str] = mapped_column(String(40), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    ioc: Mapped[IOC] = relationship(back_populates="tags")
    tag: Mapped[Tag] = relationship(lazy="joined")


class IOCRelationship(Base):
    """A relationship stored only when live intelligence or an analyst asserts it.

    relation: resolves_to (domain → IP), asn (IP → ASN), malware (hash → family),
    threat_actor, campaign. `target_ioc_id` is set when the target is itself an IOC.
    """

    __tablename__ = "ioc_relationships"
    __table_args__ = (
        UniqueConstraint(
            "ioc_id", "relation", "target_value", "origin", name="uq_ioc_relationships_identity"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    relation: Mapped[str] = mapped_column(String(20))
    target_ioc_id: Mapped[int | None] = mapped_column(
        ForeignKey("iocs.id", ondelete="SET NULL"), index=True
    )
    target_value: Mapped[str] = mapped_column(String(2048))
    label: Mapped[str | None] = mapped_column(String(200))
    origin: Mapped[str] = mapped_column(String(40))
    evidence: Mapped[str | None] = mapped_column(String(300))
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    ioc: Mapped[IOC] = relationship(foreign_keys=[ioc_id], back_populates="relationships")
    target_ioc: Mapped[IOC | None] = relationship(foreign_keys=[target_ioc_id])
