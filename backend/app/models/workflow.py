from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.ioc import IOC


class WatchlistEntry(Base):
    """An IOC the analyst is tracking. Tags live on the IOC itself (ioc_tags)."""

    __tablename__ = "watchlist_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), unique=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    ioc: Mapped[IOC] = relationship(lazy="joined")
    notes: Mapped[list[AnalystNote]] = relationship(
        cascade="all, delete-orphan", order_by="AnalystNote.created_at", lazy="selectin"
    )


class AnalystNote(Base):
    """A timestamped analyst note on exactly one target: a watchlist entry or a threat event.

    ThreatAnalystNote is this model with `threat_event_id` set.
    """

    __tablename__ = "analyst_notes"
    __table_args__ = (
        CheckConstraint(
            "(watchlist_entry_id IS NOT NULL AND threat_event_id IS NULL)"
            " OR (watchlist_entry_id IS NULL AND threat_event_id IS NOT NULL)",
            name="one_target",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    watchlist_entry_id: Mapped[int | None] = mapped_column(
        ForeignKey("watchlist_entries.id", ondelete="CASCADE"), index=True
    )
    threat_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), index=True
    )
