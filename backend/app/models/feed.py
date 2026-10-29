from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatEventRecord(Base):
    """A collected threat event. Analyst fields survive re-collection."""

    __tablename__ = "threat_events"
    __table_args__ = (UniqueConstraint("source", "external_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    external_id: Mapped[str] = mapped_column(String(500))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str | None] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(String(2048))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str | None] = mapped_column(String(20), index=True)
    category: Mapped[str] = mapped_column(String(40), index=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # Normalized ThreatEventData fields that are lists or nested (actors, CVEs, IOCs, KEV...).
    data: Mapped[dict[str, Any]] = mapped_column(JSON)

    analyst_status: Mapped[str | None] = mapped_column(String(20))
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    analyst_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeedSourceState(Base):
    """Per-source fetch bookkeeping: HTTP cache validators and last outcome."""

    __tablename__ = "feed_source_state"

    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    etag: Mapped[str | None] = mapped_column(String(300))
    last_modified: Mapped[str | None] = mapped_column(String(100))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(20))
    last_error: Mapped[str | None] = mapped_column(String(300))
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
