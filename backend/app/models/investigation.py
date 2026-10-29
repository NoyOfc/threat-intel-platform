from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.ioc import IOC


class Investigation(Base):
    """A saved investigation: the IOC as submitted, the risk assessment, and results."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    original: Mapped[str] = mapped_column(String(2048))
    refanged: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    enrichment_status: Mapped[str] = mapped_column(String(20))
    simulated: Mapped[bool] = mapped_column(Boolean, index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(20), index=True)
    risk_summary: Mapped[str] = mapped_column(String(300))
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    providers_considered: Mapped[int] = mapped_column(Integer)
    providers_flagged: Mapped[int] = mapped_column(Integer)

    ioc: Mapped[IOC] = relationship(lazy="joined")
    provider_results: Mapped[list[ProviderResult]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="ProviderResult.position",
    )


class ProviderResult(Base):
    """One provider's normalized answer within an investigation (never a raw response)."""

    __tablename__ = "provider_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    provider: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(20))
    simulated: Mapped[bool] = mapped_column(Boolean)
    message: Mapped[str | None] = mapped_column(String(300))
    reputation: Mapped[str] = mapped_column(String(20))
    malicious_count: Mapped[int | None] = mapped_column(Integer)
    suspicious_count: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[int | None] = mapped_column(Integer)
    report_count: Mapped[int | None] = mapped_column(Integer)
    pulse_count: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    country: Mapped[str | None] = mapped_column(String(8))
    asn: Mapped[int | None] = mapped_column(BigInteger)
    organization: Mapped[str | None] = mapped_column(String(200))
    # tags, malware_families, threat_actors, raw_metadata_safe_subset (already sanitized)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)

    investigation: Mapped[Investigation] = relationship(back_populates="provider_results")
