"""Storage and querying for collected threat events."""

import hashlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.feeds.base import FeedSource, to_utc
from app.models.feed import FeedSourceState, ThreatEventRecord
from app.schemas.feed import (
    AnalystUpdate,
    FacetValue,
    FeedFacets,
    FeedListResponse,
    FeedSourceOut,
    FeedWindow,
    RelatedEvent,
    ThreatEventData,
    ThreatEventDetail,
    ThreatEventOut,
    TrendingResponse,
)

WINDOWS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
MAX_RESULTS = 200
MAX_RELATED = 8
TOP_TRENDING = 10
TRENDING_SCOPE = (
    "Trending in collected intelligence: counts across events this instance has collected "
    "in the selected window. This is not a measure of global activity."
)

# ThreatEventData fields stored together in the JSON `data` column.
_DATA_FIELDS = (
    "severity_basis",
    "kev",
    "threat_actors",
    "malware_families",
    "campaigns",
    "cves",
    "attack_techniques",
    "affected_products",
    "industries",
    "countries",
    "tags",
    "iocs",
)
_RELATED_FIELDS = ("cves", "threat_actors", "malware_families", "attack_techniques", "campaigns")


def event_id(source: str, external_id: str) -> str:
    """Stable ID so re-collecting the same report updates it instead of duplicating it."""
    return hashlib.sha256(f"{source}\x00{external_id}".encode()).hexdigest()[:32]


@dataclass(frozen=True)
class FeedFilters:
    severity: str | None = None
    category: str | None = None
    source: str | None = None
    threat_actor: str | None = None
    malware: str | None = None
    cve: str | None = None
    technique: str | None = None
    analyst_status: str | None = None
    q: str | None = None


# --- persistence ------------------------------------------------------------


def upsert_events(
    session: Session, events: Iterable[ThreatEventData], now: datetime
) -> tuple[int, int]:
    """Insert new events, update changed ones, and leave analyst fields untouched.

    Returns (new, updated). Duplicate items within one batch collapse to the first.
    """
    unique: dict[str, ThreatEventData] = {}
    for event in events:
        unique.setdefault(event_id(event.source, event.external_id), event)
    if not unique:
        return 0, 0

    existing = {
        record.id: record
        for record in session.scalars(
            select(ThreatEventRecord).where(ThreatEventRecord.id.in_(list(unique)))
        )
    }
    new = updated = 0
    for record_id, event in unique.items():
        columns = _columns(event)
        record = existing.get(record_id)
        if record is None:
            session.add(
                ThreatEventRecord(id=record_id, collected_at=now, updated_at=now, **columns)
            )
            new += 1
        elif record.data.get("fingerprint") != columns["data"]["fingerprint"]:
            for key, value in columns.items():
                setattr(record, key, value)
            record.updated_at = now
            updated += 1
    session.commit()
    return new, updated


def _columns(event: ThreatEventData) -> dict:
    data = event.model_dump(mode="json", include=set(_DATA_FIELDS))
    data["fingerprint"] = hashlib.sha256(event.model_dump_json().encode()).hexdigest()
    return {
        "source": event.source,
        "external_id": event.external_id,
        "title": event.title,
        "summary": event.summary,
        "source_url": event.source_url,
        "published_at": to_utc(event.published_at),
        "severity": event.severity.value if event.severity else None,
        "category": event.category.value,
        "known_exploited": event.known_exploited,
        "data": data,
    }


def to_out(record: ThreatEventRecord, source_names: dict[str, str]) -> ThreatEventOut:
    data = {key: value for key, value in record.data.items() if key in _DATA_FIELDS}
    return ThreatEventOut(
        id=record.id,
        source=record.source,
        source_name=source_names.get(record.source, record.source),
        external_id=record.external_id,
        title=record.title,
        summary=record.summary,
        source_url=record.source_url,
        published_at=to_utc(record.published_at),
        collected_at=to_utc(record.collected_at),
        updated_at=to_utc(record.updated_at),
        severity=record.severity,
        category=record.category,
        known_exploited=record.known_exploited,
        analyst_status=record.analyst_status,
        analyst_notes=record.analyst_notes,
        analyst_updated_at=to_utc(record.analyst_updated_at),
        **data,
    )


# --- queries ----------------------------------------------------------------


def _window_records(session: Session, window: FeedWindow, now: datetime) -> list[ThreatEventRecord]:
    cutoff = now - WINDOWS[window]
    statement = select(ThreatEventRecord).where(
        or_(
            ThreatEventRecord.published_at >= cutoff,
            and_(
                ThreatEventRecord.published_at.is_(None), ThreatEventRecord.collected_at >= cutoff
            ),
        )
    )
    records = list(session.scalars(statement))
    records.sort(key=lambda r: to_utc(r.published_at or r.collected_at), reverse=True)
    return records


def _contains(values: list[str], wanted: str, prefix: bool = False) -> bool:
    wanted = wanted.casefold()
    return any(
        v.casefold() == wanted or (prefix and v.casefold().startswith(f"{wanted}.")) for v in values
    )


def _matches(event: ThreatEventOut, f: FeedFilters) -> bool:
    if f.severity and event.severity != f.severity:
        return False
    if f.category and event.category != f.category:
        return False
    if f.source and event.source != f.source:
        return False
    if f.analyst_status and (event.analyst_status or "unreviewed") != f.analyst_status:
        return False
    if f.threat_actor and not _contains(event.threat_actors, f.threat_actor):
        return False
    if f.malware and not _contains(event.malware_families, f.malware):
        return False
    if f.cve and not _contains(event.cves, f.cve):
        return False
    if f.technique and not _contains(event.attack_techniques, f.technique, prefix=True):
        return False
    if f.q:
        haystack = " ".join(
            [
                event.title,
                event.summary or "",
                *event.tags,
                *event.cves,
                *event.threat_actors,
                *event.malware_families,
                *event.affected_products,
                *event.attack_techniques,
            ]
        ).casefold()
        if f.q.casefold() not in haystack:
            return False
    return True


def _facet(values: Iterable[str]) -> list[FacetValue]:
    counts = Counter(v for v in values if v)
    return [
        FacetValue(value=v, count=c)
        for v, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def list_events(
    session: Session,
    window: FeedWindow,
    filters: FeedFilters,
    source_names: dict[str, str],
    now: datetime,
) -> FeedListResponse:
    events = [to_out(r, source_names) for r in _window_records(session, window, now)]
    matched = [e for e in events if _matches(e, filters)]
    facets = FeedFacets(
        sources=_facet(e.source for e in events),
        severities=_facet(e.severity for e in events if e.severity),
        categories=_facet(e.category for e in events),
        threat_actors=_facet(a for e in events for a in e.threat_actors),
        malware_families=_facet(m for e in events for m in e.malware_families),
    )
    return FeedListResponse(
        window=window, total=len(matched), items=matched[:MAX_RESULTS], facets=facets
    )


def get_event(
    session: Session, record_id: str, source_names: dict[str, str]
) -> ThreatEventDetail | None:
    record = session.get(ThreatEventRecord, record_id)
    if record is None:
        return None
    event = to_out(record, source_names)

    wanted = {(field, v.casefold()) for field in _RELATED_FIELDS for v in getattr(event, field)}
    related: list[tuple[int, datetime, RelatedEvent]] = []
    if wanted:
        for other in session.scalars(
            select(ThreatEventRecord).where(ThreatEventRecord.id != record_id)
        ):
            shared = sorted(
                {
                    v
                    for field in _RELATED_FIELDS
                    for v in other.data.get(field) or []
                    if (field, v.casefold()) in wanted
                }
            )
            if shared:
                when = to_utc(other.published_at or other.collected_at)
                related.append(
                    (
                        len(shared),
                        when,
                        RelatedEvent(
                            id=other.id,
                            title=other.title,
                            source_name=source_names.get(other.source, other.source),
                            published_at=to_utc(other.published_at),
                            shared=shared,
                        ),
                    )
                )
    related.sort(key=lambda item: (item[0], item[1]), reverse=True)

    return ThreatEventDetail(
        **event.model_dump(),
        related=[item for _, _, item in related[:MAX_RELATED]],
        kev_cves=_confirmed_kev_cves(session, event.cves),
    )


def _confirmed_kev_cves(session: Session, cves: list[str]) -> list[str]:
    """CVEs that appear in the collected CISA KEV catalog. Never inferred."""
    kev_ids = {event_id("cisa_kev", cve): cve for cve in cves}
    if not kev_ids:
        return []
    found = set(
        session.scalars(select(ThreatEventRecord.id).where(ThreatEventRecord.id.in_(list(kev_ids))))
    )
    return [cve for record_id, cve in kev_ids.items() if record_id in found]


def update_analyst(
    session: Session, record_id: str, update: AnalystUpdate, now: datetime
) -> ThreatEventRecord | None:
    record = session.get(ThreatEventRecord, record_id)
    if record is None:
        return None
    if "status" in update.model_fields_set:
        record.analyst_status = update.status.value if update.status else None
    if "notes" in update.model_fields_set:
        notes = (update.notes or "").replace("\x00", "").strip()
        record.analyst_notes = notes or None
    record.analyst_updated_at = now
    session.commit()
    return record


def trending(session: Session, window: FeedWindow, now: datetime) -> TrendingResponse:
    records = _window_records(session, window, now)

    def top(field: str) -> list[FacetValue]:
        return _facet(v for r in records for v in r.data.get(field) or [])[:TOP_TRENDING]

    return TrendingResponse(
        window=window,
        scope=TRENDING_SCOPE,
        events_considered=len(records),
        cves=top("cves"),
        malware_families=top("malware_families"),
        threat_actors=top("threat_actors"),
        attack_techniques=top("attack_techniques"),
        affected_products=top("affected_products"),
    )


def source_statuses(session: Session, sources: list[FeedSource]) -> list[FeedSourceOut]:
    counts = dict(
        session.execute(
            select(ThreatEventRecord.source, func.count()).group_by(ThreatEventRecord.source)
        ).all()
    )
    results = []
    for source in sources:
        state = session.get(FeedSourceState, source.name)
        results.append(
            FeedSourceOut(
                name=source.name,
                display_name=source.display_name,
                endpoint=source.endpoint,
                category=source.category,
                refresh_minutes=source.refresh_minutes,
                planned_reason=source.planned_reason,
                event_count=counts.get(source.name, 0),
                last_attempt_at=to_utc(state.last_attempt_at) if state else None,
                last_success_at=to_utc(state.last_success_at) if state else None,
                last_status=state.last_status if state else None,
                last_error=state.last_error if state else None,
            )
        )
    return results
