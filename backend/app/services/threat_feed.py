"""Storage and querying for collected threat events."""

import hashlib
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, insert, literal, or_, select
from sqlalchemy.orm import Session, aliased

from app.feeds.base import FeedSource, to_utc
from app.models import (
    IOC,
    Tag,
    ThreatAnalystStatus,
    ThreatEvent,
    ThreatEventCVE,
    ThreatEventEntity,
    ThreatEventIOC,
    ThreatEventRelationship,
    ThreatEventTag,
    ThreatSource,
)
from app.models.feed import ENTITY_FIELDS
from app.schemas.feed import (
    AnalystStatus,
    FacetValue,
    FeedFacets,
    FeedIOC,
    FeedListResponse,
    FeedSourceOut,
    FeedWindow,
    KEVDetails,
    RelatedEvent,
    ThreatEventData,
    ThreatEventDetail,
    ThreatEventOut,
    TrendingResponse,
)
from app.services.iocs import normalize_tag
from app.services.notes import note_out

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
# Entity kinds that link two events as related when both mention the same value.
RELATED_KINDS = ("threat_actor", "malware", "technique", "campaign")


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


# --- sources ----------------------------------------------------------------


def sync_sources(session: Session, sources: list[FeedSource]) -> None:
    """Make sure every configured source has a row (events reference it by name)."""
    for source in sources:
        row = session.get(ThreatSource, source.name)
        if row is None:
            row = ThreatSource(name=source.name)
            session.add(row)
        row.display_name = source.display_name
        row.endpoint = source.endpoint
        row.category = source.category.value
    session.commit()


# --- persistence ------------------------------------------------------------


def _fingerprint(event: ThreatEventData) -> str:
    return hashlib.sha256(event.model_dump_json().encode()).hexdigest()


class _Lookup:
    """Per-batch get-or-create caches for the shared tag and IOC tables."""

    def __init__(self, session: Session, now: datetime) -> None:
        self.session, self.now = session, now
        self.tags: dict[str, Tag] = {}
        self.iocs: dict[tuple[str, str], IOC] = {}

    def tag(self, name: str) -> Tag:
        if name not in self.tags:
            tag = self.session.scalar(select(Tag).where(Tag.name == name))
            if tag is None:
                tag = Tag(name=name)
                self.session.add(tag)
                self.session.flush()
            self.tags[name] = tag
        return self.tags[name]

    def ioc(self, item: FeedIOC) -> IOC:
        key = (item.type.value, item.value)
        if key not in self.iocs:
            record = self.session.scalar(select(IOC).where(IOC.type == key[0], IOC.value == key[1]))
            if record is None:
                record = IOC(type=key[0], value=key[1], created_at=self.now)
                self.session.add(record)
                self.session.flush()
            self.iocs[key] = record
        return self.iocs[key]


def _apply(record: ThreatEvent, event: ThreatEventData, lookup: _Lookup) -> None:
    """Copy feed-supplied fields and children onto the record. Analyst rows are separate."""
    record.source = event.source
    record.external_id = event.external_id
    record.title = event.title
    record.summary = event.summary
    record.source_url = event.source_url
    record.published_at = to_utc(event.published_at)
    record.severity = event.severity.value if event.severity else None
    record.severity_basis = event.severity_basis
    record.category = event.category.value
    record.known_exploited = event.known_exploited
    record.kev = event.kev.model_dump(mode="json") if event.kev else None
    record.fingerprint = _fingerprint(event)

    record.cves = [ThreatEventCVE(cve=cve) for cve in dict.fromkeys(event.cves)]
    record.entities = [
        ThreatEventEntity(kind=kind, value=value[:200], position=position)
        for field, kind in ENTITY_FIELDS.items()
        for position, value in enumerate(dict.fromkeys(getattr(event, field)))
    ]
    tags = dict.fromkeys(name for t in event.tags if (name := normalize_tag(t)))
    record.tag_links = [
        ThreatEventTag(tag=lookup.tag(name), position=i) for i, name in enumerate(tags)
    ]
    iocs = {(item.type, item.value): lookup.ioc(item) for item in event.iocs}
    record.ioc_links = [ThreatEventIOC(ioc=ioc, position=i) for i, ioc in enumerate(iocs.values())]


def upsert_events(
    session: Session, events: Iterable[ThreatEventData], now: datetime
) -> tuple[int, int]:
    """Insert new events and update changed ones; analyst status and notes are untouched.

    Returns (new, updated). Duplicate items within one batch collapse to the first.
    """
    unique: dict[str, ThreatEventData] = {}
    for event in events:
        unique.setdefault(event_id(event.source, event.external_id), event)
    if not unique:
        return 0, 0

    existing = {
        record.id: record
        for record in session.scalars(select(ThreatEvent).where(ThreatEvent.id.in_(list(unique))))
    }
    lookup = _Lookup(session, now)
    changed: list[str] = []
    new = updated = 0
    for record_id, event in unique.items():
        record = existing.get(record_id)
        if record is None:
            record = ThreatEvent(id=record_id, collected_at=now, updated_at=now)
            _apply(record, event, lookup)
            session.add(record)
            new += 1
        elif record.fingerprint != _fingerprint(event):
            _apply(record, event, lookup)
            record.updated_at = now
            updated += 1
        else:
            continue
        changed.append(record_id)
    session.flush()
    _rebuild_relationships(session, changed)
    session.commit()
    return new, updated


def _rebuild_relationships(session: Session, event_ids: list[str]) -> None:
    """Recompute stored links for changed events: pairs sharing a literal CVE or entity."""
    if not event_ids:
        return
    session.execute(
        delete(ThreatEventRelationship).where(
            or_(
                ThreatEventRelationship.event_id.in_(event_ids),
                ThreatEventRelationship.related_event_id.in_(event_ids),
            )
        )
    )
    columns = ["event_id", "related_event_id", "basis", "value"]
    a, b = aliased(ThreatEventCVE), aliased(ThreatEventCVE)
    session.execute(
        insert(ThreatEventRelationship).from_select(
            columns,
            select(a.event_id, b.event_id, literal("cve"), a.cve)
            .join(b, and_(a.cve == b.cve, a.event_id < b.event_id))
            .where(or_(a.event_id.in_(event_ids), b.event_id.in_(event_ids))),
        )
    )
    a, b = aliased(ThreatEventEntity), aliased(ThreatEventEntity)
    session.execute(
        insert(ThreatEventRelationship).from_select(
            columns,
            select(a.event_id, b.event_id, a.kind, a.value)
            .join(b, and_(a.kind == b.kind, a.value == b.value, a.event_id < b.event_id))
            .where(
                a.kind.in_(RELATED_KINDS),
                or_(a.event_id.in_(event_ids), b.event_id.in_(event_ids)),
            ),
        )
    )


# --- reading ----------------------------------------------------------------


def to_out(record: ThreatEvent, source_names: dict[str, str]) -> ThreatEventOut:
    entities: dict[str, list[str]] = defaultdict(list)
    for entity in sorted(record.entities, key=lambda e: (e.kind, e.position)):
        entities[entity.kind].append(entity.value)
    status = record.analyst_status
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
        severity_basis=record.severity_basis,
        category=record.category,
        known_exploited=record.known_exploited,
        kev=KEVDetails(**record.kev) if record.kev else None,
        cves=sorted(c.cve for c in record.cves),
        tags=[link.tag.name for link in sorted(record.tag_links, key=lambda t: t.position)],
        iocs=[
            FeedIOC(type=link.ioc.type, value=link.ioc.value)
            for link in sorted(record.ioc_links, key=lambda i: i.position)
        ],
        analyst_status=status.status if status else None,
        analyst_updated_at=to_utc(status.updated_at) if status else None,
        notes=[note_out(n) for n in record.notes],
        **{field: entities.get(kind, []) for field, kind in ENTITY_FIELDS.items()},
    )


def _window_condition(window: FeedWindow, now: datetime):
    cutoff = now - WINDOWS[window]
    return or_(
        ThreatEvent.published_at >= cutoff,
        and_(ThreatEvent.published_at.is_(None), ThreatEvent.collected_at >= cutoff),
    )


def _window_records(session: Session, window: FeedWindow, now: datetime) -> list[ThreatEvent]:
    records = list(session.scalars(select(ThreatEvent).where(_window_condition(window, now))))
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


def get_record(session: Session, record_id: str) -> ThreatEvent | None:
    return session.get(ThreatEvent, record_id)


def detail_out(
    session: Session, record: ThreatEvent, source_names: dict[str, str]
) -> ThreatEventDetail:
    event = to_out(record, source_names)
    links = session.scalars(
        select(ThreatEventRelationship).where(
            or_(
                ThreatEventRelationship.event_id == record.id,
                ThreatEventRelationship.related_event_id == record.id,
            )
        )
    ).all()
    shared: dict[str, set[str]] = defaultdict(set)
    for link in links:
        other = link.related_event_id if link.event_id == record.id else link.event_id
        shared[other].add(link.value)

    related: list[RelatedEvent] = []
    if shared:
        others = session.scalars(select(ThreatEvent).where(ThreatEvent.id.in_(list(shared)))).all()
        ranked = sorted(
            others,
            key=lambda o: (len(shared[o.id]), to_utc(o.published_at or o.collected_at)),
            reverse=True,
        )
        related = [
            RelatedEvent(
                id=o.id,
                title=o.title,
                source_name=source_names.get(o.source, o.source),
                published_at=to_utc(o.published_at),
                shared=sorted(shared[o.id]),
            )
            for o in ranked[:MAX_RELATED]
        ]

    return ThreatEventDetail(
        **event.model_dump(),
        related=related,
        kev_cves=_confirmed_kev_cves(session, event.cves),
    )


def _confirmed_kev_cves(session: Session, cves: list[str]) -> list[str]:
    """CVEs that appear in the collected CISA KEV catalog. Never inferred."""
    kev_ids = {event_id("cisa_kev", cve): cve for cve in cves}
    if not kev_ids:
        return []
    found = set(session.scalars(select(ThreatEvent.id).where(ThreatEvent.id.in_(list(kev_ids)))))
    return [cve for record_id, cve in kev_ids.items() if record_id in found]


def set_analyst_status(record: ThreatEvent, status: AnalystStatus | None, now: datetime) -> None:
    if status is None:
        record.analyst_status = None
    elif record.analyst_status is None:
        record.analyst_status = ThreatAnalystStatus(status=status.value, updated_at=now)
    else:
        record.analyst_status.status = status.value
        record.analyst_status.updated_at = now


# --- trending and sources ---------------------------------------------------


def trending(session: Session, window: FeedWindow, now: datetime) -> TrendingResponse:
    in_window = select(ThreatEvent.id).where(_window_condition(window, now))
    considered = session.scalar(select(func.count()).select_from(in_window.subquery())) or 0

    def top(statement) -> list[FacetValue]:
        rows = session.execute(statement.limit(TOP_TRENDING)).all()
        return [FacetValue(value=value, count=count) for value, count in rows]

    def top_entities(kind: str) -> list[FacetValue]:
        count = func.count(ThreatEventEntity.event_id.distinct())
        return top(
            select(ThreatEventEntity.value, count)
            .where(ThreatEventEntity.kind == kind, ThreatEventEntity.event_id.in_(in_window))
            .group_by(ThreatEventEntity.value)
            .order_by(count.desc(), ThreatEventEntity.value)
        )

    cve_count = func.count(ThreatEventCVE.event_id.distinct())
    return TrendingResponse(
        window=window,
        scope=TRENDING_SCOPE,
        events_considered=considered,
        cves=top(
            select(ThreatEventCVE.cve, cve_count)
            .where(ThreatEventCVE.event_id.in_(in_window))
            .group_by(ThreatEventCVE.cve)
            .order_by(cve_count.desc(), ThreatEventCVE.cve)
        ),
        malware_families=top_entities("malware"),
        threat_actors=top_entities("threat_actor"),
        attack_techniques=top_entities("technique"),
        affected_products=top_entities("product"),
    )


def source_statuses(session: Session, sources: list[FeedSource]) -> list[FeedSourceOut]:
    counts = dict(
        session.execute(select(ThreatEvent.source, func.count()).group_by(ThreatEvent.source)).all()
    )
    results = []
    for source in sources:
        state = session.get(ThreatSource, source.name)
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
