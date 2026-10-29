"""Shared IOC records, tags, and relationships.

Relationships and tags are stored only when (a) live, non-simulated provider data
states them, or (b) an analyst enters them. Nothing here resolves, fetches, or
infers: e.g. domain → IP comes only from an analyst, since no provider data
used by ThreatScope supplies resolutions.
"""

import re
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.feeds.base import to_utc
from app.models import (
    IOC,
    Investigation,
    IOCRelationship,
    IOCTag,
    Tag,
    ThreatEvent,
    ThreatEventIOC,
    WatchlistEntry,
)
from app.models.ioc import ANALYST_ORIGIN
from app.providers.sanitize import clean_text
from app.schemas.ioc import IOCOut
from app.schemas.provider import ProviderResult, ProviderStatus
from app.schemas.risk import RiskLevel
from app.schemas.workflow import (
    InvestigationSummary,
    IOCContext,
    RelationshipOut,
    RelationType,
    TagOut,
    ThreatEventRef,
    WatchlistRef,
)
from app.services.ioc import IOC as ParsedIOC
from app.services.ioc import IOCType, IOCValidationError, parse_ioc

MAX_TAGS_PER_ORIGIN = 25
MAX_NAME_LENGTH = 100
_ASN = re.compile(r"(?:AS)?(\d{1,10})", re.IGNORECASE)
_IP_TYPES = frozenset({IOCType.IPV4, IOCType.IPV6})
_HASH_TYPES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})


class RelationshipError(ValueError):
    """An analyst-entered relationship is not valid for these IOC types/values."""


def _now() -> datetime:
    return datetime.now(UTC)


# --- IOCs and tags ----------------------------------------------------------


def get_or_create_ioc(
    session: Session, ioc: ParsedIOC | tuple[str, str], now: datetime | None = None
) -> IOC:
    ioc_type, value = (ioc.type.value, ioc.value) if isinstance(ioc, ParsedIOC) else ioc
    record = session.scalar(select(IOC).where(IOC.type == ioc_type, IOC.value == value))
    if record is None:
        record = IOC(type=ioc_type, value=value, created_at=now or _now())
        session.add(record)
        session.flush()
    return record


def ioc_out(record: IOC) -> IOCOut:
    """Rebuild the display form from the stored, already-normalized value."""
    parsed = parse_ioc(record.value)
    return IOCOut.from_ioc(parsed, ioc_id=record.id)


def normalize_tag(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = re.sub(r"\s+", " ", value).strip().lower()[:64]
    return name or None


def get_or_create_tag(session: Session, name: str) -> Tag:
    tag = session.scalar(select(Tag).where(Tag.name == name))
    if tag is None:
        tag = Tag(name=name)
        session.add(tag)
        session.flush()
    return tag


def add_tag(session: Session, record: IOC, raw_name: str, origin: str = ANALYST_ORIGIN) -> bool:
    """Attach a tag. Returns False if the name is empty after normalization."""
    name = normalize_tag(raw_name)
    if not name:
        return False
    tag = get_or_create_tag(session, name)
    if not any(link.tag_id == tag.id and link.origin == origin for link in record.tags):
        record.tags.append(IOCTag(tag_id=tag.id, tag=tag, origin=origin, created_at=_now()))
    return True


def remove_analyst_tag(record: IOC, raw_name: str) -> bool:
    """Remove an analyst tag. Provider-supplied tags record evidence and stay."""
    name = normalize_tag(raw_name)
    for link in list(record.tags):
        if link.origin == ANALYST_ORIGIN and link.tag.name == name:
            record.tags.remove(link)
            return True
    return False


def tags_out(record: IOC) -> list[TagOut]:
    return sorted(
        (TagOut(name=link.tag.name, origin=link.origin) for link in record.tags),
        key=lambda t: (t.origin != ANALYST_ORIGIN, t.name, t.origin),
    )


# --- relationships ----------------------------------------------------------


def _upsert_relationship(
    session: Session,
    record: IOC,
    relation: RelationType,
    target_value: str,
    origin: str,
    *,
    target_ioc: IOC | None = None,
    label: str | None = None,
    evidence: str | None = None,
    investigation_id: str | None = None,
) -> IOCRelationship:
    now = _now()
    existing = session.scalar(
        select(IOCRelationship).where(
            IOCRelationship.ioc_id == record.id,
            IOCRelationship.relation == relation.value,
            IOCRelationship.target_value == target_value,
            IOCRelationship.origin == origin,
        )
    )
    if existing:
        existing.last_observed_at = now
        existing.label = label or existing.label
        existing.investigation_id = investigation_id or existing.investigation_id
        return existing
    relationship = IOCRelationship(
        ioc_id=record.id,
        relation=relation.value,
        target_ioc_id=target_ioc.id if target_ioc else None,
        target_value=target_value,
        label=label,
        origin=origin,
        evidence=evidence,
        investigation_id=investigation_id,
        created_at=now,
        last_observed_at=now,
    )
    session.add(relationship)
    session.flush()
    return relationship


def add_analyst_relationship(
    session: Session, record: IOC, relation: RelationType, raw_target: str
) -> IOCRelationship:
    """Validate and store a relationship the analyst asserts. Nothing is resolved or fetched."""
    source_type = IOCType(record.type)
    if relation is RelationType.RESOLVES_TO:
        if source_type is not IOCType.DOMAIN:
            raise RelationshipError("Only a domain can resolve to an IP address.")
        try:
            target = parse_ioc(raw_target)
        except IOCValidationError as exc:
            raise RelationshipError(f"Target is not a valid IP address: {exc.message}") from None
        if target.type not in _IP_TYPES:
            raise RelationshipError("A domain can only resolve to an IPv4 or IPv6 address.")
        target_ioc = get_or_create_ioc(session, target)
        return _upsert_relationship(
            session,
            record,
            relation,
            target.value,
            ANALYST_ORIGIN,
            target_ioc=target_ioc,
            evidence="Entered by analyst",
        )
    if relation is RelationType.ASN:
        if source_type not in _IP_TYPES:
            raise RelationshipError("Only an IP address belongs to an ASN.")
        match = _ASN.fullmatch(raw_target.strip())
        if not match:
            raise RelationshipError("ASN must look like AS15169 or 15169.")
        return _upsert_relationship(
            session,
            record,
            relation,
            f"AS{int(match.group(1))}",
            ANALYST_ORIGIN,
            evidence="Entered by analyst",
        )
    if relation is RelationType.MALWARE and source_type not in _HASH_TYPES:
        raise RelationshipError("Only a file hash can be linked to a malware family.")
    name = clean_text(raw_target, MAX_NAME_LENGTH)
    if not name:
        raise RelationshipError("Name is required.")
    return _upsert_relationship(
        session, record, relation, name, ANALYST_ORIGIN, evidence="Entered by analyst"
    )


def delete_analyst_relationship(session: Session, record: IOC, relationship_id: int) -> bool:
    relationship = session.get(IOCRelationship, relationship_id)
    if (
        relationship is None
        or relationship.ioc_id != record.id
        or relationship.origin != ANALYST_ORIGIN
    ):
        return False
    session.delete(relationship)
    return True


def record_provider_intelligence(
    session: Session, record: IOC, results: list[ProviderResult], investigation_id: str
) -> None:
    """Store relationships and tags that live provider data states explicitly.

    Simulated (DEMO_MODE) and failed results never produce stored relationships.
    """
    ioc_type = IOCType(record.type)
    for result in results:
        if result.simulated or result.status is not ProviderStatus.OK:
            continue
        common = {
            "evidence": f"Reported by {result.display_name}",
            "investigation_id": investigation_id,
        }
        if ioc_type in _IP_TYPES and result.asn is not None:
            _upsert_relationship(
                session,
                record,
                RelationType.ASN,
                f"AS{result.asn}",
                result.provider,
                label=result.organization,
                **common,
            )
        if ioc_type in _HASH_TYPES:
            for family in result.malware_families:
                _upsert_relationship(
                    session, record, RelationType.MALWARE, family, result.provider, **common
                )
        for actor in result.threat_actors:
            _upsert_relationship(
                session, record, RelationType.THREAT_ACTOR, actor, result.provider, **common
            )
        for tag in result.tags[:MAX_TAGS_PER_ORIGIN]:
            add_tag(session, record, tag, origin=result.provider)


def relationships_out(session: Session, record: IOC) -> list[RelationshipOut]:
    rows = session.scalars(
        select(IOCRelationship)
        .where(or_(IOCRelationship.ioc_id == record.id, IOCRelationship.target_ioc_id == record.id))
        .order_by(IOCRelationship.relation, IOCRelationship.target_value)
    ).all()
    return [
        RelationshipOut(
            id=r.id,
            direction="outgoing" if r.ioc_id == record.id else "incoming",
            relation=r.relation,
            ioc_id=r.ioc_id,
            ioc_type=r.ioc.type,
            ioc_value=r.ioc.value,
            target_value=r.target_value,
            target_ioc_id=r.target_ioc_id,
            label=r.label,
            origin=r.origin,
            evidence=r.evidence,
            investigation_id=r.investigation_id,
            created_at=to_utc(r.created_at),
            last_observed_at=to_utc(r.last_observed_at),
        )
        for r in rows
    ]


# --- context ----------------------------------------------------------------


def investigation_summary(investigation: Investigation) -> InvestigationSummary:
    return InvestigationSummary(
        id=investigation.id,
        created_at=to_utc(investigation.created_at),
        ioc_id=investigation.ioc_id,
        ioc_type=investigation.ioc.type,
        ioc_value=investigation.ioc.value,
        risk_score=investigation.risk_score,
        risk_level=RiskLevel(investigation.risk_level),
        simulated=investigation.simulated,
        enrichment_status=investigation.enrichment_status,
    )


def ioc_context(session: Session, record: IOC, source_names: dict[str, str]) -> IOCContext:
    investigations = session.scalars(
        select(Investigation)
        .where(Investigation.ioc_id == record.id)
        .order_by(Investigation.created_at.desc())
        .limit(10)
    ).all()
    events = session.scalars(
        select(ThreatEvent)
        .join(ThreatEventIOC, ThreatEventIOC.event_id == ThreatEvent.id)
        .where(ThreatEventIOC.ioc_id == record.id)
        .order_by(ThreatEvent.published_at.desc())
        .limit(10)
    ).all()
    entry = session.scalar(select(WatchlistEntry).where(WatchlistEntry.ioc_id == record.id))
    return IOCContext(
        ioc=ioc_out(record),
        tags=tags_out(record),
        relationships=relationships_out(session, record),
        watchlist=WatchlistRef(id=entry.id, status=entry.status) if entry else None,
        investigations=[investigation_summary(i) for i in investigations],
        threat_events=[
            ThreatEventRef(
                id=e.id,
                title=e.title,
                source_name=source_names.get(e.source, e.source),
                published_at=to_utc(e.published_at) if e.published_at else None,
            )
            for e in events
        ],
    )
