from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.feeds.base import to_utc
from app.models import IOC, Investigation, WatchlistEntry
from app.schemas.workflow import (
    WatchlistCreate,
    WatchlistEntryOut,
    WatchlistList,
    WatchlistStatus,
)
from app.services.ioc import parse_ioc
from app.services.iocs import add_tag, get_or_create_ioc, investigation_summary, ioc_out, tags_out
from app.services.notes import add_note, note_out

MAX_WATCHLIST_RESULTS = 500


class AlreadyWatchedError(Exception):
    def __init__(self, entry_id: int) -> None:
        super().__init__("IOC is already on the watchlist.")
        self.entry_id = entry_id


def entry_out(entry: WatchlistEntry, latest: Investigation | None) -> WatchlistEntryOut:
    return WatchlistEntryOut(
        id=entry.id,
        status=entry.status,
        created_at=to_utc(entry.created_at),
        updated_at=to_utc(entry.updated_at),
        ioc=ioc_out(entry.ioc),
        tags=tags_out(entry.ioc),
        notes=[note_out(n) for n in entry.notes],
        latest_investigation=investigation_summary(latest) if latest else None,
    )


def _latest_investigations(session: Session, ioc_ids: list[int]) -> dict[int, Investigation]:
    latest: dict[int, Investigation] = {}
    if not ioc_ids:
        return latest
    for investigation in session.scalars(
        select(Investigation)
        .where(Investigation.ioc_id.in_(ioc_ids))
        .order_by(Investigation.created_at.desc())
    ):
        latest.setdefault(investigation.ioc_id, investigation)
    return latest


def list_entries(session: Session, status: WatchlistStatus | None, q: str | None) -> WatchlistList:
    statement = select(WatchlistEntry).join(IOC, IOC.id == WatchlistEntry.ioc_id)
    if status:
        statement = statement.where(WatchlistEntry.status == status.value)
    if q:
        statement = statement.where(func.lower(IOC.value).contains(q.lower(), autoescape=True))
    total = session.scalar(select(func.count()).select_from(statement.subquery())) or 0
    entries = session.scalars(
        statement.order_by(WatchlistEntry.updated_at.desc(), WatchlistEntry.id.desc()).limit(
            MAX_WATCHLIST_RESULTS
        )
    ).all()
    latest = _latest_investigations(session, [e.ioc_id for e in entries])
    return WatchlistList(total=total, items=[entry_out(e, latest.get(e.ioc_id)) for e in entries])


def get_entry_out(session: Session, entry: WatchlistEntry) -> WatchlistEntryOut:
    return entry_out(entry, _latest_investigations(session, [entry.ioc_id]).get(entry.ioc_id))


def create_entry(session: Session, body: WatchlistCreate) -> WatchlistEntry:
    """Add an IOC to the watchlist. Raises IOCValidationError or AlreadyWatchedError."""
    parsed = parse_ioc(body.ioc)
    now = datetime.now(UTC)
    record = get_or_create_ioc(session, parsed, now)
    existing = session.scalar(select(WatchlistEntry).where(WatchlistEntry.ioc_id == record.id))
    if existing:
        raise AlreadyWatchedError(existing.id)
    entry = WatchlistEntry(ioc=record, status=body.status.value, created_at=now, updated_at=now)
    session.add(entry)
    for tag in body.tags:
        add_tag(session, record, tag)
    if body.note and body.note.strip():
        add_note(entry, body.note)
    session.commit()
    return entry


def touch(entry: WatchlistEntry) -> None:
    entry.updated_at = datetime.now(UTC)
