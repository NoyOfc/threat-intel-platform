from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_feed_collector, get_settings_from_app
from app.core.config import Settings
from app.db.session import get_db
from app.models import ThreatEvent
from app.schemas.errors import ErrorResponse
from app.schemas.feed import (
    AnalystStatus,
    AnalystUpdate,
    FeedListResponse,
    FeedSourceOut,
    FeedWindow,
    RefreshResponse,
    Severity,
    ThreatCategory,
    ThreatEventDetail,
    ThreatEventOut,
    TrendingResponse,
)
from app.schemas.workflow import NoteCreate
from app.services import threat_feed
from app.services.feed_refresh import FeedCollector, RefreshInProgressError
from app.services.notes import add_note, remove_note

router = APIRouter(prefix="/feed", tags=["threat feed"], responses={422: {"model": ErrorResponse}})

DB = Annotated[Session, Depends(get_db)]
Collector = Annotated[FeedCollector, Depends(get_feed_collector)]
EventId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]
Text = Annotated[str | None, Query(max_length=200)]


@router.get("/events")
def list_events(
    db: DB,
    collector: Collector,
    window: FeedWindow = "7d",
    severity: Severity | None = None,
    category: ThreatCategory | None = None,
    source: Annotated[str | None, Query(max_length=40)] = None,
    threat_actor: Text = None,
    malware: Text = None,
    cve: Annotated[str | None, Query(max_length=20)] = None,
    technique: Annotated[str | None, Query(max_length=12)] = None,
    analyst_status: AnalystStatus | None = None,
    q: Text = None,
) -> FeedListResponse:
    filters = threat_feed.FeedFilters(
        severity=severity,
        category=category,
        source=source,
        threat_actor=threat_actor,
        malware=malware,
        cve=cve.strip() if cve else None,
        technique=technique.strip().upper() if technique else None,
        analyst_status=analyst_status,
        q=q.strip() if q else None,
    )
    return threat_feed.list_events(db, window, filters, collector.source_names, datetime.now(UTC))


def _record(db: Session, event_id: str) -> ThreatEvent:
    record = threat_feed.get_record(db, event_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Threat event not found.")
    return record


@router.get("/events/{event_id}", responses={404: {"model": ErrorResponse}})
def get_event(event_id: EventId, db: DB, collector: Collector) -> ThreatEventDetail:
    return threat_feed.detail_out(db, _record(db, event_id), collector.source_names)


@router.patch("/events/{event_id}/analyst", responses={404: {"model": ErrorResponse}})
def update_analyst(
    event_id: EventId, body: AnalystUpdate, db: DB, collector: Collector
) -> ThreatEventOut:
    """Set Relevant / Monitoring / Not Relevant, or null to clear."""
    record = _record(db, event_id)
    threat_feed.set_analyst_status(record, body.status, datetime.now(UTC))
    db.commit()
    return threat_feed.to_out(record, collector.source_names)


@router.post("/events/{event_id}/notes", status_code=status.HTTP_201_CREATED)
def add_event_note(
    event_id: EventId, body: NoteCreate, db: DB, collector: Collector
) -> ThreatEventOut:
    record = _record(db, event_id)
    add_note(record, body.body)
    db.commit()
    return threat_feed.to_out(record, collector.source_names)


@router.delete("/events/{event_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_event_note(event_id: EventId, note_id: int, db: DB) -> Response:
    if not remove_note(_record(db, event_id), note_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found.")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/trending")
def trending(db: DB, window: FeedWindow = "7d") -> TrendingResponse:
    return threat_feed.trending(db, window, datetime.now(UTC))


@router.get("/sources")
def sources(db: DB, collector: Collector) -> list[FeedSourceOut]:
    return threat_feed.source_statuses(db, collector.sources)


@router.post("/refresh", responses={409: {"model": ErrorResponse}})
async def refresh(
    collector: Collector, settings: Annotated[Settings, Depends(get_settings_from_app)]
) -> RefreshResponse:
    if not settings.feeds_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Threat feed collection is disabled (FEEDS_ENABLED=false)."
        )
    try:
        return await collector.refresh()
    except RefreshInProgressError:
        raise HTTPException(status.HTTP_409_CONFLICT, "A refresh is already running.") from None
