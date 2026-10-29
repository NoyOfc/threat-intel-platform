from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import WatchlistEntry
from app.schemas.errors import ErrorResponse
from app.schemas.workflow import (
    NoteCreate,
    WatchlistCreate,
    WatchlistEntryOut,
    WatchlistList,
    WatchlistStatus,
    WatchlistUpdate,
)
from app.services import watchlist
from app.services.notes import add_note, remove_note

router = APIRouter(
    prefix="/watchlist",
    tags=["watchlist"],
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)

DB = Annotated[Session, Depends(get_db)]


def _entry(db: Session, entry_id: int) -> WatchlistEntry:
    entry = db.get(WatchlistEntry, entry_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Watchlist entry not found.")
    return entry


@router.get("")
def list_watchlist(
    db: DB,
    status_filter: Annotated[WatchlistStatus | None, Query(alias="status")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> WatchlistList:
    return watchlist.list_entries(db, status_filter, q.strip() if q else None)


@router.post("", status_code=status.HTTP_201_CREATED)
def add_to_watchlist(body: WatchlistCreate, db: DB) -> WatchlistEntryOut:
    try:
        entry = watchlist.create_entry(db, body)
    except watchlist.AlreadyWatchedError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This IOC is already on the watchlist."
        ) from None
    return watchlist.get_entry_out(db, entry)


@router.patch("/{entry_id}")
def update_status(entry_id: int, body: WatchlistUpdate, db: DB) -> WatchlistEntryOut:
    entry = _entry(db, entry_id)
    entry.status = body.status.value
    watchlist.touch(entry)
    db.commit()
    return watchlist.get_entry_out(db, entry)


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_from_watchlist(entry_id: int, db: DB) -> Response:
    """Removes the entry and its notes. The IOC, its tags, and its history are kept."""
    db.delete(_entry(db, entry_id))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{entry_id}/notes", status_code=status.HTTP_201_CREATED)
def add_watchlist_note(entry_id: int, body: NoteCreate, db: DB) -> WatchlistEntryOut:
    entry = _entry(db, entry_id)
    add_note(entry, body.body)
    watchlist.touch(entry)
    db.commit()
    return watchlist.get_entry_out(db, entry)


@router.delete("/{entry_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_watchlist_note(entry_id: int, note_id: int, db: DB) -> Response:
    if not remove_note(_entry(db, entry_id), note_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Note not found.")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
