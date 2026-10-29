"""Analyst notes shared by watchlist entries and threat events (both expose `.notes`)."""

from datetime import UTC, datetime

from app.feeds.base import to_utc
from app.models import AnalystNote
from app.schemas.workflow import NoteOut


def note_out(note: AnalystNote) -> NoteOut:
    return NoteOut(id=note.id, body=note.body, created_at=to_utc(note.created_at))


def add_note(entry_or_event, body: str) -> AnalystNote:
    note = AnalystNote(body=body.replace("\x00", "").strip(), created_at=datetime.now(UTC))
    entry_or_event.notes.append(note)
    return note


def remove_note(entry_or_event, note_id: int) -> bool:
    for note in list(entry_or_event.notes):
        if note.id == note_id:
            entry_or_event.notes.remove(note)
            return True
    return False
