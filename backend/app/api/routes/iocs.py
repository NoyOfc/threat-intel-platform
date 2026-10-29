from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_feed_collector
from app.db.session import get_db
from app.models import IOC
from app.schemas.errors import ErrorResponse
from app.schemas.workflow import IOCContext, RelationshipCreate, TagCreate
from app.services import iocs
from app.services.feed_refresh import FeedCollector

router = APIRouter(
    prefix="/iocs",
    tags=["iocs"],
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)

DB = Annotated[Session, Depends(get_db)]
Collector = Annotated[FeedCollector, Depends(get_feed_collector)]


def _ioc(db: Session, ioc_id: int) -> IOC:
    record = db.get(IOC, ioc_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IOC not found.")
    return record


@router.get("/{ioc_id}")
def ioc_context(ioc_id: int, db: DB, collector: Collector) -> IOCContext:
    """Tags, relationships, watchlist entry, investigations, and feed mentions for one IOC."""
    return iocs.ioc_context(db, _ioc(db, ioc_id), collector.source_names)


@router.post("/{ioc_id}/tags", status_code=status.HTTP_201_CREATED)
def add_tag(ioc_id: int, body: TagCreate, db: DB, collector: Collector) -> IOCContext:
    record = _ioc(db, ioc_id)
    if not iocs.add_tag(db, record, body.name):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Tag name is empty.")
    db.commit()
    return iocs.ioc_context(db, record, collector.source_names)


@router.delete("/{ioc_id}/tags", status_code=status.HTTP_204_NO_CONTENT)
def remove_tag(
    ioc_id: int, name: Annotated[str, Query(min_length=1, max_length=64)], db: DB
) -> Response:
    """Remove an analyst tag. Tags supplied by provider data are evidence and stay."""
    if not iocs.remove_analyst_tag(_ioc(db, ioc_id), name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No analyst tag with that name.")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{ioc_id}/relationships", status_code=status.HTTP_201_CREATED)
def add_relationship(
    ioc_id: int, body: RelationshipCreate, db: DB, collector: Collector
) -> IOCContext:
    """Record a relationship the analyst asserts. Nothing is resolved or fetched to verify it."""
    record = _ioc(db, ioc_id)
    iocs.add_analyst_relationship(db, record, body.relation, body.target)
    db.commit()
    return iocs.ioc_context(db, record, collector.source_names)


@router.delete("/{ioc_id}/relationships/{relationship_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_relationship(ioc_id: int, relationship_id: int, db: DB) -> Response:
    """Only analyst-entered relationships can be removed."""
    if not iocs.delete_analyst_relationship(db, _ioc(db, ioc_id), relationship_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No analyst relationship with that id.")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
