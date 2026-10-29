from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_providers
from app.db.session import get_db
from app.providers.base import Provider
from app.schemas.errors import ErrorResponse
from app.schemas.ioc import (
    BulkInvestigateRequest,
    BulkInvestigateResponse,
    InvestigateRequest,
    InvestigationResponse,
)
from app.schemas.risk import RiskLevel
from app.schemas.workflow import InvestigationList
from app.services.investigation import (
    HistoryFilters,
    analyze_bulk,
    create_investigation,
    list_investigations,
    load_investigation,
)
from app.services.ioc import IOCType

DB = Annotated[Session, Depends(get_db)]
Providers = Annotated[list[Provider], Depends(get_providers)]

router = APIRouter(
    prefix="/investigate",
    tags=["investigate"],
    responses={422: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def investigate(
    body: InvestigateRequest, providers: Providers, db: DB
) -> InvestigationResponse:
    return await create_investigation(body.ioc, providers, db)


@router.post("/bulk")
def investigate_bulk(body: BulkInvestigateRequest) -> BulkInvestigateResponse:
    # Validation and type detection only; bulk enrichment is not implemented.
    return analyze_bulk(body.iocs)


history_router = APIRouter(prefix="/investigations", tags=["investigations"])


@history_router.get("")
def investigation_history(
    db: DB,
    q: Annotated[str | None, Query(max_length=200)] = None,
    ioc_type: IOCType | None = None,
    risk: RiskLevel | None = None,
    sort: Literal["newest", "oldest"] = "newest",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> InvestigationList:
    filters = HistoryFilters(
        q=q.strip() if q else None,
        ioc_type=ioc_type.value if ioc_type else None,
        risk_level=risk.value if risk else None,
        oldest_first=sort == "oldest",
        limit=limit,
        offset=offset,
    )
    return list_investigations(db, filters)


@history_router.get("/{investigation_id}", responses={404: {"model": ErrorResponse}})
def reopen_investigation(
    investigation_id: Annotated[str, Path(pattern=r"^[0-9a-f-]{36}$")],
    db: DB,
    providers: Providers,
) -> InvestigationResponse:
    """Return a saved investigation as recorded. No provider is queried again."""
    names = {p.name: p.display_name for p in providers}
    investigation = load_investigation(db, investigation_id, names)
    if investigation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found.")
    return investigation
