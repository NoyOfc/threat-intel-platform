from fastapi import APIRouter, status

from app.schemas.errors import ErrorResponse
from app.schemas.ioc import (
    BulkInvestigateRequest,
    BulkInvestigateResponse,
    InvestigateRequest,
    InvestigationResponse,
)
from app.services.investigation import analyze_bulk, create_investigation

router = APIRouter(
    prefix="/investigate",
    tags=["investigate"],
    responses={422: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
)


@router.post("", status_code=status.HTTP_201_CREATED)
def investigate(body: InvestigateRequest) -> InvestigationResponse:
    return create_investigation(body.ioc)


@router.post("/bulk")
def investigate_bulk(body: BulkInvestigateRequest) -> BulkInvestigateResponse:
    return analyze_bulk(body.iocs)
