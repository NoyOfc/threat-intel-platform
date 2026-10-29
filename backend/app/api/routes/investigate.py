from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_providers
from app.providers.base import Provider
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
async def investigate(
    body: InvestigateRequest, providers: Annotated[list[Provider], Depends(get_providers)]
) -> InvestigationResponse:
    return await create_investigation(body.ioc, providers)


@router.post("/bulk")
def investigate_bulk(body: BulkInvestigateRequest) -> BulkInvestigateResponse:
    # Validation and type detection only; bulk enrichment is not implemented.
    return analyze_bulk(body.iocs)
