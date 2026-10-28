from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.health import HealthResponse
from app.services.health import check_health

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(
    request: Request, response: Response, db: Annotated[Session, Depends(get_db)]
) -> HealthResponse:
    result = check_health(db, request.app.state.settings)
    if result.status != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
