from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_providers, get_settings_from_app
from app.core.config import Settings
from app.providers.base import Provider
from app.schemas.provider import ProvidersStatusResponse
from app.services.provider_status import provider_statuses

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get("/status")
def providers_status(
    providers: Annotated[list[Provider], Depends(get_providers)],
    settings: Annotated[Settings, Depends(get_settings_from_app)],
) -> ProvidersStatusResponse:
    return provider_statuses(providers, settings.demo_mode)
