from fastapi import Request

from app.core.config import Settings
from app.providers.base import Provider


def get_providers(request: Request) -> list[Provider]:
    return request.app.state.providers


def get_settings_from_app(request: Request) -> Settings:
    return request.app.state.settings
