from fastapi import Request

from app.core.config import Settings
from app.providers.base import Provider
from app.services.feed_refresh import FeedCollector


def get_providers(request: Request) -> list[Provider]:
    return request.app.state.providers


def get_feed_collector(request: Request) -> FeedCollector:
    return request.app.state.feed_collector


def get_settings_from_app(request: Request) -> Settings:
    return request.app.state.settings
