from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.errors import register_exception_handlers
from app.api.middleware import BodySizeLimitMiddleware
from app.api.routes import feed, health, investigate, iocs, providers, watchlist
from app.core.config import Settings, get_settings
from app.db.migrations import run_migrations
from app.db.session import create_db_engine, create_session_factory
from app.feeds.base import FeedSource
from app.feeds.registry import build_sources
from app.providers.base import Provider
from app.providers.http import create_http_client
from app.providers.registry import build_providers
from app.services.feed_refresh import FeedCollector
from app.services.threat_feed import sync_sources


def create_app(
    settings: Settings | None = None,
    provider_list: list[Provider] | None = None,
    feed_sources: list[FeedSource] | None = None,
) -> FastAPI:
    """App factory. Tests may inject providers/feed sources backed by a mock transport."""
    settings = settings or get_settings()
    engine = create_db_engine(settings.database_url)
    run_migrations(engine)
    http_client = create_http_client(
        user_agent=f"{settings.app_name.replace(' ', '-')}/{__version__}",
        timeout=settings.provider_timeout_seconds,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await http_client.aclose()
        engine.dispose()

    app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.session_factory = session_factory = create_session_factory(engine)
    app.state.providers = (
        provider_list if provider_list is not None else build_providers(settings, http_client)
    )
    sources = feed_sources if feed_sources is not None else build_sources(http_client)
    with session_factory() as session:
        sync_sources(session, sources)
    app.state.feed_collector = FeedCollector(sources, session_factory)

    app.add_middleware(BodySizeLimitMiddleware)
    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(investigate.router, prefix="/api")
    app.include_router(investigate.history_router, prefix="/api")
    app.include_router(watchlist.router, prefix="/api")
    app.include_router(iocs.router, prefix="/api")
    app.include_router(providers.router, prefix="/api")
    app.include_router(feed.router, prefix="/api")

    return app
