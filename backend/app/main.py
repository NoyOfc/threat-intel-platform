from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.routes import health
from app.core.config import Settings, get_settings
from app.db.session import create_db_engine, create_session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = create_db_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.session_factory = create_session_factory(engine)

    app.include_router(health.router)
    # Feature routers will be mounted under /api/v1.

    return app
