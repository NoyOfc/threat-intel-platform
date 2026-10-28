from collections.abc import Iterator
from pathlib import Path

from fastapi import Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker


def create_db_engine(database_url: str) -> Engine:
    """Build an engine for any SQLAlchemy URL.

    SQLite-specific handling is confined here so switching to PostgreSQL only
    requires a different DATABASE_URL and driver package.
    """
    url = make_url(database_url)
    connect_args: dict[str, object] = {}
    if url.get_backend_name() == "sqlite":
        connect_args["check_same_thread"] = False
        if url.database and url.database != ":memory:":
            Path(url.database).parent.mkdir(parents=True, exist_ok=True)
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session_factory: sessionmaker[Session] = request.app.state.session_factory
    with session_factory() as session:
        yield session
