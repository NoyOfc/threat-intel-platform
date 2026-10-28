import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import Settings
from app.schemas.health import HealthResponse

logger = logging.getLogger(__name__)


def database_is_reachable(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        # Log the class only; connection errors can embed the database URL.
        logger.warning("Database health check failed", exc_info=False)
        return False
    return True


def check_health(db: Session, settings: Settings) -> HealthResponse:
    db_ok = database_is_reachable(db)
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        service=settings.app_name,
        version=__version__,
        database="ok" if db_ok else "error",
        demo_mode=settings.demo_mode,
    )
