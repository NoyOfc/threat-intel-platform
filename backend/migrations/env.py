"""Alembic environment.

The app passes an open connection via `config.attributes["connection"]`; the CLI
falls back to the app's configured DATABASE_URL.
"""

from alembic import context
from sqlalchemy.engine import Connection

from app.core.config import get_settings
from app.db.session import create_db_engine
from app.models import Base

target_metadata = Base.metadata


def run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite can't ALTER most constraints; batch mode rebuilds tables. No-op on PostgreSQL.
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if connection is not None:
    run(connection)
else:
    engine = create_db_engine(get_settings().database_url)
    with engine.connect() as cli_connection:
        run(cli_connection)
