"""Run Alembic migrations programmatically at startup."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"
BASELINE_REVISION = "0001"


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    return config


def run_migrations(engine: Engine) -> None:
    """Upgrade the database to the latest revision.

    A database created by `create_all` before migrations existed (it has
    `threat_events` but no `alembic_version`) is stamped at the baseline first, so
    its data is migrated rather than recreated.
    """
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        tables = set(inspect(connection).get_table_names())
        if "alembic_version" not in tables and "threat_events" in tables:
            command.stamp(config, BASELINE_REVISION)
        command.upgrade(config, "head")
