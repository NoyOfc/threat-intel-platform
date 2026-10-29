"""Baseline: the Phase 4 threat-feed schema (previously created by create_all).

Databases created before migrations existed are stamped at this revision at
startup instead of running it.

Revision ID: 0001
Revises:
Create Date: 2026-10-29
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_events",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("external_id", sa.String(500), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("source_url", sa.String(2048)),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(20)),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("known_exploited", sa.Boolean(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("analyst_status", sa.String(20)),
        sa.Column("analyst_notes", sa.Text()),
        sa.Column("analyst_updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("source", "external_id", name="uq_threat_events_v1_source_external_id"),
    )
    for column in ("source", "published_at", "severity", "category", "known_exploited"):
        op.create_index(f"ix_threat_events_{column}", "threat_events", [column])

    op.create_table(
        "feed_source_state",
        sa.Column("name", sa.String(40), primary_key=True),
        sa.Column("etag", sa.String(300)),
        sa.Column("last_modified", sa.String(100)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_status", sa.String(20)),
        sa.Column("last_error", sa.String(300)),
        sa.Column("cooldown_until", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("feed_source_state")
    op.drop_table("threat_events")
