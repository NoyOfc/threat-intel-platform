"""Analyst workflow: shared IOC/tag tables, investigations, watchlist, notes,
IOC relationships, and normalized threat events.

Existing threat events, source state, analyst statuses, and notes are migrated.
Investigation history and the watchlist start empty (they were never persisted).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-29
"""

import re
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)
# Frozen copy of the mapping at the time of this migration.
ENTITY_FIELDS = {
    "threat_actors": "threat_actor",
    "malware_families": "malware",
    "campaigns": "campaign",
    "attack_techniques": "technique",
    "affected_products": "product",
    "industries": "industry",
    "countries": "country",
}
RELATED_KINDS = ("threat_actor", "malware", "technique", "campaign")


def _fk(
    table: str, column: str, target: str, ondelete: str | None = None
) -> sa.ForeignKeyConstraint:
    ref_table, ref_column = target.split(".")
    return sa.ForeignKeyConstraint(
        [column], [target], name=f"fk_{table}_{column}_{ref_table}", ondelete=ondelete
    )


def _create_schema() -> None:
    op.create_table(
        "tags",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_tags"),
        sa.UniqueConstraint("name", name="uq_tags_name"),
    )
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(10), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_iocs"),
        sa.UniqueConstraint("type", "value", name="uq_iocs_type_value"),
    )
    op.create_index("ix_iocs_type", "iocs", ["type"])

    op.create_table(
        "threat_sources",
        sa.Column("name", sa.String(40), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("endpoint", sa.String(500), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("etag", sa.String(300)),
        sa.Column("last_modified", sa.String(100)),
        sa.Column("last_attempt_at", TZ),
        sa.Column("last_success_at", TZ),
        sa.Column("last_status", sa.String(20)),
        sa.Column("last_error", sa.String(300)),
        sa.Column("cooldown_until", TZ),
        sa.PrimaryKeyConstraint("name", name="pk_threat_sources"),
    )
    op.create_table(
        "threat_events",
        sa.Column("id", sa.String(32), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("external_id", sa.String(500), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("source_url", sa.String(2048)),
        sa.Column("published_at", TZ),
        sa.Column("collected_at", TZ, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.Column("severity", sa.String(20)),
        sa.Column("severity_basis", sa.String(200)),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("known_exploited", sa.Boolean(), nullable=False),
        sa.Column("kev", sa.JSON()),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_threat_events"),
        sa.UniqueConstraint("source", "external_id", name="uq_threat_events_source_external_id"),
        _fk("threat_events", "source", "threat_sources.name"),
    )
    for column in ("source", "published_at", "severity", "category", "known_exploited"):
        op.create_index(f"ix_threat_events_{column}", "threat_events", [column])

    op.create_table(
        "investigations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("original", sa.String(2048), nullable=False),
        sa.Column("refanged", sa.Boolean(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("enrichment_status", sa.String(20), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("risk_score", sa.Integer()),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("risk_summary", sa.String(300), nullable=False),
        sa.Column("risk_factors", sa.JSON(), nullable=False),
        sa.Column("providers_considered", sa.Integer(), nullable=False),
        sa.Column("providers_flagged", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_investigations"),
        _fk("investigations", "ioc_id", "iocs.id", "CASCADE"),
    )
    for column in ("ioc_id", "created_at", "simulated", "risk_level"):
        op.create_index(f"ix_investigations_{column}", "investigations", [column])

    op.create_table(
        "provider_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("message", sa.String(300)),
        sa.Column("reputation", sa.String(20), nullable=False),
        sa.Column("malicious_count", sa.Integer()),
        sa.Column("suspicious_count", sa.Integer()),
        sa.Column("confidence", sa.Integer()),
        sa.Column("report_count", sa.Integer()),
        sa.Column("pulse_count", sa.Integer()),
        sa.Column("first_seen", TZ),
        sa.Column("last_seen", TZ),
        sa.Column("country", sa.String(8)),
        sa.Column("asn", sa.BigInteger()),
        sa.Column("organization", sa.String(200)),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_provider_results"),
        _fk("provider_results", "investigation_id", "investigations.id", "CASCADE"),
    )
    op.create_index(
        "ix_provider_results_investigation_id", "provider_results", ["investigation_id"]
    )
    op.create_index("ix_provider_results_provider", "provider_results", ["provider"])

    op.create_table(
        "ioc_tags",
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.Column("origin", sa.String(40), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("ioc_id", "tag_id", "origin", name="pk_ioc_tags"),
        _fk("ioc_tags", "ioc_id", "iocs.id", "CASCADE"),
        _fk("ioc_tags", "tag_id", "tags.id", "CASCADE"),
    )
    op.create_table(
        "ioc_relationships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("relation", sa.String(20), nullable=False),
        sa.Column("target_ioc_id", sa.Integer()),
        sa.Column("target_value", sa.String(2048), nullable=False),
        sa.Column("label", sa.String(200)),
        sa.Column("origin", sa.String(40), nullable=False),
        sa.Column("evidence", sa.String(300)),
        sa.Column("investigation_id", sa.String(36)),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("last_observed_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_ioc_relationships"),
        sa.UniqueConstraint(
            "ioc_id", "relation", "target_value", "origin", name="uq_ioc_relationships_identity"
        ),
        _fk("ioc_relationships", "ioc_id", "iocs.id", "CASCADE"),
        _fk("ioc_relationships", "target_ioc_id", "iocs.id", "SET NULL"),
        _fk("ioc_relationships", "investigation_id", "investigations.id", "SET NULL"),
    )
    op.create_index("ix_ioc_relationships_ioc_id", "ioc_relationships", ["ioc_id"])
    op.create_index("ix_ioc_relationships_target_ioc_id", "ioc_relationships", ["target_ioc_id"])

    op.create_table(
        "watchlist_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_watchlist_entries"),
        sa.UniqueConstraint("ioc_id", name="uq_watchlist_entries_ioc_id"),
        _fk("watchlist_entries", "ioc_id", "iocs.id", "CASCADE"),
    )
    op.create_index("ix_watchlist_entries_status", "watchlist_entries", ["status"])
    op.create_index("ix_watchlist_entries_updated_at", "watchlist_entries", ["updated_at"])

    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("watchlist_entry_id", sa.Integer()),
        sa.Column("threat_event_id", sa.String(32)),
        sa.PrimaryKeyConstraint("id", name="pk_analyst_notes"),
        sa.CheckConstraint(
            "(watchlist_entry_id IS NOT NULL AND threat_event_id IS NULL)"
            " OR (watchlist_entry_id IS NULL AND threat_event_id IS NOT NULL)",
            name="ck_analyst_notes_one_target",
        ),
        _fk("analyst_notes", "watchlist_entry_id", "watchlist_entries.id", "CASCADE"),
        _fk("analyst_notes", "threat_event_id", "threat_events.id", "CASCADE"),
    )
    op.create_index("ix_analyst_notes_watchlist_entry_id", "analyst_notes", ["watchlist_entry_id"])
    op.create_index("ix_analyst_notes_threat_event_id", "analyst_notes", ["threat_event_id"])

    op.create_table(
        "threat_event_cves",
        sa.Column("event_id", sa.String(32), nullable=False),
        sa.Column("cve", sa.String(20), nullable=False),
        sa.PrimaryKeyConstraint("event_id", "cve", name="pk_threat_event_cves"),
        _fk("threat_event_cves", "event_id", "threat_events.id", "CASCADE"),
    )
    op.create_index("ix_threat_event_cves_cve", "threat_event_cves", ["cve"])
    op.create_table(
        "threat_event_entities",
        sa.Column("event_id", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("value", sa.String(200), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("event_id", "kind", "value", name="pk_threat_event_entities"),
        _fk("threat_event_entities", "event_id", "threat_events.id", "CASCADE"),
    )
    op.create_index(
        "ix_threat_event_entities_kind_value", "threat_event_entities", ["kind", "value"]
    )
    op.create_table(
        "threat_event_tags",
        sa.Column("event_id", sa.String(32), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("event_id", "tag_id", name="pk_threat_event_tags"),
        _fk("threat_event_tags", "event_id", "threat_events.id", "CASCADE"),
        _fk("threat_event_tags", "tag_id", "tags.id", "CASCADE"),
    )
    op.create_table(
        "threat_event_iocs",
        sa.Column("event_id", sa.String(32), nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("event_id", "ioc_id", name="pk_threat_event_iocs"),
        _fk("threat_event_iocs", "event_id", "threat_events.id", "CASCADE"),
        _fk("threat_event_iocs", "ioc_id", "iocs.id", "CASCADE"),
    )
    op.create_index("ix_threat_event_iocs_ioc_id", "threat_event_iocs", ["ioc_id"])
    op.create_table(
        "threat_event_relationships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(32), nullable=False),
        sa.Column("related_event_id", sa.String(32), nullable=False),
        sa.Column("basis", sa.String(20), nullable=False),
        sa.Column("value", sa.String(200), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_threat_event_relationships"),
        sa.UniqueConstraint(
            "event_id",
            "related_event_id",
            "basis",
            "value",
            name="uq_threat_event_relationships_pair",
        ),
        sa.CheckConstraint(
            "event_id < related_event_id", name="ck_threat_event_relationships_ordered_pair"
        ),
        _fk("threat_event_relationships", "event_id", "threat_events.id", "CASCADE"),
        _fk("threat_event_relationships", "related_event_id", "threat_events.id", "CASCADE"),
    )
    op.create_index(
        "ix_threat_event_relationships_event_id", "threat_event_relationships", ["event_id"]
    )
    op.create_index(
        "ix_threat_event_relationships_related_event_id",
        "threat_event_relationships",
        ["related_event_id"],
    )
    op.create_table(
        "threat_analyst_statuses",
        sa.Column("event_id", sa.String(32), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("event_id", name="pk_threat_analyst_statuses"),
        _fk("threat_analyst_statuses", "event_id", "threat_events.id", "CASCADE"),
    )
    op.create_index("ix_threat_analyst_statuses_status", "threat_analyst_statuses", ["status"])


def _normalize_tag(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = re.sub(r"\s+", " ", value).strip().lower()[:64]
    return name or None


def _migrate_data(now: datetime) -> None:
    bind = op.get_bind()
    legacy = sa.table(
        "threat_events_legacy",
        *(
            sa.column(c, sa.String)
            for c in (
                "id",
                "source",
                "external_id",
                "title",
                "summary",
                "source_url",
                "severity",
                "category",
                "analyst_status",
                "analyst_notes",
            )
        ),
        *(
            sa.column(c, TZ)
            for c in ("published_at", "collected_at", "updated_at", "analyst_updated_at")
        ),
        sa.column("known_exploited", sa.Boolean),
        sa.column("data", sa.JSON),
    )
    state = sa.table(
        "feed_source_state",
        *(
            sa.column(c, sa.String)
            for c in ("name", "etag", "last_modified", "last_status", "last_error")
        ),
        *(sa.column(c, TZ) for c in ("last_attempt_at", "last_success_at", "cooldown_until")),
    )
    meta = sa.MetaData()
    meta.reflect(bind)
    t = meta.tables

    sources = {row["name"]: dict(row) for row in bind.execute(sa.select(state)).mappings()}
    for (name,) in bind.execute(sa.select(legacy.c.source).distinct()):
        sources.setdefault(name, {"name": name})
    if sources:
        # Every row needs every key for executemany; display fields are synced by the app.
        state_columns = (
            "etag",
            "last_modified",
            "last_attempt_at",
            "last_success_at",
            "last_status",
            "last_error",
            "cooldown_until",
        )
        bind.execute(
            t["threat_sources"].insert(),
            [
                {
                    "name": n,
                    "display_name": n,
                    "endpoint": "",
                    "category": "",
                    **{c: row.get(c) for c in state_columns},
                }
                for n, row in sources.items()
            ],
        )

    tag_ids: dict[str, int] = {}
    ioc_ids: dict[tuple[str, str], int] = {}

    def tag_id(name: str) -> int:
        if name not in tag_ids:
            tag_ids[name] = bind.execute(t["tags"].insert().values(name=name)).inserted_primary_key[
                0
            ]
        return tag_ids[name]

    def ioc_id(ioc_type: str, value: str, created: datetime) -> int:
        key = (ioc_type, value)
        if key not in ioc_ids:
            ioc_ids[key] = bind.execute(
                t["iocs"].insert().values(type=ioc_type, value=value, created_at=created)
            ).inserted_primary_key[0]
        return ioc_ids[key]

    events, cves, entities, tags, iocs, statuses, notes = [], [], [], [], [], [], []
    for row in bind.execute(sa.select(legacy)).mappings():
        data = row["data"] or {}
        events.append(
            {
                **{
                    k: row[k]
                    for k in (
                        "id",
                        "source",
                        "external_id",
                        "title",
                        "summary",
                        "source_url",
                        "published_at",
                        "collected_at",
                        "updated_at",
                        "severity",
                        "category",
                        "known_exploited",
                    )
                },
                "severity_basis": data.get("severity_basis"),
                "kev": data.get("kev"),
                "fingerprint": data.get("fingerprint") or "",
            }
        )
        cves += [{"event_id": row["id"], "cve": c} for c in dict.fromkeys(data.get("cves") or [])]
        for field, kind in ENTITY_FIELDS.items():
            for position, value in enumerate(dict.fromkeys(data.get(field) or [])):
                entities.append(
                    {
                        "event_id": row["id"],
                        "kind": kind,
                        "value": value[:200],
                        "position": position,
                    }
                )
        seen_tags: set[int] = set()
        for position, raw in enumerate(data.get("tags") or []):
            if (name := _normalize_tag(raw)) and (tid := tag_id(name)) not in seen_tags:
                seen_tags.add(tid)
                tags.append({"event_id": row["id"], "tag_id": tid, "position": position})
        seen_iocs: set[int] = set()
        for position, item in enumerate(data.get("iocs") or []):
            if isinstance(item, dict) and item.get("type") and item.get("value"):
                iid = ioc_id(item["type"], item["value"], row["collected_at"] or now)
                if iid not in seen_iocs:
                    seen_iocs.add(iid)
                    iocs.append({"event_id": row["id"], "ioc_id": iid, "position": position})
        changed_at = row["analyst_updated_at"] or row["updated_at"] or now
        if row["analyst_status"]:
            statuses.append(
                {"event_id": row["id"], "status": row["analyst_status"], "updated_at": changed_at}
            )
        if row["analyst_notes"] and row["analyst_notes"].strip():
            notes.append(
                {
                    "threat_event_id": row["id"],
                    "body": row["analyst_notes"].strip(),
                    "created_at": changed_at,
                }
            )

    for table, rows in (
        ("threat_events", events),
        ("threat_event_cves", cves),
        ("threat_event_entities", entities),
        ("threat_event_tags", tags),
        ("threat_event_iocs", iocs),
        ("threat_analyst_statuses", statuses),
        ("analyst_notes", notes),
    ):
        if rows:
            bind.execute(t[table].insert(), rows)

    # Events that share a literal CVE or entity are related (stored once per ordered pair).
    bind.execute(
        sa.text(
            "INSERT INTO threat_event_relationships (event_id, related_event_id, basis, value) "
            "SELECT a.event_id, b.event_id, 'cve', a.cve FROM threat_event_cves a "
            "JOIN threat_event_cves b ON a.cve = b.cve AND a.event_id < b.event_id"
        )
    )
    bind.execute(
        sa.text(
            "INSERT INTO threat_event_relationships (event_id, related_event_id, basis, value) "
            "SELECT a.event_id, b.event_id, a.kind, a.value FROM threat_event_entities a "
            "JOIN threat_event_entities b ON a.kind = b.kind AND a.value = b.value "
            "AND a.event_id < b.event_id WHERE a.kind IN :kinds"
        ).bindparams(sa.bindparam("kinds", expanding=True)),
        {"kinds": list(RELATED_KINDS)},
    )


def upgrade() -> None:
    for column in ("source", "published_at", "severity", "category", "known_exploited"):
        op.drop_index(f"ix_threat_events_{column}", table_name="threat_events")
    op.rename_table("threat_events", "threat_events_legacy")
    _create_schema()
    _migrate_data(datetime.now(UTC))
    op.drop_table("threat_events_legacy")
    op.drop_table("feed_source_state")


def downgrade() -> None:
    raise RuntimeError("Migration 0002 is not reversible. Restore a database backup instead.")
