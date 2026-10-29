"""Migrations, schema parity, and database-enforced integrity."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.migrations import alembic_config, run_migrations
from app.db.session import create_db_engine
from app.models import (
    IOC,
    AnalystNote,
    Base,
    Investigation,
    ProviderResult,
    ThreatEvent,
    ThreatEventCVE,
    ThreatSource,
    WatchlistEntry,
)

NOW = datetime(2026, 10, 1, tzinfo=UTC)


def engine_at(tmp_path: Path, name: str = "test.db") -> sa.Engine:
    return create_db_engine(f"sqlite:///{tmp_path / name}")


def tables(engine: sa.Engine) -> set[str]:
    return set(sa.inspect(engine).get_table_names())


def test_fresh_database_matches_models(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    run_migrations(engine)

    with engine.connect() as connection:
        diff = compare_metadata(
            MigrationContext.configure(connection, opts={"compare_type": True}), Base.metadata
        )
        version = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))

    assert diff == []
    assert version == "0002"
    assert set(Base.metadata.tables) <= tables(engine)


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)

    run_migrations(engine)
    run_migrations(engine)

    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == "0002"


def _legacy_database(engine: sa.Engine) -> None:
    """Build the Phase 4 schema exactly as create_all left it: no alembic_version table."""
    config = alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")
        connection.execute(sa.text("DROP TABLE alembic_version"))
        events = sa.table(
            "threat_events",
            *(
                sa.column(c)
                for c in (
                    "id",
                    "source",
                    "external_id",
                    "title",
                    "summary",
                    "category",
                    "severity",
                    "known_exploited",
                    "analyst_status",
                    "analyst_notes",
                )
            ),
            *(
                sa.column(c, sa.DateTime(timezone=True))
                for c in ("published_at", "collected_at", "updated_at", "analyst_updated_at")
            ),
            sa.column("data", sa.JSON),
        )
        connection.execute(
            events.insert(),
            [
                {
                    "id": "a" * 32,
                    "source": "talos",
                    "external_id": "post-1",
                    "title": "Volt Typhoon report",
                    "summary": "Summary",
                    "category": "threat_research",
                    "severity": None,
                    "known_exploited": False,
                    "published_at": NOW,
                    "collected_at": NOW,
                    "updated_at": NOW,
                    "analyst_status": "relevant",
                    "analyst_notes": "  Escalated to IR.  ",
                    "analyst_updated_at": NOW,
                    "data": {
                        "cves": ["CVE-2026-1111"],
                        "threat_actors": ["Volt Typhoon"],
                        "malware_families": [],
                        "attack_techniques": ["T1059"],
                        "tags": ["APT", "Threat  Advisory", "apt"],
                        "iocs": [{"type": "domain", "value": "evil.example.com"}],
                        "fingerprint": "f" * 64,
                        "severity_basis": None,
                        "kev": None,
                    },
                },
                {
                    "id": "b" * 32,
                    "source": "cisa_kev",
                    "external_id": "CVE-2026-1111",
                    "title": "KEV entry",
                    "summary": None,
                    "category": "exploited_vulnerability",
                    "severity": "high",
                    "known_exploited": True,
                    "published_at": NOW,
                    "collected_at": NOW,
                    "updated_at": NOW,
                    "analyst_status": None,
                    "analyst_notes": None,
                    "analyst_updated_at": None,
                    "data": {
                        "cves": ["CVE-2026-1111"],
                        "affected_products": ["ExampleSoft Gateway"],
                        "kev": {"cve": "CVE-2026-1111", "vendor": "ExampleSoft"},
                        "severity_basis": "Derived: listed in CISA KEV",
                        "fingerprint": "e" * 64,
                    },
                },
            ],
        )
        connection.execute(
            sa.text(
                "INSERT INTO feed_source_state (name, etag, last_status) "
                "VALUES ('talos', '\"v1\"', 'updated')"
            )
        )


def test_legacy_database_is_upgraded_with_data_preserved(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    _legacy_database(engine)

    run_migrations(engine)

    assert "threat_events_legacy" not in tables(engine)
    assert "feed_source_state" not in tables(engine)
    with Session(engine) as session:
        talos = session.get(ThreatEvent, "a" * 32)
        kev = session.get(ThreatEvent, "b" * 32)
        assert talos.title == "Volt Typhoon report"
        assert talos.fingerprint == "f" * 64
        assert talos.analyst_status.status == "relevant"
        assert [n.body for n in talos.notes] == ["Escalated to IR."]
        assert [c.cve for c in talos.cves] == ["CVE-2026-1111"]
        assert {(e.kind, e.value) for e in talos.entities} == {
            ("threat_actor", "Volt Typhoon"),
            ("technique", "T1059"),
        }
        assert sorted(link.tag.name for link in talos.tag_links) == ["apt", "threat advisory"]
        assert [(link.ioc.type, link.ioc.value) for link in talos.ioc_links] == [
            ("domain", "evil.example.com")
        ]
        assert kev.kev == {"cve": "CVE-2026-1111", "vendor": "ExampleSoft"}
        assert kev.severity_basis == "Derived: listed in CISA KEV"
        assert kev.analyst_status is None and kev.notes == []
        assert session.get(ThreatSource, "talos").etag == '"v1"'
        assert session.get(ThreatSource, "cisa_kev") is not None  # created for referenced source
        pairs = session.execute(
            sa.text(
                "SELECT event_id, related_event_id, basis, value FROM threat_event_relationships"
            )
        ).all()
        assert pairs == [("a" * 32, "b" * 32, "cve", "CVE-2026-1111")]


def test_sqlite_enforces_foreign_keys(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    run_migrations(engine)

    with Session(engine) as session, pytest.raises(IntegrityError):
        session.add(
            ProviderResult(
                investigation_id="missing",
                position=0,
                provider="x",
                status="ok",
                simulated=False,
                reputation="unknown",
                details={},
            )
        )
        session.commit()


def test_note_must_have_exactly_one_target(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    run_migrations(engine)

    with Session(engine) as session, pytest.raises(IntegrityError):
        session.add(AnalystNote(body="orphan", created_at=NOW))
        session.commit()


def test_deleting_parents_cascades(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    run_migrations(engine)
    with Session(engine) as session:
        session.add(
            ThreatSource(name="talos", display_name="Talos", endpoint="https://x", category="c")
        )
        session.commit()
        ioc = IOC(type="domain", value="evil.example.com", created_at=NOW)
        entry = WatchlistEntry(ioc=ioc, status="monitoring", created_at=NOW, updated_at=NOW)
        entry.notes.append(AnalystNote(body="n", created_at=NOW))
        event = ThreatEvent(
            id="c" * 32,
            source="talos",
            external_id="x",
            title="t",
            collected_at=NOW,
            updated_at=NOW,
            category="threat_research",
            known_exploited=False,
            fingerprint="0",
        )
        event.cves.append(ThreatEventCVE(cve="CVE-2026-1"))
        session.add_all([entry, event])
        session.commit()

        session.execute(sa.delete(WatchlistEntry))
        session.execute(sa.delete(ThreatEvent))
        session.commit()

        assert session.scalar(sa.select(sa.func.count()).select_from(AnalystNote)) == 0
        assert session.scalar(sa.select(sa.func.count()).select_from(ThreatEventCVE)) == 0
        assert (
            session.scalar(sa.select(sa.func.count()).select_from(IOC)) == 1
        )  # IOC is shared, kept


def test_ioc_rows_are_unique_per_type_and_value(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    run_migrations(engine)

    with Session(engine) as session, pytest.raises(IntegrityError):
        session.add_all(
            [IOC(type="domain", value="a.example.com", created_at=NOW) for _ in range(2)]
        )
        session.commit()


def test_investigation_rows_cascade_to_provider_results(tmp_path: Path) -> None:
    engine = engine_at(tmp_path)
    run_migrations(engine)
    with Session(engine) as session:
        ioc = IOC(type="ipv4", value="8.8.8.8", created_at=NOW)
        investigation = Investigation(
            id="0" * 36,
            ioc=ioc,
            original="8.8.8.8",
            refanged=False,
            created_at=NOW,
            enrichment_status="completed",
            simulated=True,
            risk_level="unknown",
            risk_summary="",
            risk_factors=[],
            providers_considered=0,
            providers_flagged=0,
            provider_results=[
                ProviderResult(
                    position=0,
                    provider="x",
                    status="ok",
                    simulated=True,
                    reputation="unknown",
                    details={},
                )
            ],
        )
        session.add(investigation)
        session.commit()
        session.delete(investigation)
        session.commit()

        assert session.scalar(sa.select(sa.func.count()).select_from(ProviderResult)) == 0
