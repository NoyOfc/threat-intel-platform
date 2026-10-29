"""On-demand feed collection.

`FeedCollector.refresh()` is the single ingestion entry point, so a scheduler
(cron, APScheduler, a worker) can call it later without changes.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session, sessionmaker

from app.feeds.base import FeedFetchError, FeedParseError, FeedSource, FetchResult, to_utc
from app.models.feed import FeedSourceState
from app.schemas.feed import RefreshResponse, SourceRefreshResult
from app.services.threat_feed import upsert_events

logger = logging.getLogger(__name__)

MAX_CONCURRENCY = 3
# Hard ceiling = source timeout + grace, covering connect and body read together.
FETCH_GRACE_SECONDS = 5.0
DEFAULT_COOLDOWN = timedelta(minutes=15)
MAX_COOLDOWN = timedelta(hours=6)


class RefreshInProgressError(Exception):
    pass


@dataclass
class _Fetched:
    source: FeedSource
    result: FetchResult | None = None
    skipped: SourceRefreshResult | None = None
    error: FeedFetchError | None = None


class FeedCollector:
    def __init__(
        self,
        sources: list[FeedSource],
        session_factory: sessionmaker[Session],
        max_concurrency: int = MAX_CONCURRENCY,
    ) -> None:
        self.sources = sources
        self._session_factory = session_factory
        self._lock = asyncio.Lock()
        self._max_concurrency = max_concurrency

    @property
    def source_names(self) -> dict[str, str]:
        return {source.name: source.display_name for source in self.sources}

    async def refresh(self, now: datetime | None = None) -> RefreshResponse:
        if self._lock.locked():
            raise RefreshInProgressError
        async with self._lock:
            started = now or datetime.now(UTC)
            with self._session_factory() as session:
                states = {s.name: self._state(session, s.name) for s in self.sources}
                snapshots = {name: _Snapshot.of(state) for name, state in states.items()}

            # Network phase: concurrent but bounded, each source with its own timeout.
            semaphore = asyncio.Semaphore(self._max_concurrency)
            fetched = await asyncio.gather(
                *(self._fetch(s, snapshots[s.name], started, semaphore) for s in self.sources)
            )

            # Storage phase: sequential, one transaction per source.
            results = []
            with self._session_factory() as session:
                for item in fetched:
                    results.append(self._store(session, item, started))
            return RefreshResponse(
                started_at=started, finished_at=datetime.now(UTC), sources=results
            )

    @staticmethod
    def _state(session: Session, name: str) -> FeedSourceState:
        state = session.get(FeedSourceState, name)
        if state is None:
            state = FeedSourceState(name=name)
            session.add(state)
            session.commit()
        return state

    async def _fetch(
        self,
        source: FeedSource,
        snapshot: _Snapshot,
        now: datetime,
        semaphore: asyncio.Semaphore,
    ) -> _Fetched:
        if source.planned_reason:
            return _Fetched(source, skipped=self._result(source, "planned", source.planned_reason))
        if snapshot.cooldown_until and now < snapshot.cooldown_until:
            return _Fetched(
                source,
                skipped=self._result(source, "rate_limited", "Cooling down after a rate limit."),
            )
        if snapshot.last_success_at and now - snapshot.last_success_at < timedelta(
            minutes=source.refresh_minutes
        ):
            return _Fetched(
                source,
                skipped=self._result(
                    source,
                    "fresh",
                    f"Checked recently; refreshes every {source.refresh_minutes} min.",
                ),
            )
        async with semaphore:
            try:
                async with asyncio.timeout(source.timeout_seconds + FETCH_GRACE_SECONDS):
                    result = await source.fetch(snapshot.etag, snapshot.last_modified)
                return _Fetched(source, result=result)
            except TimeoutError:
                return _Fetched(
                    source, error=FeedFetchError("timeout", "Source did not respond in time.")
                )
            except FeedFetchError as exc:
                return _Fetched(source, error=exc)
            except Exception as exc:  # noqa: BLE001 - one source must never break the refresh
                logger.error("Feed %s fetch failed: %s", source.name, type(exc).__name__)
                return _Fetched(
                    source, error=FeedFetchError("error", "Unexpected error while fetching.")
                )

    def _store(self, session: Session, item: _Fetched, now: datetime) -> SourceRefreshResult:
        source = item.source
        if item.skipped:
            return item.skipped
        state = self._state(session, source.name)
        state.last_attempt_at = now

        if item.error:
            state.last_status, state.last_error = item.error.status, item.error.message
            if item.error.status == "rate_limited":
                delay = (
                    timedelta(seconds=item.error.retry_after)
                    if item.error.retry_after
                    else DEFAULT_COOLDOWN
                )
                state.cooldown_until = now + min(delay, MAX_COOLDOWN)
            session.commit()
            return self._result(source, item.error.status, item.error.message)

        assert item.result is not None  # noqa: S101 - set whenever there is no error/skip
        if item.result.body is None:
            state.last_status, state.last_error, state.last_success_at = "not_modified", None, now
            session.commit()
            return self._result(source, "not_modified", "Source unchanged since last refresh.")

        try:
            events = source.parse(item.result.body)
        except (FeedParseError, ValueError, TypeError, KeyError) as exc:
            logger.warning("Feed %s parse failed: %s", source.name, type(exc).__name__)
            state.last_status, state.last_error = (
                "error",
                "Source returned content that could not be parsed.",
            )
            session.commit()
            return self._result(source, "error", state.last_error)

        new, updated = upsert_events(session, events, now)
        state.etag, state.last_modified = item.result.etag, item.result.last_modified
        state.last_status, state.last_error, state.last_success_at = "updated", None, now
        state.cooldown_until = None
        session.commit()
        return self._result(source, "updated", None, fetched=len(events), new=new, updated=updated)

    @staticmethod
    def _result(
        source: FeedSource, status: str, message: str | None, **counts: int
    ) -> SourceRefreshResult:
        return SourceRefreshResult(
            source=source.name,
            source_name=source.display_name,
            status=status,
            message=message,
            **counts,
        )


@dataclass(frozen=True)
class _Snapshot:
    etag: str | None
    last_modified: str | None
    last_success_at: datetime | None
    cooldown_until: datetime | None

    @classmethod
    def of(cls, state: FeedSourceState) -> _Snapshot:
        return cls(
            etag=state.etag,
            last_modified=state.last_modified,
            last_success_at=to_utc(state.last_success_at),
            cooldown_until=to_utc(state.cooldown_until),
        )
