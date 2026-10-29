import asyncio
import logging

from app.providers.base import Provider
from app.schemas.ioc import EnrichmentOut, EnrichmentStatus
from app.schemas.provider import FAILED_STATUSES, RESPONDED_STATUSES, ProviderResult, ProviderStatus
from app.services.ioc import IOC

logger = logging.getLogger(__name__)


async def enrich(ioc: IOC, providers: list[Provider]) -> EnrichmentOut:
    """Query all providers concurrently. One provider failing never fails the rest."""
    outcomes = await asyncio.gather(*(p.lookup(ioc) for p in providers), return_exceptions=True)
    results: list[ProviderResult] = []
    for provider, outcome in zip(providers, outcomes, strict=True):
        if isinstance(outcome, ProviderResult):
            results.append(outcome)
            continue
        # lookup() is designed never to raise; this is a last line of defense.
        logger.error("Provider %s raised %s", provider.name, type(outcome).__name__)
        results.append(
            provider.result(ProviderStatus.ERROR, "Provider lookup failed unexpectedly.")
        )

    return EnrichmentOut(
        status=_overall_status(results),
        simulated=any(r.simulated for r in results),
        results=results,
    )


def _overall_status(results: list[ProviderResult]) -> EnrichmentStatus:
    responded = any(r.status in RESPONDED_STATUSES for r in results)
    failed = any(r.status in FAILED_STATUSES for r in results)
    if responded:
        return "partial" if failed else "completed"
    return "failed" if failed else "no_providers"
