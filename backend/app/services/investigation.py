from collections import Counter
from datetime import UTC, datetime
from uuid import uuid4

from app.providers.base import Provider
from app.schemas.ioc import (
    BulkInvestigateResponse,
    BulkItem,
    BulkItemError,
    BulkSummary,
    InvestigationResponse,
    IOCOut,
)
from app.services.enrichment import enrich
from app.services.ioc import MAX_IOC_LENGTH, IOCValidationError, parse_ioc
from app.services.risk import assess


async def create_investigation(raw: str, providers: list[Provider]) -> InvestigationResponse:
    """Validate an IOC, enrich it via the providers, and score it.

    Providers receive the parsed IOC, never the raw input. Investigations are not
    persisted yet.
    """
    ioc = parse_ioc(raw)
    enrichment = await enrich(ioc, providers)
    return InvestigationResponse(
        id=uuid4(),
        created_at=datetime.now(UTC),
        ioc=IOCOut.from_ioc(ioc),
        enrichment=enrichment,
        risk=assess(enrichment.results),
    )


def analyze_bulk(raws: list[str]) -> BulkInvestigateResponse:
    """Validate and type-detect each IOC independently. No enrichment."""
    items: list[BulkItem] = []
    for index, raw in enumerate(raws):
        echoed = raw[:MAX_IOC_LENGTH]
        try:
            ioc = parse_ioc(raw)
        except IOCValidationError as exc:
            error = BulkItemError(
                code=exc.code, message=exc.message, suspected_type=exc.suspected_type
            )
            items.append(BulkItem(index=index, input=echoed, valid=False, error=error))
        else:
            items.append(BulkItem(index=index, input=echoed, valid=True, ioc=IOCOut.from_ioc(ioc)))

    by_type = Counter(item.ioc.type for item in items if item.ioc is not None)
    valid = sum(by_type.values())
    return BulkInvestigateResponse(
        items=items,
        summary=BulkSummary(
            total=len(items), valid=valid, invalid=len(items) - valid, by_type=dict(by_type)
        ),
    )
