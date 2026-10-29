from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.feeds.base import to_utc
from app.models import IOC, Investigation, ProviderResult
from app.providers.base import Provider
from app.schemas.ioc import (
    BulkInvestigateResponse,
    BulkItem,
    BulkItemError,
    BulkSummary,
    EnrichmentOut,
    InvestigationResponse,
    IOCOut,
)
from app.schemas.provider import ProviderResult as ProviderResultOut
from app.schemas.risk import RiskAssessment, RiskFactor, RiskLevel
from app.schemas.workflow import InvestigationList
from app.services.enrichment import enrich
from app.services.ioc import MAX_IOC_LENGTH, IOCValidationError, parse_ioc
from app.services.iocs import (
    get_or_create_ioc,
    investigation_summary,
    ioc_out,
    record_provider_intelligence,
)
from app.services.risk import assess

MAX_PAGE = 100
_DETAIL_FIELDS = ("tags", "malware_families", "threat_actors", "raw_metadata_safe_subset")


async def create_investigation(
    raw: str, providers: list[Provider], session: Session
) -> InvestigationResponse:
    """Validate an IOC, enrich it, score it, and save it to investigation history.

    Providers receive the parsed IOC, never the raw input.
    """
    parsed = parse_ioc(raw)
    enrichment = await enrich(parsed, providers)
    risk = assess(enrichment.results)
    now = datetime.now(UTC)

    record = get_or_create_ioc(session, parsed, now)
    investigation = Investigation(
        id=str(uuid4()),
        ioc_id=record.id,
        original=parsed.original,
        refanged=parsed.refanged,
        created_at=now,
        enrichment_status=enrichment.status,
        simulated=enrichment.simulated,
        risk_score=risk.score,
        risk_level=risk.level.value,
        risk_summary=risk.summary[:300],
        risk_factors=[factor.model_dump(mode="json") for factor in risk.factors],
        providers_considered=risk.providers_considered,
        providers_flagged=risk.providers_flagged,
        provider_results=[
            _result_row(position, r) for position, r in enumerate(enrichment.results)
        ],
    )
    session.add(investigation)
    session.flush()
    record_provider_intelligence(session, record, enrichment.results, investigation.id)
    session.commit()

    return InvestigationResponse(
        id=investigation.id,
        created_at=now,
        ioc=IOCOut.from_ioc(parsed, ioc_id=record.id),
        enrichment=enrichment,
        risk=risk,
    )


def _result_row(position: int, result: ProviderResultOut) -> ProviderResult:
    data = result.model_dump(mode="json")
    return ProviderResult(
        position=position,
        details={key: data[key] for key in _DETAIL_FIELDS},
        **{
            key: getattr(result, key)
            for key in (
                "provider",
                "simulated",
                "message",
                "malicious_count",
                "suspicious_count",
                "confidence",
                "report_count",
                "pulse_count",
                "first_seen",
                "last_seen",
                "country",
                "asn",
                "organization",
            )
        },
        status=result.status.value,
        reputation=result.reputation.value,
    )


def _result_out(row: ProviderResult, display_names: dict[str, str]) -> ProviderResultOut:
    return ProviderResultOut(
        provider=row.provider,
        display_name=display_names.get(row.provider, row.provider),
        status=row.status,
        simulated=row.simulated,
        message=row.message,
        reputation=row.reputation,
        malicious_count=row.malicious_count,
        suspicious_count=row.suspicious_count,
        confidence=row.confidence,
        report_count=row.report_count,
        pulse_count=row.pulse_count,
        first_seen=to_utc(row.first_seen),
        last_seen=to_utc(row.last_seen),
        country=row.country,
        asn=row.asn,
        organization=row.organization,
        **row.details,
    )


def load_investigation(
    session: Session, investigation_id: str, display_names: dict[str, str]
) -> InvestigationResponse | None:
    """Reopen a saved investigation exactly as it was recorded (no new lookups)."""
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        return None
    ioc = ioc_out(investigation.ioc).model_copy(
        update={"original": investigation.original, "refanged": investigation.refanged}
    )
    return InvestigationResponse(
        id=investigation.id,
        created_at=to_utc(investigation.created_at),
        ioc=ioc,
        enrichment=EnrichmentOut(
            status=investigation.enrichment_status,
            simulated=investigation.simulated,
            results=[_result_out(row, display_names) for row in investigation.provider_results],
        ),
        risk=RiskAssessment(
            score=investigation.risk_score,
            level=RiskLevel(investigation.risk_level),
            summary=investigation.risk_summary,
            factors=[RiskFactor(**factor) for factor in investigation.risk_factors],
            providers_considered=investigation.providers_considered,
            providers_flagged=investigation.providers_flagged,
            simulated=investigation.simulated,
        ),
    )


@dataclass(frozen=True)
class HistoryFilters:
    q: str | None = None
    ioc_type: str | None = None
    risk_level: str | None = None
    oldest_first: bool = False
    limit: int = 50
    offset: int = 0


def list_investigations(session: Session, filters: HistoryFilters) -> InvestigationList:
    statement = select(Investigation).join(IOC, IOC.id == Investigation.ioc_id)
    if filters.q:
        statement = statement.where(
            func.lower(IOC.value).contains(filters.q.lower(), autoescape=True)
        )
    if filters.ioc_type:
        statement = statement.where(IOC.type == filters.ioc_type)
    if filters.risk_level:
        statement = statement.where(Investigation.risk_level == filters.risk_level)
    total = session.scalar(select(func.count()).select_from(statement.subquery()))
    order = (
        Investigation.created_at.asc() if filters.oldest_first else Investigation.created_at.desc()
    )
    rows = session.scalars(
        statement.order_by(order, Investigation.id)
        .limit(min(filters.limit, MAX_PAGE))
        .offset(filters.offset)
    ).all()
    return InvestigationList(total=total or 0, items=[investigation_summary(r) for r in rows])


def analyze_bulk(raws: list[str]) -> BulkInvestigateResponse:
    """Validate and type-detect each IOC independently. No enrichment, not saved."""
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
