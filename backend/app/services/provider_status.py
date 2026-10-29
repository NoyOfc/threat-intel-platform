from app.providers.base import Provider
from app.schemas.provider import (
    FAILED_STATUSES,
    ProviderAvailability,
    ProvidersStatusResponse,
    ProviderStatus,
    ProviderStatusOut,
)

_FAILURE_DETAILS = {
    ProviderStatus.AUTH_ERROR: "Last request failed authentication. Check the API key.",
    ProviderStatus.RATE_LIMITED: "Rate limited by the provider. Requests are paused briefly.",
    ProviderStatus.TIMEOUT: "Last request timed out.",
    ProviderStatus.UNAVAILABLE: "Provider was unreachable or reported an outage.",
    ProviderStatus.ERROR: "Provider returned an unexpected response.",
}


def provider_statuses(providers: list[Provider], demo_mode: bool) -> ProvidersStatusResponse:
    """Report configuration and recent health. Never includes credentials or any part of them."""
    return ProvidersStatusResponse(
        demo_mode=demo_mode,
        providers=[_status(provider, demo_mode) for provider in providers],
    )


def _status(provider: Provider, demo_mode: bool) -> ProviderStatusOut:
    health = provider.health
    if not provider.configured:
        status = ProviderAvailability.NOT_CONFIGURED
        detail = f"Set {provider.api_key_env} in the backend .env file and restart."
    elif not demo_mode and (health.cooling_down or health.last_status in FAILED_STATUSES):
        status = ProviderAvailability.UNAVAILABLE
        detail = _FAILURE_DETAILS.get(health.last_status, "Provider is temporarily unavailable.")
    else:
        status = ProviderAvailability.CONFIGURED
        detail = "API key configured."
    if demo_mode:
        detail += " Demo mode is on: results are simulated and no requests are sent."

    return ProviderStatusOut(
        name=provider.name,
        display_name=provider.display_name,
        status=status,
        mode="simulated" if demo_mode else "live",
        api_host=provider.api_host,
        api_key_env=provider.api_key_env,
        supported_types=sorted(provider.supported_types),
        last_result=health.last_status,
        last_checked_at=health.last_checked_at,
        detail=detail,
    )
