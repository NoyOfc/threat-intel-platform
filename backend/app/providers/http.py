import httpx


def create_http_client(*, user_agent: str, timeout: float) -> httpx.AsyncClient:
    """Shared outbound client for provider adapters only."""
    return httpx.AsyncClient(
        follow_redirects=False,  # a redirect could point anywhere; treat it as an error
        trust_env=False,  # ignore HTTP(S)_PROXY / netrc so traffic goes only where code says
        timeout=httpx.Timeout(timeout),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        headers={"User-Agent": user_agent},
    )
