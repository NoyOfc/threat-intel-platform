# Development image for the ThreatScope API.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Source is mounted read-only in compose; keep tool caches out of it.
    RUFF_CACHE_DIR=/tmp/ruff-cache \
    PYTEST_ADDOPTS="-p no:cacheprovider"

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

# Unprivileged runtime user; /data holds the SQLite database (named volume).
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--reload"]
