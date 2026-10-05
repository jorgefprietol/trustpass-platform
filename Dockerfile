FROM python:3.14-slim-bookworm@sha256:c8137f4c460908c8763f281c8f22c431eb5c538514ba9553fc3a89c06b7cfb88 AS dependencies
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock

FROM python:3.14-slim-bookworm@sha256:c8137f4c460908c8763f281c8f22c431eb5c538514ba9553fc3a89c06b7cfb88 AS runtime
ARG SOURCE_REVISION=local
LABEL org.opencontainers.image.title="TrustPass Platform" \
      org.opencontainers.image.source="https://github.com/jorgefprietol/trustpass-platform" \
      org.opencontainers.image.revision=$SOURCE_REVISION
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Apply available Debian security fixes for PCRE2 and Perl before dropping privileges.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0 perl-base \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app \
    && mkdir /data && chown app:app /data
COPY --from=dependencies /opt/venv /opt/venv
WORKDIR /app
COPY --chown=app:app trustpass trustpass
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"]
CMD ["uvicorn", "trustpass.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-level", "info", "--log-config", "/app/trustpass/logging.json"]
