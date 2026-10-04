FROM python:3.12.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT_WARDEN_BIND_HOST=0.0.0.0 \
    PORT_WARDEN_BIND_PORT=8443 \
    PORT_WARDEN_EXPOSE_PUBLIC=1 \
    PORT_WARDEN_DATA_DIR=/var/lib/port-warden \
    PORT_WARDEN_DATABASE_URL=sqlite:////var/lib/port-warden/port-warden.sqlite \
    PORT_WARDEN_NFT_BACKEND=disabled

WORKDIR /app
RUN useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin portwarden \
    && mkdir -p /var/lib/port-warden \
    && chown portwarden:portwarden /var/lib/port-warden
COPY requirements.txt .
ARG PIP_INDEX_URL=
RUN if [ -n "$PIP_INDEX_URL" ]; then \
      pip install --no-cache-dir -i "$PIP_INDEX_URL" -r requirements.txt; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi
COPY app ./app
COPY config.example.yaml ./config.example.yaml
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/health')" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "app"]
