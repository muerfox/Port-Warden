FROM python:3.12.11-slim AS tls
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /out \
    && openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout /out/key.pem \
        -out /out/cert.pem \
        -subj "/CN=port-warden" \
        -addext "subjectAltName=DNS:localhost,DNS:port-warden,IP:127.0.0.1"

FROM python:3.12.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT_WARDEN_BIND_HOST=0.0.0.0 \
    PORT_WARDEN_BIND_PORT=9090 \
    PORT_WARDEN_EXPOSE_PUBLIC=1 \
    PORT_WARDEN_COOKIE_SECURE=1 \
    PORT_WARDEN_SSL_CERTFILE=/etc/port-warden/tls/cert.pem \
    PORT_WARDEN_SSL_KEYFILE=/etc/port-warden/tls/key.pem \
    PORT_WARDEN_DATA_DIR=/var/lib/port-warden \
    PORT_WARDEN_DATABASE_URL=sqlite:////var/lib/port-warden/port-warden.sqlite \
    PORT_WARDEN_NFT_BACKEND=local \
    PORT_WARDEN_HOST_NETWORK=0

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin portwarden \
    && mkdir -p /var/lib/port-warden /etc/port-warden/tls \
    && chown portwarden:portwarden /var/lib/port-warden /etc/port-warden /etc/port-warden/tls
COPY --from=tls --chown=10001:10001 /out/cert.pem /etc/port-warden/tls/cert.pem
COPY --from=tls --chown=10001:10001 /out/key.pem /etc/port-warden/tls/key.pem
RUN chmod 750 /etc/port-warden/tls \
    && chmod 644 /etc/port-warden/tls/cert.pem \
    && chmod 640 /etc/port-warden/tls/key.pem
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
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,ssl,urllib.request; urllib.request.urlopen('https://127.0.0.1:%s/health' % os.environ.get('PORT_WARDEN_BIND_PORT','9090'), context=ssl._create_unverified_context())" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "app"]
