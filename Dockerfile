# LODESTAR - production image (non-root, read-only friendly)
FROM python:3.12-slim AS base
LABEL org.opencontainers.image.title="LODESTAR" org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/manabouprj/Lodestar"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd -r lodestar && useradd -r -g lodestar -d /app lodestar
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY lodestar ./lodestar
COPY config ./config
COPY LICENSE NOTICE ./
RUN mkdir -p /app/data /app/reports /app/dist && chown -R lodestar:lodestar /app/data /app/reports /app/dist
USER lodestar
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').read()==b'ok' else 1)"
CMD ["python", "-m", "lodestar", "serve", "--host", "0.0.0.0", "--port", "8080"]
