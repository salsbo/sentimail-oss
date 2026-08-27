FROM python:3.12.13-slim

ARG SOURCE_REVISION=v0.2.1
LABEL org.opencontainers.image.source="https://github.com/salsbo/sentimail-oss" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"

# zbar : décodage QR / barcodes
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY server.py \
     domain_name.py \
     pinned_http.py \
     url_policy.py \
     /app/
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/sentimail/

RUN useradd -r -s /usr/sbin/nologin sandbox
USER sandbox

EXPOSE 8090

CMD ["python", "server.py"]
