FROM python:3.12.13-slim

ARG SOURCE_REVISION=v0.2.1
LABEL org.opencontainers.image.source="https://github.com/salsbo/sentimail-oss" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"

# YARA + libmagic + OCR raster. Les packs eng/fra couvrent les langues
# majoritaires des factures et notifications reçues sans appel réseau.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-fra \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Evite qu'une image lance un nombre de threads OpenMP disproportionné.
ENV OMP_THREAD_LIMIT=1

WORKDIR /app

COPY requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY rules /app/rules
COPY server.py /app/
COPY archive_scan.py /app/
COPY document_extract.py /app/
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/sentimail/

RUN useradd -r -s /usr/sbin/nologin sandbox
USER sandbox

EXPOSE 8091

CMD ["python", "server.py"]
