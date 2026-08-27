FROM mcr.microsoft.com/playwright/python:v1.55.0-noble

ARG SOURCE_REVISION=v0.2.1
LABEL org.opencontainers.image.source="https://github.com/salsbo/sentimail-oss" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"

RUN apt-get update && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY server.py /app/
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/sentimail/

USER pwuser

EXPOSE 8092

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8092"]
