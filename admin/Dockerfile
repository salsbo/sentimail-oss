FROM python:3.12.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
COPY tests /app/tests

# La console ne conserve rien sur disque : elle n'a pas besoin d'être root.
RUN useradd --system --uid 10093 --no-create-home sentinel-admin
USER sentinel-admin

CMD ["python", "-m", "sentimail_admin.app"]
