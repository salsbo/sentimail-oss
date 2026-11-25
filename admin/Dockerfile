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
# Un checkout à umask restrictif doit aussi rester lisible par cet utilisateur.
RUN useradd --system --uid 10093 --no-create-home sentinel-admin \
    && chmod -R a+rX /app/src /app/tests
USER sentinel-admin

CMD ["python", "-m", "sentimail_admin.app"]
