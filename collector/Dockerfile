FROM python:3.12.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
COPY tests /app/tests
RUN chmod -R a+rX /app/src /app/tests

CMD ["python", "-m", "sentimail_v3.observation.smtp_server"]
