# Development image for the TraceLock backend (includes test tooling).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

COPY . .

# The file store directory (mounted as a named volume) is owned by the app user, not world-readable.
RUN useradd --create-home --uid 1000 app \
    && mkdir -p /var/lib/tracelock/files \
    && chown app:app /var/lib/tracelock/files \
    && chmod 750 /var/lib/tracelock/files
USER app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
