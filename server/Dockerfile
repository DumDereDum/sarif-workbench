FROM python:3.12-slim
WORKDIR /app

# weasyprint system deps + Cyrillic fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    libcairo2 libgdk-pixbuf-2.0-0 libffi8 \
    fonts-dejavu-core fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Layer cache: rebuild only when pyproject.toml changes.
# Stub lets pip install deps without the full source tree.
COPY pyproject.toml .
RUN mkdir -p swb_server && touch swb_server/__init__.py && \
    pip install --no-cache-dir -e . && \
    rm swb_server/__init__.py

COPY swb_server/ swb_server/

ENV DATA_DIR=/data
EXPOSE 8000

CMD ["uvicorn", "swb_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
