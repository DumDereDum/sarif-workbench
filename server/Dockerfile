FROM python:3.12-slim
WORKDIR /app

# weasyprint system deps + Cyrillic fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    libcairo2 libgdk-pixbuf-2.0-0 libffi8 \
    fonts-dejavu-core fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Build context is the repo root (T-34: server depends on the workspace-local
# swb-contract package, which lives outside server/ — see contract/).
#
# Layer cache: rebuild only when either pyproject.toml changes.
# Stubs let pip install deps/editable-metadata without the full source tree.
COPY contract/pyproject.toml contract/pyproject.toml
COPY server/pyproject.toml server/pyproject.toml
RUN mkdir -p contract/swb_contract server/swb_server && \
    touch contract/swb_contract/__init__.py server/swb_server/__init__.py && \
    pip install --no-cache-dir -e ./contract -e ./server && \
    rm contract/swb_contract/__init__.py server/swb_server/__init__.py

COPY contract/swb_contract/ contract/swb_contract/
COPY server/swb_server/ server/swb_server/

ENV DATA_DIR=/data
EXPOSE 8000

CMD ["uvicorn", "swb_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
