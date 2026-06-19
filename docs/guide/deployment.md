# Deployment

SARIF Workbench ships as a Docker Compose stack. The default (dev) setup takes one command; the production setup adds nginx and persistent volumes.

---

## Requirements

- Docker Desktop or Docker Engine + Compose plugin
- Ports 8000 (API) and 5173 (dev UI) or 80 (prod) free on the host

---

## Development mode

Starts the API server and the Vite dev server with hot reload. Source code is mounted directly — no rebuild needed after changes.

```bash
docker compose up          # start
docker compose down        # stop
docker compose logs -f     # follow server logs
```

| Service | URL |
|---|---|
| Web UI | http://localhost:5173 |
| API | http://localhost:8000 |
| API docs (Swagger) | http://localhost:8000/docs |

### Debug mode

To see full LLM request / response payloads in the logs:

```bash
make debug
# equivalent: LOG_LEVEL=DEBUG docker compose up
```

---

## Production mode

Builds a optimized React bundle, serves it via nginx on port 80, and proxies `/api/` to FastAPI. Data is stored in a Docker volume.

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

Open http://localhost after the build completes (takes ~2 minutes on first run).

**Stop:**
```bash
docker compose -f docker-compose.prod.yml down
```

---

## Environment variables

Copy the template and edit:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Server log verbosity: `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_FILE` | _(empty)_ | Log file path. In Docker, `./logs/server.log` is mounted to `/logs/server.log` |
| `DATA_DIR` | `/data` | Directory for SQLite DB and blob files |
| `DATABASE_URL` | `sqlite:////data/swb.db` | SQLite database path |

---

## Without Docker

Run the server and web UI directly on the host for development.

```bash
# Install Python dependencies
uv sync

# Install Node dependencies
cd web && npm install && cd ..

# Terminal 1 — API server (auto-reload on save)
uv run uvicorn swb_server.main:app --reload --app-dir server

# Terminal 2 — Web UI (hot reload)
cd web && npm run dev
```

Open http://localhost:5173.

---

## Makefile reference

| Command | Description |
|---|---|
| `make dev` | Start dev stack |
| `make dev-build` | Rebuild images and start dev stack |
| `make down` | Stop all services |
| `make logs` | Follow server logs |
| `make debug` | Start with `LOG_LEVEL=DEBUG` |
| `make prod` | Build and start production stack |
| `make sample` | Enrich and upload the built-in C++ sample |
| `make enrich SARIF=path/to/file.sarif` | Run `swb-cli enrich` on a file |
| `make upload SARIF=path/to/file.sarif` | Run `swb-cli upload` on a file |

