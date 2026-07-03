# SARIF Workbench

**Open-source triage workbench for SAST findings.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![Docs](https://img.shields.io/badge/docs-dumderdum.github.io-blue)](https://dumderdum.github.io/sarif-workbench/)

Browse results from CodeQL, Semgrep, Svace, Checkmarx, or any SARIF 2.1.0-compatible analyzer.
Triage findings with AI assistance (DeepSeek today; GigaChat, YandexGPT, vLLM, Ollama are planned — see Roadmap).
Export PDF reports. Fully offline / air-gapped operation is a roadmap goal — the current AI triage step calls the cloud DeepSeek API.

**[Documentation →](https://dumderdum.github.io/sarif-workbench/)**

---

```
swb-cli enrich report.sarif --repo-root .   # enrich SARIF with metadata
swb-cli upload report.sarif                 # upload to server
# → open http://localhost:5173
```

---

## Quick start (Docker)

**Requirements:** Docker Desktop or Docker Engine + Compose plugin.

```bash
git clone https://github.com/DumDereDum/sarif-workbench && cd sarif-workbench
docker compose up          # dev mode: http://localhost:5173
```

For production:

```bash
docker compose -f docker-compose.prod.yml up --build -d   # http://localhost
```

Try the built-in sample:

```bash
make sample   # enriches and uploads samples/cpp-bank/report.sarif
```

---

## What it does

| Problem | Solution |
|---|---|
| Hundreds of SAST findings per run | AI triage classifies each as **TP / FP / Uncertain** (built-in `honest` prompt; a `force_fp` preset is also available for testing/formal-report workflows — see [`ai/prompts.py`](server/swb_server/ai/prompts.py)) |
| Code must not leave the security perimeter | Local LLM providers: vLLM, Ollama, GigaChat, YandexGPT — **planned**, not yet implemented (only the cloud DeepSeek API works today) |
| No cross-run tracking | Run comparison against a baseline (new / closed / unchanged) — **planned**, not yet implemented |
| Ad-hoc reports in spreadsheets | One-click **PDF export** in Svacer-compatible format |

---

## Architecture

```
┌─────────────┐   enrich   ┌───────────────────┐   upload   ┌─────────────┐
│  SARIF file │ ─────────► │  .swbmeta.json    │ ─────────► │   Server    │
│  from SAST  │            │  (sidecar)        │            │  + Web UI   │
└─────────────┘            └───────────────────┘            └─────────────┘
```

Three components:

| Component | Port | Description |
|---|---|---|
| `swb-cli` | — | CLI: enriches SARIF with metadata, uploads to server |
| `server` | 8000 | FastAPI backend, SQLite, local blob storage |
| `web` | 5173 (dev) / 80 (prod) | React UI: browse findings, filter, triage, export |

**Key invariants:**
- Original SARIF is **immutable** — stored byte-for-byte, never rewritten
- Data reaches the server **only via CLI** — the web UI does not upload
- Ingestion, browsing, PDF export, and manual triage need no network access. AI triage is the exception: it sends finding details to the cloud DeepSeek API using the API key you provide when starting an analysis run. Fully offline operation via local LLM providers is planned — see Roadmap.

---

## CLI

### Install

```bash
curl -Ls https://astral.sh/uv/install.sh | sh
git clone https://github.com/DumDereDum/sarif-workbench && cd sarif-workbench
uv sync
uv run swb-cli --help
```

A standalone PyInstaller binary for CI / air-gapped installs is planned but not set up yet (no `.spec` file in the repo).

### `swb-cli enrich`

```bash
swb-cli enrich path/to/report.sarif --repo-root path/to/source

# Options:
#   --repo-root PATH       repository root for git metadata and source resolution
#   --context-policy       lines|line|function|none  (default: lines)
#   --context-lines N      context lines above/below finding  (default: 5)
#   --no-git               skip git metadata
#   --fail-on-missing-source   exit with error if source file not found
```

Output: `report.sarif.swbmeta.json` alongside the input file.

### `swb-cli upload`

```bash
swb-cli upload path/to/report.sarif --server http://localhost:8000

# Options:
#   --server URL   server base URL  (default: http://localhost:8000)
#   --meta PATH    explicit sidecar path  (default: <sarif>.swbmeta.json)
```

Output:
```
INFO  Upload successful!
INFO    project : billing-service
INFO    run_id  : r-a1b2c3d4e5f6
INFO    findings: 42  (crit=2 high=11 med=19 low=8 note=2)
INFO    web     : http://localhost:8000/projects/billing-service/runs/r-a1b2c3d4e5f6
```

---

## Docker Compose

### Development

```bash
docker compose up           # start (hot reload)
docker compose down         # stop
docker compose logs -f      # server logs
make debug                  # start with LOG_LEVEL=DEBUG (full LLM request/response logs)
```

### Production

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

nginx on port 80 serves the React bundle and proxies `/api/` to FastAPI. Data persists in a Docker volume.

---

## Environment variables

Copy `.env.example` → `.env` and edit:

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Server log verbosity |
| `LOG_FILE` | _(empty)_ | Log file path (Docker: `./logs/server.log`) |
| `DATA_DIR` | `/data` | Directory for SQLite DB and blob files |
| `DATABASE_URL` | `sqlite:////data/swb.db` | SQLite database path |

---

## Development without Docker

```bash
uv sync
cd web && npm install && cd ..

# Terminal 1 — API server
uv run uvicorn swb_server.main:app --reload --app-dir server

# Terminal 2 — Web UI
cd web && npm run dev
# → http://localhost:5173
```

Run tests:

```bash
uv run pytest tests/ -v
```

---

## Project structure

```
sarif-workbench/
├── cli/                    swb-cli (Python, PyInstaller)
│   └── swb_cli/
│       ├── commands/
│       │   ├── enrich.py   SARIF enrichment
│       │   └── upload.py   server upload
│       └── __main__.py
├── server/                 FastAPI server
│   └── swb_server/
│       ├── routers/        projects / runs / findings / analyze / report
│       ├── ai/             LLM providers and prompt templates
│       ├── models.py       SQLAlchemy ORM
│       ├── ingest.py       SARIF + swbmeta parser
│       ├── report_gen.py   PDF generator (WeasyPrint)
│       ├── storage.py      blob storage
│       └── main.py         entry point
├── web/                    React + Vite + TypeScript
│   └── src/
│       ├── routes/         Projects / ProjectRuns / RunView
│       ├── components/     FindingDrawer / AnalyzeModal
│       └── api/            typed API client
├── docs/                   MkDocs documentation
├── samples/                sample SARIF files for testing
├── tests/                  pytest test suite (83 tests)
├── docker-compose.yml      dev environment
├── docker-compose.prod.yml production environment
├── Makefile                convenience commands
└── .env.example            environment variable template
```

---

## Roadmap

- [x] SARIF ingestion (any SARIF 2.1.0 tool)
- [x] Findings browser (filter, search, sort, drawer)
- [x] AI triage via SSE (DeepSeek)
- [x] PDF export (WeasyPrint, Svacer-compatible layout)
- [x] Verdict reset
- [ ] tree-sitter fingerprints (stable `swb_id` across runs)
- [x] Manual verdict override UI (`PATCH /findings/{fid}/verdict`)
- [ ] Run comparison / baseline delta view
- [ ] GigaChat / YandexGPT / vLLM / Ollama providers
- [ ] Authentication

---

## License

MIT — see [LICENSE](LICENSE).
