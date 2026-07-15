# SARIF Workbench

**Open-source triage workbench for SAST findings.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![Docs](https://img.shields.io/badge/docs-dumderdum.github.io-blue)](https://dumderdum.github.io/sarif-workbench/)

Browse results from CodeQL, Semgrep, Svace, Checkmarx, or any SARIF 2.1.0-compatible analyzer.
Triage findings with AI assistance against any OpenAI-compatible endpoint (vLLM, Ollama — local by
default; DeepSeek and other cloud providers are available as an explicit opt-in — see below).
Export PDF reports. AI triage is the only feature that can reach the network, and by default it
only reaches `localhost` — cloud providers are disabled unless you turn them on.

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
cp .env.example .env && $EDITOR .env   # fill in POSTGRES_*/MINIO_ROOT_* before first run
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
| Code must not leave the security perimeter | The AI provider registry defaults to a local endpoint (Ollama, `http://localhost:11434/v1`); any OpenAI-compatible server (vLLM, Ollama, etc.) works via config. Cloud providers (DeepSeek, GigaChat, YandexGPT, ...) are supported by the same registry but are **disabled by default** — see [AI providers](#ai-providers) below |
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
- Ingestion, browsing, PDF export, and manual triage need no network access. AI triage is the only
  feature that talks to a network endpoint, and by default that endpoint is `localhost` (see
  [AI providers](#ai-providers)): out of the box, the built-in provider is a local Ollama-compatible
  server, and remote/cloud providers are refused with an explicit error unless you opt in with
  `SWB_ALLOW_REMOTE_PROVIDERS=true` plus a host allowlist.

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
make debug                  # start with LOG_LEVEL=DEBUG (extra request/response *metadata* — lengths,
                             # latency, HTTP status, token counts; never prompt/response content or api_key, see T-43)
```

### Production

```bash
cp .env.example .env   # fill in POSTGRES_USER/PASSWORD and MINIO_ROOT_USER/PASSWORD first
docker compose -f docker-compose.prod.yml up --build -d
```

nginx on port 80 serves the React bundle and proxies `/api/` to FastAPI. Data persists in a Docker volume.

`docker-compose.prod.yml` has no default credentials: `POSTGRES_USER`, `POSTGRES_PASSWORD`,
`MINIO_ROOT_USER`, and `MINIO_ROOT_PASSWORD` are required (`${VAR:?...}`) and compose refuses
to start without them, even if you don't use the `postgres`/`s3` profiles — variable
interpolation runs over the whole file before profiles are applied.

---

## Environment variables

Copy `.env.example` → `.env` and edit:

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Server log verbosity |
| `LOG_FILE` | _(empty)_ | Log file path (Docker: `./logs/server.log`) |
| `DATA_DIR` | `/data` | Directory for SQLite DB and blob files |
| `DATABASE_URL` | `sqlite:////data/swb.db` | SQLite database path |
| `POSTGRES_USER` | _(required, no default)_ | `docker-compose.prod.yml` `postgres` service — only used with `--profile postgres` / `make prod-full`, but must be set for any `make prod` run |
| `POSTGRES_PASSWORD` | _(required, no default)_ | Same as above — don't reuse the image's old `swb` default |
| `MINIO_ROOT_USER` | _(required, no default)_ | `docker-compose.prod.yml` `minio` service — only used with `--profile s3` / `make prod-full`, but must be set for any `make prod` run |
| `MINIO_ROOT_PASSWORD` | _(required, no default)_ | Same as above — don't reuse the image's old `minioadmin` default; MinIO requires 8+ chars |
| `SWB_AI_PROVIDERS` | _(unset → local Ollama only)_ | Inline JSON array configuring the AI provider registry — see [AI providers](#ai-providers) |
| `SWB_AI_PROVIDERS_FILE` | _(unset)_ | Path to a JSON file with the same shape as `SWB_AI_PROVIDERS`; takes precedence if both are set |
| `SWB_ALLOW_REMOTE_PROVIDERS` | `false` | Must be `true` for any non-local (`"local": false`) provider to be callable at all |
| `SWB_REMOTE_PROVIDER_ALLOWLIST` | _(empty)_ | Comma-separated hostnames a remote provider's `base_url` may point at (SSRF guard) |

---

## AI providers

The AI triage step (`POST /api/v1/runs/{id}/analyze`) talks to a provider registry, not a
hardcoded API. Out of the box — no configuration at all — the only registered provider is a local,
OpenAI-compatible endpoint (`ollama`, `http://localhost:11434/v1`); no analysis request can leave
the machine.

Any OpenAI-compatible server works the same way, local or remote: describe it as a registry entry.

```bash
export SWB_AI_PROVIDERS='[
  {"name": "vllm-local", "base_url": "http://localhost:8000/v1", "local": true},
  {"name": "deepseek",   "base_url": "https://api.deepseek.com",  "local": false, "default_model": "deepseek-chat"}
]'
```

`local: false` entries (cloud/remote) are registered but **refused with an explicit error** unless
you opt in with both of the following — the flag alone is not enough, since `base_url` is
attacker-influenceable configuration and a bare flag would turn any configured remote entry into an
SSRF channel (see `inspection/03-security.md` §2, §5):

```bash
export SWB_ALLOW_REMOTE_PROVIDERS=true
export SWB_REMOTE_PROVIDER_ALLOWLIST=api.deepseek.com   # comma-separated hostnames
```

A remote provider that isn't allowed this way is neither callable nor listed as "available" in
error messages — it behaves as if it weren't configured, not as a silent no-op.

**API keys live on the server only (T-44).** The client never holds or sends one — no
`api_key` field anywhere in the web UI, no localStorage. A remote entry names an
`api_key_env`: the environment variable the real secret is read from at call time, never
the registry JSON itself:

```bash
export SWB_AI_PROVIDERS='[
  {"name": "deepseek", "base_url": "https://api.deepseek.com", "local": false,
   "default_model": "deepseek-chat", "api_key_env": "SWB_DEEPSEEK_API_KEY"}
]'
export SWB_DEEPSEEK_API_KEY=sk-...
```

Local providers need no key at all (most local inference servers don't check
`Authorization`). The web UI reads its provider/model choices from `GET /api/v1/providers`
(name/local/default_model for whatever's currently visible, plus a default) instead of a
hardcoded list — the same source of truth this section describes, so the UI can never name
a provider that isn't actually in the registry.

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
- [x] AI triage via SSE, OpenAI-compatible provider registry (local default, cloud opt-in)
- [x] PDF export (WeasyPrint, Svacer-compatible layout)
- [x] Verdict reset
- [ ] tree-sitter fingerprints (stable `swb_id` across runs)
- [x] Manual verdict override UI (`PATCH /findings/{fid}/verdict`)
- [ ] Run comparison / baseline delta view
- [x] Server-managed API keys + `GET /api/v1/providers` for the web UI (no more localStorage key)
- [ ] Authentication

---

## License

MIT — see [LICENSE](LICENSE).
