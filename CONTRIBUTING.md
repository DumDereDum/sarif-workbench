# Contributing to SARIF Workbench

## First steps

```bash
git clone https://github.com/DumDereDum/sarif-workbench
cd sarif-workbench

# Install Python dependencies
uv sync

# Install Node dependencies
cd web && npm install && cd ..

# Start the full stack
docker compose up

# In another terminal — run the sample
make sample

# Open http://localhost:5173 — you should see findings from the sample C++ project
```

## Project structure (read this first)

```
cli/swb_cli/
  commands/enrich.py   — main enrichment logic, this is where swb_id lives
  commands/upload.py   — uploads SARIF + sidecar to server
  sarif/parser.py      — reads SARIF 2.1.0, returns internal dataclasses
  code.py              — extracts code snippets from source files

server/swb_server/
  routers/             — one file per endpoint group
  routers/analyze.py   — SSE AI triage, this is the most complex one
  routers/runs.py      — ingestion (POST /runs) + reset
  models.py            — SQLAlchemy models (Project, Run, Finding, Rule)
  ingest.py            — parses SARIF + swbmeta, writes to DB
  ai/                  — LLM providers and prompt templates

web/src/
  routes/RunView.tsx   — main page: findings table + action buttons
  components/FindingDrawer.tsx  — side panel with finding detail
  components/AnalyzeModal.tsx   — AI triage modal with SSE progress
  api/client.ts        — all API calls go through here
```

## Running tests

```bash
uv run pytest tests/ -v
```

Tests live in `tests/cli/`. There are no server or frontend tests yet — adding them is welcome.

## Branch and PR conventions

- Branch name: `feat/short-description` or `fix/short-description`
- One PR per feature or fix — keep them small and reviewable
- PRs go into `main` — direct commits to `main` are blocked
- CI must be green before merging

## How to make a PR

1. Create a branch: `git checkout -b feat/my-feature`
2. Make changes, run `uv run pytest tests/ -v`
3. Push: `git push -u origin feat/my-feature`
4. Open PR on GitHub — fill in the template
5. Request review

## Key design rules (do not break these)

- The original SARIF file is **never modified** — `enrich` writes a sidecar, not in-place
- Data reaches the server **only via CLI** — no upload endpoint in the web UI
- `swb_id` must be deterministic — same input → same hash, always

## Where to ask questions

Open a GitHub Issue with label `question`, or ping in the team chat.
