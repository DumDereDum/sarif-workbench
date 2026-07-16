# SARIF Workbench

**Open-source triage workbench for SAST findings.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/DumDereDum/sarif-workbench/ci.yml?branch=main&label=CI)](https://github.com/DumDereDum/sarif-workbench/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![Docs](https://img.shields.io/badge/docs-dumderedum.github.io-blue)](https://dumderedum.github.io/sarif-workbench/)

Browse results from CodeQL, Semgrep, Svace, Checkmarx, or any SARIF 2.1.0-compatible analyzer.
Triage findings with AI assistance against any OpenAI-compatible endpoint (local by default;
cloud providers such as DeepSeek are an explicit opt-in). Export PDF reports.

**[Full documentation →](https://dumderedum.github.io/sarif-workbench/)**

---

## Quick start

```bash
git clone https://github.com/DumDereDum/sarif-workbench && cd sarif-workbench
docker compose up          # dev stack: http://localhost:5173
make sample                 # optional: enrich + upload the built-in sample
```

CLI only:

```bash
uv sync
uv run swb-cli enrich report.sarif --repo-root .   # enrich SARIF with metadata
uv run swb-cli upload report.sarif                  # upload to server
```

Production deploy, environment variables, CLI reference, and API reference: see the
**[Documentation site](https://dumderdum.github.io/sarif-workbench/)**
([Deployment](https://dumderdum.github.io/sarif-workbench/guide/deployment/) ·
[CLI](https://dumderdum.github.io/sarif-workbench/guide/cli/) ·
[API](https://dumderdum.github.io/sarif-workbench/api/reference/)).

---

## What it does

| Problem | Solution |
|---|---|
| Hundreds of SAST findings per run | AI triage classifies each as **TP / FP / Uncertain** (built-in `honest` prompt; a `force_fp` preset is also available for testing/formal-report workflows) |
| Code must not leave the security perimeter | The AI provider registry defaults to a local endpoint (Ollama, `http://localhost:11434/v1`). Cloud providers (DeepSeek, GigaChat, YandexGPT, ...) are supported by the same registry but are **disabled by default** — opt in with `SWB_ALLOW_REMOTE_PROVIDERS=true` plus a host allowlist |
| No cross-run tracking | Run comparison against a baseline (new / closed / unchanged) — **planned**, not yet implemented |
| Ad-hoc reports in spreadsheets | One-click **PDF export** in Svacer-compatible format |

**Key invariants:** the original SARIF file is immutable (CLI writes a sidecar, server stores the
blob byte-for-byte); data reaches the server only via the CLI, never the web UI; API keys live on
the server only, never in the browser. Full details, including the AI-provider allowlist model, are
in the [documentation](https://dumderdum.github.io/sarif-workbench/).

---

## Development

```bash
uv sync && (cd web && npm install)
uv run pytest tests/ -v       # pytest test suite (325+ tests)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the PR workflow and our
[Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

MIT — see [LICENSE](LICENSE).
