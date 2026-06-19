---
hide:
  - toc
---

# SARIF Workbench

**Open-source triage workbench for SAST findings.**

Browse results from CodeQL, Semgrep, Svace, or any SARIF-compatible analyzer.
Triage findings with AI assistance using local or cloud LLMs.
Export PDF reports. Works fully offline — designed for air-gapped and corporate environments.

[Get started in 5 minutes](guide/quickstart.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/DumDereDum/sarif-workbench){ .md-button }

---

## Why SARIF Workbench?

Modern static analysis tools generate hundreds of findings per run. Teams waste days manually reviewing false positives. SARIF Workbench solves this:

| Problem | Solution |
|---|---|
| Too many findings to review manually | AI triage classifies each finding as TP / FP / Uncertain |
| Ad-hoc reports in spreadsheets | One-click PDF export in Svacer-compatible format |
| SAST tools output in different formats | Unified SARIF 2.1.0 ingestion with severity normalization |

---

## Key features

<div class="grid cards" markdown>

-   :material-magnify: **Unified findings browser**

    ---

    Filter by severity, verdict, rule, file, or full-text search. Click any finding to see the code snippet, CWE description, git blame, and triage history.

-   :material-robot: **AI-assisted triage**

    ---

    Stream AI verdicts over SSE via DeepSeek. Select the prompt strategy per run: balanced, FP-biased, or TP-biased.

-   :material-file-pdf-box: **PDF reports**

    ---

    Server-side PDF generation with WeasyPrint. Report layout matches the Svacer style — code snippets, verdict badges, triage rationale, and a per-rule table of contents.

-   :material-lock: **Air-gap friendly**

    ---

    The server, web UI, and CLI have no external network dependencies. Deploy with a single `docker compose up`.

-   :material-console: **CLI for CI/CD**

    ---

    `swb-cli` runs on the CI runner where source code is available. It enriches the SARIF with code snippets, git metadata, and fingerprints — then uploads the bundle to the server.

</div>

---

## How it works

```
┌─────────────┐   enrich   ┌───────────────────┐   upload   ┌─────────────┐
│  SARIF file │ ─────────► │  .swbmeta.json    │ ─────────► │   Server    │
│  from SAST  │            │  (sidecar)        │            │  + Web UI   │
└─────────────┘            └───────────────────┘            └─────────────┘
```

1. **`swb-cli enrich`** reads the SARIF on your CI runner, extracts git metadata, code snippets, and stable fingerprints for cross-run matching. Produces `report.sarif.swbmeta.json` alongside the original file. The original SARIF is never modified.

2. **`swb-cli upload`** sends the SARIF + sidecar pair to the server. The server resolves the project name from git provenance automatically.

3. **Web UI** — findings are immediately available in the browser. Filter, triage, trigger AI analysis, and download the PDF report.

---

## Supported analyzers

Any tool that outputs [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) is supported:

**Tested:** CodeQL · Semgrep · Svace · Checkmarx · Fortify (via SARIF export)

**Severity mapping:** `security-severity` score (0–10) takes priority over SARIF `level`. See [API reference](api/reference.md#severity-mapping).

---

## Quick start

```bash
# 1. Start the server
git clone https://github.com/DumDereDum/sarif-workbench && cd sarif-workbench
docker compose up

# 2. Enrich and upload a SARIF report (run on the machine with source code)
swb-cli enrich report.sarif --repo-root .
swb-cli upload report.sarif --server http://localhost:8000

# 3. Open the UI
open http://localhost:5173
```

[Full quickstart guide →](guide/quickstart.md)
