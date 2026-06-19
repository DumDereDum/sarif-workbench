# API Reference

All endpoints use the `/api/v1` prefix.

**Base URL:** `http://localhost:8000/api/v1`  
**Format:** `application/json` (except ingestion: `multipart/form-data`)  
**Time:** UTC, ISO-8601

---

## Ingestion

### `POST /api/v1/runs`

Upload a SARIF + sidecar pair. Called by `swb-cli upload` — not from the web UI.

**Content-Type:** `multipart/form-data`

| Part | Type | Description |
|---|---|---|
| `sarif` | file | Original SARIF file (unmodified) |
| `meta` | file | Sidecar file (`swbmeta/v1`) |

**Algorithm:**

1. Compute `sha256` of the received SARIF
2. Verify it matches `meta.source_sarif.sha256` — mismatch → `409 sha_mismatch`
3. Validate `meta.schema` version — unsupported → `422 unsupported_schema`
4. Resolve project from `meta.provenance.repo` (create if not exists)
5. **Idempotency:** if this project already has a run with the same SHA-256 → return `200` with existing run
6. Create run, store blobs, parse findings and rules

**Response `201 Created`** (or `200` for duplicate):

```json
{
  "run_id": "r-a1b2c3d4e5f6",
  "project_id": "billing-service",
  "deduplicated": false,
  "finding_count": 42,
  "counts": {
    "critical": 2,
    "high": 11,
    "medium": 19,
    "low": 8,
    "note": 2
  }
}
```

---

## Projects

### `GET /api/v1/projects`

List all projects with latest run summary.

```json
{
  "projects": [
    {
      "id": "billing-service",
      "name": "billing-service",
      "repo": "billing-service",
      "last_run": {
        "id": "r-a1b2c3d4e5f6",
        "scanned_at": "2026-06-18T09:00:00Z",
        "commit": "a1b2c3d"
      },
      "counts": { "critical": 2, "high": 11, "medium": 19, "low": 8, "note": 2, "all": 42 },
      "counts_by_verdict": {
        "true_positive": 5,
        "false_positive": 12,
        "uncertain": 3,
        "unmarked": 22
      }
    }
  ]
}
```

### `GET /api/v1/projects/{id}/runs`

List all runs for a project (for run selector and comparison).

```json
{
  "runs": [
    {
      "id": "r-a1b2c3d4e5f6",
      "commit": "a1b2c3d",
      "branch": "main",
      "tool": "Semgrep OSS",
      "tool_version": "1.x.x",
      "scanned_at": "2026-06-18T09:00:00Z",
      "counts": { "critical": 2, "high": 11, "medium": 19, "low": 8, "note": 2 }
    }
  ]
}
```

---

## Runs

### `GET /api/v1/runs/{runId}`

Run header: project, commit, branch, tool, dates, counts.

### `GET /api/v1/runs/{runId}/findings`

Paginated findings list (lightweight — no code snippets; fetch those in `/findings/{fid}`).

**Query parameters:**

| Parameter | Example | Description |
|---|---|---|
| `severity` | `critical,high` | Filter by severity (CSV) |
| `verdict` | `true_positive,uncertain` | Filter by verdict (CSV) |
| `rule` | `CWE-89` | Filter by rule ID |
| `file` | `src/db/` | File path prefix/substring |
| `q` | `sql` | Full-text search across file, rule, message, scope |
| `sort` | `severity` | Sort field |
| `dir` | `asc` / `desc` | Sort direction |
| `page` | `1` | Page number (1-based) |
| `page_size` | `50` | Items per page (default 50, max 200) |

**Response:**

```json
{
  "total": 42,
  "page": 1,
  "page_size": 50,
  "items": [
    {
      "id": "F1",
      "swb_id": "h:6cfba861453794c0",
      "severity": "critical",
      "rule_id": "CWE-89",
      "rule_name": "SQL Injection",
      "uri": "src/db/queries.py",
      "start_line": 88,
      "scope": "execute_query",
      "message": "Untrusted user_id concatenated into SQL query",
      "verdict": "true_positive",
      "verdict_source": "llm",
      "confidence": 91
    }
  ]
}
```

### `GET /api/v1/runs/{runId}/aggregations`

Grouped counts for the filter panel. `?by=severity|verdict|rule|file|cwe`

```json
{
  "by": "rule",
  "groups": [
    { "key": "CWE-89", "label": "CWE-89 SQL Injection", "count": 3 },
    { "key": "CWE-79", "label": "CWE-79 Cross-site Scripting", "count": 2 }
  ]
}
```

### `GET /api/v1/runs/{runId}/sarif`

Returns the original SARIF blob (byte-for-byte, unmodified).

### `POST /api/v1/runs/{runId}/analyze`

Trigger AI triage for all unverdicted findings in a run.

**Content-Type:** `application/json`

```json
{
  "provider": "deepseek",
  "api_key": "sk-...",
  "model": "deepseek-chat",
  "prompt_type": "honest"
}
```

**Response:** `text/event-stream` (SSE)

Each event is a JSON object:

```
data: {"type": "progress", "finding_id": "F1", "verdict": "false_positive", "confidence": 86, "done": 5, "total": 42}

data: {"type": "error", "finding_id": "F7", "message": "Rate limit exceeded"}

data: {"type": "done", "verdicts_set": 38, "errors": 4}
```

### `POST /api/v1/runs/{runId}/reset`

Reset all AI verdicts in a run back to `unmarked`. Preserves manual (`human`) verdicts.

**Response `200 OK`:**
```json
{ "reset_count": 38 }
```

### `GET /api/v1/runs/{runId}/report`

Generate and download a PDF report.

**Query parameters:**

| Parameter | Example | Description |
|---|---|---|
| `severity` | `critical,high` | Include only these severities (CSV) |
| `verdict` | `true_positive` | Include only these verdicts (CSV) |

**Response:** `application/pdf`

---

## Findings

### `GET /api/v1/findings/{fid}`

Full finding detail: code snippet, rule description, codeFlow, git info, full triage history.

```json
{
  "id": "F1",
  "swb_id": "h:6cfba861453794c0",
  "severity": "critical",
  "rule_id": "CWE-89",
  "rule_name": "SQL Injection",
  "rule_description": "Concatenation of untrusted input into an SQL query...",
  "uri": "src/db/queries.py",
  "start_line": 88,
  "scope": "execute_query",
  "snippet": {
    "start_line": 83,
    "lines": ["...", "...", "    result = db.execute(query + user_id)", "..."],
    "hot_line": 88
  },
  "git": {
    "blob_sha": "e3b0c4...",
    "blame_commit": "a1b2c3d4...",
    "last_changed": "2026-05-30"
  },
  "verdict": {
    "verdict": "true_positive",
    "source": "llm",
    "confidence": 91,
    "rationale": "User ID is passed directly into the SQL string without parameterization.",
    "provider": "deepseek",
    "history": [
      { "source": "llm", "verdict": "true_positive", "at": "2026-06-18T10:00:00Z" }
    ]
  }
}
```

### `PATCH /api/v1/findings/{fid}/verdict`

Override a finding's verdict manually.

**Request:**
```json
{
  "verdict": "false_positive",
  "rationale": "Input is validated upstream before reaching this function."
}
```

**Response `200 OK`:** updated `verdict` object with `source: "human"`.

---

## Prompts

### `GET /api/v1/prompts`

List available built-in prompt templates for AI triage.

```json
{
  "prompts": [
    {
      "id": "honest",
      "name": "Honest",
      "description": "Balanced classification — mark uncertain when evidence is insufficient."
    },
    {
      "id": "force_fp",
      "name": "Force FP",
      "description": "Classify as FP unless there is strong evidence of a real vulnerability."
    }
  ]
}
```

---

## Severity mapping {#severity-mapping}

SARIF findings are normalized to a unified severity scale. The numeric `security-severity` property (0–10) takes priority over the SARIF `level` field:

| `security-severity` | SARIF `level` | Severity |
|---|---|---|
| ≥ 9.0 | — | `critical` |
| 7.0–8.9 | — | `high` |
| 4.0–6.9 | — | `medium` |
| 0.1–3.9 | — | `low` |
| _(none)_ | `error` | `high` |
| _(none)_ | `warning` | `medium` |
| _(none)_ | `note` | `low` |
| _(none)_ | `none` / absent | `note` |

---

## Errors

All errors use a consistent JSON envelope:

```json
{ "error": "sha_mismatch", "message": "meta.source_sarif.sha256 does not match the uploaded SARIF" }
```

| HTTP | `error` | When |
|---|---|---|
| 400 | `bad_request` | Malformed multipart / invalid parameters |
| 404 | `not_found` | Project / run / finding not found |
| 409 | `sha_mismatch` | SARIF hash does not match the sidecar's `source_sarif.sha256` |
| 422 | `unsupported_schema` | Sidecar `schema` version is not supported |
| 422 | `invalid_sarif` | SARIF cannot be parsed or does not conform to the schema |
