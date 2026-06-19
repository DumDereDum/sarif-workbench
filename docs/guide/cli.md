# CLI Reference

`swb-cli` is the command-line tool that enriches SARIF reports and uploads them to the server.

It runs **on the machine with source code** — a CI runner or developer workstation — where git history and source files are available. The original SARIF is never modified.

---

## Installation

=== "uv (development)"

    ```bash
    # From the repo root
    uv sync
    uv run swb-cli --help
    ```

=== "PyInstaller binary (CI / air-gap)"

    ```bash
    uv sync
    uv run pyinstaller cli/swb_cli.spec --distpath dist/
    # Standalone binary — no Python required on the target machine
    ./dist/swb-cli --help
    ```

---

## `swb-cli enrich`

Reads a SARIF file and produces a `.swbmeta.json` sidecar with:

- **Code snippets** — configurable context lines around each finding
- **Git metadata** — blob SHA, blame commit, last-changed date
- **Fingerprints** — rule, content, and context hashes for finding identification
- **Provenance** — repository, branch, commit, tool name and version

The original SARIF file is **never modified**.

### Usage

```bash
swb-cli enrich <path-to-sarif> [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `<path-to-sarif>` | _(required)_ | Path to the input SARIF file |
| `--out PATH` | `<input>.swbmeta.json` | Output sidecar path |
| `--repo-root PATH` | auto-detect | Repository root for git metadata and source resolution |
| `--context-policy` | `lines` | How much source code to embed: `none` / `line` / `lines` / `function` |
| `--context-lines N` | `5` | Lines of context above and below the finding (for `lines` mode) |
| `--no-git` | off | Skip git metadata collection |
| `--fail-on-missing-source` | off | Exit with error if a finding's source file is not found |
| `--log-level` | `info` | Log verbosity: `error` / `warn` / `info` / `debug` |

### Context policy

The `--context-policy` flag controls how much source code is embedded in the sidecar.
This is the main privacy knob for air-gapped deployments:

| Mode | What is embedded |
|---|---|
| `none` | No source code — metadata and fingerprints only |
| `line` | Only the exact finding line |
| `lines` | Finding line ± `--context-lines` rows **(default)** |

### Examples

```bash
# Basic — auto-detects repo root
swb-cli enrich build/report.sarif

# Explicit repo root and wider context
swb-cli enrich build/report.sarif \
  --repo-root /workspace/my-service \
  --context-lines 10

# No source code embedded (metadata and fingerprints only)
swb-cli enrich build/report.sarif --context-policy none --no-git

# Fail if source files are missing (e.g. partial checkout)
swb-cli enrich build/report.sarif --fail-on-missing-source
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — sidecar written |
| `1` | Invalid SARIF (parse error or not SARIF) |
| `2` | I/O error (file not found, permission denied) |
| `3` | Partial success — sidecar written, but some metadata could not be collected (check logs) |

---

## `swb-cli upload`

Uploads a SARIF + sidecar pair to the server.

The server creates the project automatically from the `provenance.repo` field in the sidecar.
If the same SARIF (by SHA-256) was already uploaded, the server returns the existing run (idempotent).

### Usage

```bash
swb-cli upload <path-to-sarif> [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `<path-to-sarif>` | _(required)_ | Path to the SARIF file (sidecar must be next to it) |
| `--server URL` | `http://localhost:8000` | Server base URL |
| `--meta PATH` | `<sarif>.swbmeta.json` | Explicit path to the sidecar if not next to the SARIF |

### Examples

```bash
# Upload to local server
swb-cli upload build/report.sarif

# Upload to a remote server
swb-cli upload build/report.sarif --server https://swb.internal.company.com

# Sidecar in a different location
swb-cli upload build/report.sarif --meta /tmp/report.sarif.swbmeta.json
```

### Output

**New run (HTTP 201):**
```
INFO  Upload successful!
INFO    project : billing-service
INFO    run_id  : r-a1b2c3d4e5f6
INFO    findings: 42  (crit=2 high=11 med=19 low=8 note=2)
INFO    web     : http://localhost:8000/projects/billing-service/runs/r-a1b2c3d4e5f6
```

**Duplicate (HTTP 200, same SARIF already on server):**
```
WARNING Duplicate upload detected — this SARIF was already uploaded.
WARNING   run_id : r-a1b2c3d4e5f6
WARNING   uploaded_at: 2026-06-18T09:00:00Z
WARNING   web    : http://localhost:8000/projects/billing-service/runs/r-a1b2c3d4e5f6
```

---

## Sidecar format (`swbmeta/v1`)

The sidecar is a JSON file with the following top-level structure:

```json
{
  "schema": "swbmeta/v1",
  "generated_by": "swb-cli 0.1.0",
  "generated_at": "2026-06-18T09:00:00Z",
  "source_sarif": {
    "filename": "report.sarif",
    "sha256": "9f2c8a...",
    "size_bytes": 48120
  },
  "provenance": {
    "repo": "billing-service",
    "branch": "main",
    "commit": "a1b2c3d4...",
    "commit_short": "a1b2c3d",
    "is_dirty": false,
    "tool": "Semgrep OSS",
    "tool_version": "1.x.x",
    "scanned_at": "2026-06-18T07:41:30Z"
  },
  "context_policy": { "mode": "lines", "lines": 5 },
  "findings": [
    {
      "swb_id": "h:6cfba861453794c0",
      "occurrence": 0,
      "locator": {
        "run": 0,
        "result": 0,
        "rule_id": "CWE-89",
        "uri": "src/db/queries.py",
        "region": { "start_line": 88, "start_column": 5 }
      },
      "fingerprints": {
        "rule": "CWE-89",
        "scope": "func:execute_query@src/db/queries.py",
        "content": "h:7d1e...",
        "context": "h:42af..."
      },
      "git": {
        "blob_sha": "e3b0c4...",
        "blame_commit": "a1b2c3d4...",
        "last_changed": "2026-05-30"
      },
      "code": {
        "lang": "python",
        "start_line": 83,
        "end_line": 93,
        "snippet": "..."
      }
    }
  ]
}
```

### `swb_id` — stable cross-run key

`swb_id` is a deterministic hash derived from `rule + scope + content + occurrence`. It identifies the same logical finding across different runs, even if the line number shifts due to unrelated code changes.

### Fingerprints

| Key | What it hashes | Purpose |
|---|---|---|
| `rule` | Rule ID / CWE | Finding type |
| `scope` | Symbol name + file path | Location identifier |
| `content` | Normalized code at the finding | Detects code changes |
| `context` | Normalized surrounding lines | Distinguishes identical snippets |

---

## CI/CD integration

### GitHub Actions

```yaml
- name: SAST triage upload
  run: |
    swb-cli enrich ${{ github.workspace }}/report.sarif \
      --repo-root ${{ github.workspace }}
    swb-cli upload ${{ github.workspace }}/report.sarif \
      --server ${{ secrets.SWB_SERVER_URL }}
```

### GitLab CI

```yaml
sast-upload:
  stage: post-test
  script:
    - swb-cli enrich report.sarif --repo-root .
    - swb-cli upload report.sarif --server $SWB_SERVER_URL
  artifacts:
    paths:
      - "*.swbmeta.json"
```
