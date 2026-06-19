# Quick Start

Get SARIF Workbench running in under 5 minutes.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin)
- A SARIF 2.1.0 file from your static analysis tool

!!! tip "Don't have a SARIF file yet?"
    The repository includes a sample C++ project with a pre-generated SARIF. Run `make sample` to try it.

---

## Step 1 — Start the server

```bash
git clone https://github.com/DumDereDum/sarif-workbench
cd sarif-workbench
docker compose up
```

This starts:

| Service | URL | Description |
|---|---|---|
| Web UI | http://localhost:5173 | React interface |
| API server | http://localhost:8000 | FastAPI backend |

The first run downloads images and may take 1–2 minutes.

---

## Step 2 — Install swb-cli

The CLI runs **on the machine with your source code** (CI runner or developer machine), not inside Docker.

=== "uv (recommended for development)"

    ```bash
    # Install uv if you don't have it
    curl -Ls https://astral.sh/uv/install.sh | sh

    # From the repo root
    uv sync
    uv run swb-cli --help
    ```

=== "PyInstaller binary"

    ```bash
    uv sync
    uv run pyinstaller cli/swb_cli.spec --distpath dist/
    sudo cp dist/swb-cli /usr/local/bin/
    swb-cli --help
    ```

---

## Step 3 — Enrich and upload a SARIF report

```bash
# Enrich: adds git metadata, code snippets, and fingerprints
swb-cli enrich path/to/report.sarif --repo-root path/to/source

# Upload: sends the SARIF + sidecar to the server
swb-cli upload path/to/report.sarif --server http://localhost:8000
```

After a successful upload:

```
INFO  Upload successful!
INFO    project : my-service
INFO    run_id  : r-a1b2c3d4e5f6
INFO    findings: 42  (crit=2 high=11 med=19 low=8 note=2)
INFO    web     : http://localhost:8000/projects/my-service/runs/r-a1b2c3d4e5f6
```

Open the printed URL (or navigate to **http://localhost:5173**) to see your findings.

---

## Try the built-in sample

The repository ships with a C++ sample application with known vulnerabilities:

```bash
make sample
```

This runs `enrich` + `upload` on `samples/cpp-bank/report.sarif` and prints the UI URL.

---

## Next steps

- [CLI Reference](cli.md) — all flags, output format, exit codes
- [Deployment Guide](deployment.md) — production setup, environment variables
- [API Reference](../api/reference.md) — REST endpoints for integration
