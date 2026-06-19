from __future__ import annotations

import logging
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json

logger = logging.getLogger(__name__)


def upload(args) -> int:
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)s %(message)s",
    )

    sarif_path = Path(args.sarif).resolve()
    if not sarif_path.exists():
        logger.error("SARIF file not found: %s", sarif_path)
        return 2

    # Find the swbmeta file
    if args.meta:
        meta_path = Path(args.meta).resolve()
    else:
        meta_path = Path(str(sarif_path) + ".swbmeta.json")

    if not meta_path.exists():
        logger.error(
            "swbmeta file not found: %s\n"
            "Run `swb-cli enrich %s` first, or pass --meta <path>",
            meta_path, sarif_path,
        )
        return 2

    server = args.server.rstrip("/")
    url = f"{server}/api/v1/runs"
    logger.info("Uploading %s → %s", sarif_path.name, url)

    sarif_bytes = sarif_path.read_bytes()
    meta_bytes = meta_path.read_bytes()

    # Build multipart/form-data manually
    boundary = "swbcli_boundary_" + _hex_token()
    body_parts: list[bytes] = []

    body_parts.append(_form_file(boundary, "sarif", sarif_path.name, sarif_bytes, "application/json"))
    body_parts.append(_form_file(boundary, "meta", meta_path.name, meta_bytes, "application/json"))
    body_parts.append(f"--{boundary}--\r\n".encode())

    body = b"".join(body_parts)
    content_type = f"multipart/form-data; boundary={boundary}"

    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", content_type)

    try:
        with urlopen(req, timeout=60) as resp:
            resp_body = resp.read()
            result = json.loads(resp_body)
    except HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        logger.error("Server returned %d: %s", exc.code, body_text)
        return 1
    except URLError as exc:
        logger.error("Connection failed: %s\nIs the server running at %s?", exc.reason, server)
        return 1
    except Exception as exc:
        logger.error("Upload failed: %s", exc)
        return 1

    run_id = result.get("run_id", "?")
    project_id = result.get("project_id", "?")
    finding_count = result.get("finding_count", 0)
    deduplicated = result.get("deduplicated", False)
    counts = result.get("counts", {})

    if deduplicated:
        uploaded_at = result.get("uploaded_at", "")
        when = f" (загружен {uploaded_at.replace('T', ' ')[:16]})" if uploaded_at else ""
        logger.warning(
            "Этот файл уже был загружен ранее%s — повторный импорт пропущен.\n"
            "  run_id  : %s\n"
            "  web     : %s/projects/%s/runs/%s",
            when, run_id, server, project_id, run_id,
        )
    else:
        logger.info("Upload successful!")
        logger.info("  project : %s", project_id)
        logger.info("  run_id  : %s", run_id)
        logger.info("  findings: %d  (crit=%s high=%s med=%s low=%s note=%s)",
                    finding_count,
                    counts.get("critical", 0),
                    counts.get("high", 0),
                    counts.get("medium", 0),
                    counts.get("low", 0),
                    counts.get("note", 0),
        )
        logger.info("  web     : %s/projects/%s/runs/%s", server, project_id, run_id)

    return 0


def _form_file(boundary: str, field: str, filename: str, data: bytes, mime: str) -> bytes:
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: {mime}\r\n"
        f"\r\n"
    ).encode()
    return header + data + b"\r\n"


def _hex_token() -> str:
    import os
    return os.urandom(8).hex()
