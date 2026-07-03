"""Fingerprint extraction and normalization per ADR 0001 (swb-fp/2).

Implements §1 (level chain materials, swb_id), §2 (deterministic
occurrence), §3 (norm_uri), §4 (norm_window) of
roadmap/adr/0001-identity-and-verdict.md.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from swb_cli.swbmeta import Fingerprints

ALGO = "swb-fp/2"
_SEP = "\x00"
_MAX_WINDOW_LINES = 10   # §4: window capped at 10 lines
_CONTEXT_PAD = 2         # §4: context fingerprint = window ±2 lines


# ── norm_uri (ADR §3) ─────────────────────────────────────────────────────────

def normalize_uri(
    uri: str,
    uri_base_id: str | None,
    original_uri_base_ids: dict,
    repo_root: Path | None,
) -> str:
    """Normalize a SARIF artifact uri per ADR 0001 §3 (5 steps)."""
    # 1. resolve uriBaseId via originalUriBaseIds (recursively), prefixing left
    full = _resolve_base(uri, uri_base_id, original_uri_base_ids, set())
    # 2. drop file:// scheme, percent-decode, backslashes -> slashes
    if full.lower().startswith("file://"):
        full = full[len("file://"):]
    full = unquote(full).replace("\\", "/")
    # 3. lexical normalization: drop "./", collapse ".." without escaping
    #    the root of the string (posixpath.normpath keeps leading "..")
    norm = posixpath.normpath(full) if full else ""
    if norm == ".":
        norm = ""
    # 4. absolute path inside a known repo_root -> relative to repo_root
    if norm.startswith("/") and repo_root is not None:
        root = repo_root.resolve().as_posix().rstrip("/")
        if norm == root or norm.startswith(root + "/"):
            norm = norm[len(root):]
    # 5. POSIX path without a leading "/"
    return norm.lstrip("/")


def _resolve_base(
    uri: str,
    base_id: str | None,
    bases: dict,
    seen: set[str],
) -> str:
    if not base_id or base_id in seen:  # missing or cyclic base: tolerate, keep uri
        return uri
    base = bases.get(base_id)
    if not isinstance(base, dict):
        return uri
    prefix = _resolve_base(
        str(base.get("uri", "")), base.get("uriBaseId"), bases, seen | {base_id}
    )
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    return prefix + uri


# ── norm_window (ADR §4) ──────────────────────────────────────────────────────

def normalize_window(
    lines: list[str],
    start_line: int,
    end_line: int | None,
    pad: int = 0,
) -> str:
    """Normalized window of source lines per ADR 0001 §4.

    Window is [start_line, end_line] (1-based, inclusive), capped at
    10 lines, optionally padded by ``pad`` lines on each side (context
    fingerprint). Each line has whitespace runs collapsed to single spaces;
    an empty result is valid material.
    """
    start = start_line
    end = end_line if end_line is not None and end_line >= start else start
    end = min(end, start + _MAX_WINDOW_LINES - 1)
    start = max(1, start - pad)
    end = min(len(lines), end + pad)
    window = lines[start - 1:end] if start <= len(lines) else []
    return "\n".join(" ".join(line.split()) for line in window)


# ── fingerprint assembly (ADR §1/§5) ─────────────────────────────────────────

def content_hash(tool: str, rule_id: str, norm_uri: str, norm_window: str) -> str:
    """sha256 hex of the level-2 material (ADR §1) — no line numbers."""
    material = _SEP.join([ALGO, "content", tool, rule_id, norm_uri, norm_window])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_fingerprints(
    tool_name: str,
    rule_id: str,
    norm_uri: str,
    start_line: int,
    end_line: int | None,
    tool_fingerprints: dict[str, str],
    partial_fingerprints: dict[str, str],
    source_lines: list[str] | None,
) -> Fingerprints:
    """Assemble the swbmeta v2 Fingerprints block per ADR 0001 §1/§5.

    Level priority is strict: tool fingerprints, else content hash, else
    legacy. content/context are computed whenever the source is readable —
    even at level "tool" — for diagnostics and future re-matching.
    """
    tool = tool_name.lower()

    fp_dict: dict[str, str] | None = None
    tool_kind = None
    if tool_fingerprints:
        fp_dict, tool_kind = tool_fingerprints, "fingerprints"
    elif partial_fingerprints:
        fp_dict, tool_kind = partial_fingerprints, "partialFingerprints"

    content = context = None
    if source_lines is not None:
        window = normalize_window(source_lines, start_line, end_line)
        ctx_window = normalize_window(source_lines, start_line, end_line, pad=_CONTEXT_PAD)
        content = content_hash(tool, rule_id, norm_uri, window)
        context = content_hash(tool, rule_id, norm_uri, ctx_window)

    if fp_dict is not None:
        level = "tool"
    elif content is not None:
        level = "content"
    else:
        level = "legacy"

    return Fingerprints(
        algo=ALGO,
        level=level,
        rule=rule_id,
        tool=fp_dict,
        tool_kind=tool_kind,
        content=content,
        context=context,
    )


# ── swb_id + occurrence (ADR §1/§2) ──────────────────────────────────────────

_LEVEL_TAGS = {"tool": "t", "content": "c", "legacy": "l"}
_HASH_LEN = 24  # §1: sha256(material).hexdigest()[:24]


@dataclass(frozen=True)
class IdentitySource:
    """Per-finding inputs to swb_id: base material (§1) + tiebreak key (§2)."""
    tool_name: str
    rule_id: str
    norm_uri: str
    start_line: int
    start_column: int | None
    message: str
    fingerprints: Fingerprints


def _canonical_json(d: dict[str, str]) -> str:
    """§1 level 1: sorted keys, no spaces, ensure_ascii."""
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _base_hash(item: IdentitySource) -> str:
    """sha256 hex (truncated per §1) of the base-level material."""
    fp = item.fingerprints
    if fp.level == "content":
        # Level-2 hash is already computed by build_fingerprints (T-12).
        assert fp.content is not None
        return fp.content[:_HASH_LEN]
    tool = item.tool_name.lower()
    if fp.level == "tool":
        material = _SEP.join(
            [ALGO, "tool", tool, item.rule_id, _canonical_json(fp.tool or {})]
        )
    else:  # legacy
        material = _SEP.join(
            [ALGO, "legacy", tool, item.rule_id, item.norm_uri, str(item.start_line)]
        )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:_HASH_LEN]


def assign_swb_ids(items: list[IdentitySource]) -> list[tuple[str, int]]:
    """Compute (swb_id, occurrence) for every finding of one SARIF file.

    Findings sharing (level_tag, base hash) across all runs form a group
    (ADR §2); each group is sorted by (norm_uri, start_line,
    start_column or 0, sha256(message)) and numbered 0, 1, 2, … in that
    order. The sort is stable, so byte-identical duplicates keep file
    order. Result is aligned with the input order.
    """
    groups: dict[tuple[str, str], list[int]] = {}
    for i, item in enumerate(items):
        key = (_LEVEL_TAGS[item.fingerprints.level], _base_hash(item))
        groups.setdefault(key, []).append(i)

    out: list[tuple[str, int]] = [("", 0)] * len(items)
    for (tag, base), indices in groups.items():
        indices.sort(key=lambda i: (
            items[i].norm_uri,
            items[i].start_line,
            items[i].start_column or 0,
            hashlib.sha256(items[i].message.encode("utf-8")).hexdigest(),
        ))
        for occurrence, i in enumerate(indices):
            out[i] = (f"sw2:{tag}:{base}:{occurrence}", occurrence)
    return out
