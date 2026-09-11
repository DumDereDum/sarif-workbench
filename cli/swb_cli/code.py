from __future__ import annotations

import logging
import os
from pathlib import Path

from swb_cli.swbmeta import CodeSnippet

logger = logging.getLogger(__name__)

_DEFAULT_MAX_SOURCE_MB = 10


def _max_source_bytes() -> int:
    return int(os.environ.get("SWB_MAX_SOURCE_MB", _DEFAULT_MAX_SOURCE_MB)) * 1024 * 1024

_EXT_TO_LANG: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".jsx":  "javascript",
    ".tsx":  "typescript",
    ".c":    "c",
    ".h":    "c",
    ".cpp":  "cpp",
    ".cc":   "cpp",
    ".cxx":  "cpp",
    ".hpp":  "cpp",
    ".java": "java",
    ".go":   "go",
    ".cs":   "csharp",
    ".rb":   "ruby",
    ".rs":   "rust",
    ".kt":   "kotlin",
    ".php":  "php",
    ".swift":"swift",
}


def detect_lang(uri: str) -> str | None:
    return _EXT_TO_LANG.get(Path(uri).suffix.lower())


def resolve_under_root(source_root: Path, uri: str) -> Path | None:
    """Resolve a SARIF ``uri`` against ``source_root``, rejecting escapes.

    SARIF files are untrusted input: a crafted ``uri`` (absolute path,
    ``../`` traversal, or a symlink pointing outside the repo) must not let
    enrich read arbitrary host files. Returns the resolved path when it stays
    under ``source_root``, otherwise logs a warning and returns None.
    """
    root = source_root.resolve()
    try:
        candidate = (root / uri).resolve()
    except (OSError, RuntimeError) as exc:  # symlink loop, path too long, …
        logger.warning("Cannot resolve uri %r under source root: %s; skipping", uri, exc)
        return None
    if not candidate.is_relative_to(root):
        logger.warning("uri %r resolves outside source root %s; skipping", uri, root)
        return None
    return candidate


def read_source_lines(source_root: Path, uri: str) -> list[str] | None:
    """Read a source file referenced by a SARIF ``uri`` as a list of lines.

    Applies the same safety rails as snippet extraction: the path must
    resolve under ``source_root`` (T-01) and the file must not exceed the
    source size limit (T-02). Returns None when unreadable.
    """
    file_path = resolve_under_root(source_root, uri)
    if file_path is None:
        return None
    if not file_path.exists():
        logger.warning(
            "Source file for uri %r not found at %s (source_root=%s); skipping snippet",
            uri, file_path, source_root,
        )
        return None

    # Size cap: a bloated file referenced by an untrusted uri must not be read
    # into memory at all — degrade to None, same as T-01.
    max_bytes = _max_source_bytes()
    size = file_path.stat().st_size
    if size > max_bytes:
        logger.warning(
            "File %r is %d bytes, over the %d MB source limit (SWB_MAX_SOURCE_MB); skipping snippet",
            uri,
            size,
            max_bytes // (1024 * 1024),
        )
        return None

    return file_path.read_text(encoding="utf-8", errors="replace").splitlines()


def embedded_source_lines(uri: str, text: str) -> list[str] | None:
    """Lines of a file the tool embedded in the report itself.

    The size cap of T-02 applies here too: the report is untrusted input, and
    a multi-megabyte blob in `contents.text` must not be split into memory
    just because it arrived inside the SARIF rather than from disk.
    """
    if not text.strip():
        # Svace writes `contents: {"text": ""}` for every artifact when the
        # export ran without contents. An empty string is the absence of the
        # source, not a zero-line file: treated as text it would yield a blank
        # snippet and a content fingerprint over an empty window — the same
        # hash for every finding in the file.
        return None

    max_bytes = _max_source_bytes()
    size = len(text.encode("utf-8", errors="replace"))
    if size > max_bytes:
        logger.warning(
            "Embedded contents for uri %r are %d bytes, over the %d MB source "
            "limit (SWB_MAX_SOURCE_MB); skipping snippet",
            uri,
            size,
            max_bytes // (1024 * 1024),
        )
        return None
    return text.splitlines()


def extract_snippet(
    source_root: Path | None,
    uri: str,
    start_line: int,
    end_line: int | None,
    context_policy: str,
    context_lines: int,
    lines: list[str] | None = None,
) -> CodeSnippet | None:
    """Cut the snippet around a finding out of the source.

    ``lines`` is the source when the caller has already resolved it — from
    disk, or from `artifacts[].contents.text` when the file is not on this
    machine. Without it the file is read from ``source_root``, which is then
    required.
    """
    if context_policy == "none":
        return None

    if lines is None:
        if source_root is None:
            return None
        lines = read_source_lines(source_root, uri)
    if lines is None:
        return None
    total = len(lines)

    hot_start = start_line
    hot_end = end_line or start_line

    if context_policy == "line":
        snip_start = hot_start
        snip_end = hot_end
    elif context_policy == "lines":
        snip_start = max(1, hot_start - context_lines)
        snip_end = min(total, hot_end + context_lines)
    elif context_policy == "function":
        # tree-sitter not yet implemented — fall back to lines
        snip_start = max(1, hot_start - context_lines)
        snip_end = min(total, hot_end + context_lines)
    else:
        return None

    snippet = "\n".join(lines[snip_start - 1 : snip_end])
    return CodeSnippet(
        lang=detect_lang(uri),
        start_line=snip_start,
        end_line=snip_end,
        snippet=snippet,
    )
