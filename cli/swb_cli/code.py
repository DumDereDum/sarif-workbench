from __future__ import annotations

from pathlib import Path

from swb_cli.swbmeta import CodeSnippet

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


def extract_snippet(
    repo_root: Path,
    uri: str,
    start_line: int,
    end_line: int | None,
    context_policy: str,
    context_lines: int,
) -> CodeSnippet | None:
    if context_policy == "none":
        return None

    file_path = repo_root / uri
    if not file_path.exists():
        return None

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
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
