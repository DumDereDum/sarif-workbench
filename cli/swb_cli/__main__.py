from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="swb-cli",
        description="SARIF Workbench CLI — enriches SARIF reports with metadata sidecars",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    _add_enrich_parser(sub)
    _add_upload_parser(sub)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "enrich":
        from swb_cli.commands.enrich import enrich
        sys.exit(enrich(args))

    if args.command == "upload":
        from swb_cli.commands.upload import upload
        sys.exit(upload(args))


def _add_enrich_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "enrich",
        help="Enrich a SARIF file with a swbmeta sidecar",
        description=(
            "Reads a SARIF file, extracts findings metadata, and writes a "
            "<input>.swbmeta.json sidecar. The original SARIF is never modified."
        ),
    )
    p.add_argument("sarif", metavar="PATH", help="Path to SARIF file")
    p.add_argument("--out", metavar="PATH", help="Output path (default: <input>.swbmeta.json)")
    p.add_argument("--repo-root", metavar="PATH", help="Source tree root for git and path resolution")
    p.add_argument(
        "--context-policy",
        choices=["none", "line", "lines", "function"],
        default="lines",
        metavar="POLICY",
        help="How much source code to embed: none|line|lines|function (default: lines)",
    )
    p.add_argument(
        "--context-lines",
        type=int,
        default=5,
        metavar="N",
        help="Lines of context for --context-policy=lines (default: 5)",
    )
    p.add_argument("--no-git", action="store_true", help="Skip git metadata collection")
    p.add_argument(
        "--fail-on-missing-source",
        action="store_true",
        help="Exit with error if a source file is not found",
    )
    p.add_argument(
        "--log-level",
        choices=["error", "warn", "info", "debug"],
        default="info",
        metavar="LEVEL",
        help="Logging verbosity (default: info)",
    )


def _add_upload_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "upload",
        help="Upload a SARIF + swbmeta pair to the server",
        description=(
            "Sends <sarif> and its <sarif>.swbmeta.json sidecar to the SARIF Workbench server. "
            "Run `swb-cli enrich` first to generate the sidecar."
        ),
    )
    p.add_argument("sarif", metavar="PATH", help="Path to SARIF file")
    p.add_argument(
        "--meta",
        metavar="PATH",
        help="Path to swbmeta file (default: <sarif>.swbmeta.json)",
    )
    p.add_argument(
        "--server",
        metavar="URL",
        default="http://localhost:8000",
        help="Server base URL (default: http://localhost:8000)",
    )
    p.add_argument(
        "--log-level",
        choices=["error", "warn", "info", "debug"],
        default="info",
        metavar="LEVEL",
        help="Logging verbosity (default: info)",
    )


if __name__ == "__main__":
    main()
