from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from swb_cli.swbmeta import (
    CodeFlow,
    CodeFlowStep,
    ContextPolicy,
    ExtraLocation,
    Finding,
    GitInfo,
    Locator,
    Provenance,
    RelatedLocation,
    Region,
    SourceSarif,
    SwbMeta,
    ThreadFlow,
)

from swb_cli.sarif.parser import parse_sarif
from swb_cli.code import extract_snippet, read_source_lines, resolve_under_root
from swb_cli.fingerprints import (
    IdentitySource,
    assign_swb_ids,
    build_fingerprints,
    normalize_uri,
)

VERSION = "0.1.0"
logger = logging.getLogger(__name__)


def enrich(args) -> int:
    """Entry point for `swb-cli enrich`. Returns a process exit code."""
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)s %(message)s",
    )

    sarif_path = Path(args.sarif).resolve()
    if not sarif_path.exists():
        logger.error("File not found: %s", sarif_path)
        return 2

    out_path = (
        Path(args.out).resolve()
        if args.out
        else sarif_path.with_suffix(sarif_path.suffix + ".swbmeta.json")
    )

    if out_path == sarif_path:
        logger.error(
            "Refusing to write --out to the same path as the input SARIF file: %s. "
            "This would overwrite the original report; choose a different --out path.",
            sarif_path,
        )
        return 2

    logger.info("Reading %s", sarif_path)
    sarif_bytes = sarif_path.read_bytes()
    sha256 = hashlib.sha256(sarif_bytes).hexdigest()

    try:
        runs = parse_sarif(sarif_path)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        logger.error("Failed to parse SARIF: %s", exc)
        return 1

    if not runs:
        logger.warning("No runs found in SARIF file")

    first_run = runs[0] if runs else None
    repo_root = (
        Path(args.repo_root).resolve()
        if args.repo_root
        else _find_repo_root(sarif_path)
    )

    provenance = _build_provenance(
        tool_name=first_run.tool.name if first_run else "unknown",
        tool_version=first_run.tool.version if first_run else None,
        repo_root=repo_root,
        no_git=args.no_git,
    )

    context_policy = ContextPolicy(
        mode=args.context_policy,
        lines=args.context_lines if args.context_policy == "lines" else None,
    )

    findings, skipped_no_locations = _build_findings(
        runs,
        repo_root=repo_root,
        context_policy=args.context_policy,
        context_lines=args.context_lines,
        no_git=args.no_git,
    )

    meta = SwbMeta(
        generated_by=f"swb-cli {VERSION}",
        generated_at=datetime.now(timezone.utc).isoformat(),
        source_sarif=SourceSarif(
            filename=sarif_path.name,
            sha256=sha256,
            size_bytes=len(sarif_bytes),
        ),
        provenance=provenance,
        context_policy=context_policy,
        findings=findings,
    )

    out_path.write_text(
        meta.model_dump_json(by_alias=True, indent=2),
        encoding="utf-8",
    )
    # T-36: skipped-no-locations results are counted (not just individually
    # warned about) so a scan dominated by locationless results doesn't
    # quietly vanish from triage without a visible trace anywhere.
    logger.info(
        "Wrote %s (%d findings, %d skipped: no locations)",
        out_path, len(findings), skipped_no_locations,
    )
    return 0


def _build_findings(
    runs,
    repo_root: Path | None,
    context_policy: str,
    context_lines: int,
    no_git: bool,
) -> tuple[list[Finding], int]:
    # Two passes (ADR 0001 §2): first gather every finding with its base
    # fingerprint material, then let assign_swb_ids number duplicates
    # deterministically — occurrence must not depend on result order.
    prepared: list[tuple] = []
    identity_sources: list[IdentitySource] = []
    skipped_no_locations = 0

    for run in runs:
        for result in run.results:
            if not result.locations:
                # ADR 0001 §8: a result with no locations has no primary
                # location to build an identity from — the CLI still cannot
                # emit a finding for it (giving it one would need a new
                # fingerprint algorithm version, swb-fp/3). T-36: this used
                # to be a silent `continue` with no trace anywhere; now it's
                # logged and counted so it doesn't vanish without a warning.
                skipped_no_locations += 1
                logger.warning(
                    "Result run=%d result=%d rule=%r has no locations; "
                    "skipping (no identity can be built for it, see ADR 0001 §8)",
                    run.index, result.result_index, result.rule_id,
                )
                continue
            loc = result.locations[0]

            norm_uri = normalize_uri(
                loc.uri, loc.uri_base_id, run.original_uri_base_ids, repo_root,
            )
            # Source window for the content fingerprint (ADR 0001 §1 level 2);
            # read via norm_uri so uriBaseId-relative paths resolve too.
            source_lines = (
                read_source_lines(repo_root, norm_uri)
                if repo_root and norm_uri
                else None
            )

            code = None
            git = None
            if repo_root:
                code = extract_snippet(
                    repo_root,
                    loc.uri,
                    loc.region.start_line,
                    loc.region.end_line,
                    context_policy,
                    context_lines,
                )
                if not no_git:
                    git = _get_git_info(repo_root, loc.uri, loc.region.start_line, loc.region.end_line)

            fingerprints = build_fingerprints(
                tool_name=run.tool.name,
                rule_id=result.rule_id,
                norm_uri=norm_uri,
                start_line=loc.region.start_line,
                end_line=loc.region.end_line,
                tool_fingerprints=result.fingerprints,
                partial_fingerprints=result.partial_fingerprints,
                source_lines=source_lines,
            )

            identity_sources.append(IdentitySource(
                tool_name=run.tool.name,
                rule_id=result.rule_id,
                norm_uri=norm_uri,
                start_line=loc.region.start_line,
                start_column=loc.region.start_column,
                message=result.message,
                fingerprints=fingerprints,
            ))
            # T-39 (ADR 0001 §8): locations[1:], relatedLocations and
            # codeFlows are payload, not identity material — they ride along
            # unchanged and never touch identity_sources/fingerprints above.
            extra_locations = _convert_extra_locations(result.locations[1:])
            related_locations = _convert_related_locations(result.related_locations)
            code_flows = _convert_code_flows(result.code_flows)
            prepared.append((
                run, result, loc, norm_uri, fingerprints, code, git,
                extra_locations, related_locations, code_flows,
            ))

    swb_ids = assign_swb_ids(identity_sources)

    findings = []
    for (
        (run, result, loc, norm_uri, fingerprints, code, git,
         extra_locations, related_locations, code_flows),
        (swb_id, occurrence),
    ) in zip(prepared, swb_ids):
        findings.append(Finding(
            swb_id=swb_id,
            occurrence=occurrence,
            locator=Locator(
                run=run.index,
                result=result.result_index,
                rule_id=result.rule_id,
                uri=loc.uri,
                norm_uri=norm_uri,
                region=Region(
                    start_line=loc.region.start_line,
                    end_line=loc.region.end_line,
                    start_column=loc.region.start_column,
                ),
            ),
            fingerprints=fingerprints,
            code=code,
            git=git,
            extra_locations=extra_locations,
            related_locations=related_locations,
            code_flows=code_flows,
        ))

    return findings, skipped_no_locations


def _convert_extra_locations(locations) -> list[ExtraLocation]:
    """`result.locations[1:]` -> swbmeta payload (ADR 0001 §8: not identity)."""
    return [
        ExtraLocation(
            uri=loc.uri,
            region=Region(
                start_line=loc.region.start_line,
                end_line=loc.region.end_line,
                start_column=loc.region.start_column,
            ),
        )
        for loc in locations
    ]


def _convert_related_locations(related_locations) -> list[RelatedLocation]:
    """`result.relatedLocations` -> swbmeta payload (ADR 0001 §8: not identity)."""
    return [
        RelatedLocation(
            uri=loc.uri,
            region=Region(
                start_line=loc.region.start_line,
                end_line=loc.region.end_line,
                start_column=loc.region.start_column,
            ),
            message=loc.message or None,
        )
        for loc in related_locations
    ]


def _convert_code_flows(code_flows) -> list[CodeFlow]:
    """`result.codeFlows` -> swbmeta payload, structure preserved (T-39)."""
    return [
        CodeFlow(
            thread_flows=[
                ThreadFlow(
                    steps=[
                        CodeFlowStep(uri=step.uri, line=step.line, message=step.message or None)
                        for step in tf.steps
                    ]
                )
                for tf in cf.thread_flows
            ]
        )
        for cf in code_flows
    ]


def _build_provenance(
    tool_name: str,
    tool_version: str | None,
    repo_root: Path | None,
    no_git: bool,
) -> Provenance:
    repo = repo_root.name if repo_root else "unknown"
    branch = "unknown"
    commit = "0" * 40
    commit_short = "0000000"
    is_dirty = False
    scanned_at = datetime.now(timezone.utc).isoformat()

    if not no_git and repo_root:
        try:
            commit = _git(repo_root, ["rev-parse", "HEAD"])
            commit_short = commit[:7]
            branch = _git(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"])
            dirty_out = _git(repo_root, ["status", "--porcelain"])
            is_dirty = bool(dirty_out)
        except Exception as exc:
            logger.debug("Git info unavailable: %s", exc)

    return Provenance(
        repo=repo,
        branch=branch,
        commit=commit,
        commit_short=commit_short,
        is_dirty=is_dirty,
        tool=tool_name,
        tool_version=tool_version or "unknown",
        scanned_at=scanned_at,
    )


def _get_git_info(
    repo_root: Path,
    uri: str,
    start_line: int,
    end_line: int | None,
) -> GitInfo | None:
    file_path = resolve_under_root(repo_root, uri)
    if file_path is None or not file_path.exists():
        return None
    try:
        blob_sha = _git(repo_root, ["hash-object", str(file_path)])
        end = end_line or start_line
        blame_out = _git(
            repo_root,
            ["blame", "-L", f"{start_line},{end}", "--porcelain", str(file_path)],
        )
        blame_commit = blame_out[:40] if blame_out else None
        last_changed = None
        if blame_commit:
            last_changed = _git(repo_root, ["show", "-s", "--format=%as", blame_commit])
        return GitInfo(blob_sha=blob_sha, blame_commit=blame_commit, last_changed=last_changed)
    except Exception as exc:
        logger.debug("Git info for %s unavailable: %s", uri, exc)
        return None


def _git(cwd: Path, git_args: list[str]) -> str:
    result = subprocess.run(
        ["git", *git_args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _find_repo_root(start: Path) -> Path | None:
    for parent in [start, *start.parents]:
        if (parent / ".git").exists():
            return parent
    return None
