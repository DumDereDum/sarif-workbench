# Contributing to SARIF Workbench

## Setup

See the [README quick start](README.md#quick-start) to get the stack running locally.

## The one rule: all changes go through a Pull Request

Direct pushes and commits to `main` are not allowed — every change, however small, lands via a
PR. This applies to everyone, including maintainers.

## Running tests

- Server + CLI: `uv run pytest tests/ -v` (scope to `tests/cli` or `tests/server` if you only
  touched one side). New server tests go in `tests/server/`, new fixtures in `tests/data/`.
- Web: `npm --prefix web run test` (unit tests, `node:test`) and `npm --prefix web run build`
  (typecheck + build — what CI runs). New lib-level tests go next to the source as `*.test.ts`.

## Definition of done

Before opening a PR, run through the checklist in
[`.claude/skills/project-conventions/SKILL.md`](.claude/skills/project-conventions/SKILL.md):
tests pass, new behavior is covered by a test, `ruff`/`mypy` are clean, the web build passes if
you touched `web/`, the original SARIF stays byte-for-byte untouched, and no new outbound network
call was added without an explicit opt-in.

## Opening a PR

1. Branch off `main`: `feat/short-description` or `fix/short-description`.
2. Make your change and run `uv run pytest tests/ -v`, `uv run ruff check .`,
   `uv run mypy cli/swb_cli server/swb_server`, and — if you touched `web/` —
   `npm --prefix web run build`. All must pass locally.
3. Push and open a PR against `main`; fill in the template.
4. CI must be green.
5. Request review — at least one approval is required before merging.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before
participating.

Questions: open a GitHub Issue with label `question`.
