# Contributing to SARIF Workbench

## Setup

See the [README quick start](README.md#quick-start) to get the stack running locally.

## The one rule: all changes go through a Pull Request

Direct pushes and commits to `main` are not allowed — every change, however small, lands via a
PR. This applies to everyone, including maintainers.

## Opening a PR

1. Branch off `main`: `feat/short-description` or `fix/short-description`.
2. Make your change and run `uv run pytest tests/ -v` — it must pass locally.
3. Push and open a PR against `main`; fill in the template.
4. CI must be green.
5. Request review — at least one approval is required before merging.

Questions: open a GitHub Issue with label `question`.
