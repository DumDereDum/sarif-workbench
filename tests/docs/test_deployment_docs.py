"""Deployment-doc drift (T-68): the MkDocs deployment guide must stay in sync with
docker-compose.prod.yml / .env.example.

T-06 removed the hardcoded Postgres/MinIO credentials from docker-compose.prod.yml and made
them `${VAR:?...}` (required, no default) — see tests/infra/test_prod_compose_secrets.py.
README.md was updated to match, but docs/guide/deployment.md and docs/ru/guide/deployment.md
(the MkDocs site) were left behind: no `cp .env.example .env` step before the production
compose command, and the "Environment variables" table didn't list the new required
variables at all. Someone following only the MkDocs guide (not README) would hit an
unexplained `docker compose` failure. These tests pin the fix and catch future drift: if a
new required (no-default) variable is added to docker-compose.prod.yml later, both deployment
guides must mention it too.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMPOSE_PATH = REPO_ROOT / "docker-compose.prod.yml"
EN_DOC = REPO_ROOT / "docs" / "guide" / "deployment.md"
RU_DOC = REPO_ROOT / "docs" / "ru" / "guide" / "deployment.md"
DEPLOYMENT_DOCS = (EN_DOC, RU_DOC)

# ${VAR:?message} or ${VAR?message} — same required-syntax pattern as
# tests/infra/test_prod_compose_secrets.py; source of truth for "no default" variables.
REQUIRED_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::\?|\?)[^}]*\}")

PROD_UP_CMD = "docker compose -f docker-compose.prod.yml up --build -d"
ENV_COPY_STEP = "cp .env.example .env"


def _compose_required_vars() -> set[str]:
    text = COMPOSE_PATH.read_text(encoding="utf-8")
    variables = set(REQUIRED_VAR_RE.findall(text))
    assert variables, (
        "docker-compose.prod.yml не содержит ни одной ${VAR:?...} — источник истины пуст, "
        "проверь регулярку или сам compose-файл"
    )
    return variables


def _doc_text(path: Path) -> str:
    assert path.exists(), f"{path} отсутствует"
    return path.read_text(encoding="utf-8")


def test_required_compose_vars_are_documented_in_both_deployment_guides():
    required = _compose_required_vars()
    for doc_path in DEPLOYMENT_DOCS:
        text = _doc_text(doc_path)
        missing = {var for var in required if var not in text}
        assert not missing, (
            f"{doc_path} не упоминает обязательные (без дефолта) переменные "
            f"docker-compose.prod.yml: {sorted(missing)}"
        )


def test_env_copy_step_precedes_prod_up_command_in_both_guides():
    for doc_path in DEPLOYMENT_DOCS:
        text = _doc_text(doc_path)
        assert PROD_UP_CMD in text, (
            f"{doc_path} не содержит команду запуска prod-стека {PROD_UP_CMD!r} — "
            "если команда изменилась, обнови и тест, и доку"
        )
        assert ENV_COPY_STEP in text, (
            f"{doc_path} не описывает шаг `{ENV_COPY_STEP}`"
        )

        # cp .env.example .env должен встречаться в тексте раньше самой команды up —
        # иначе читатель, копирующий команды по порядку сверху вниз, наткнётся на
        # padение docker compose до того, как дойдёт до объяснения (T-06 оставил
        # именно такой порядок: команда up шла раньше объяснения про .env).
        up_index = text.index(PROD_UP_CMD)
        cp_indices = [m.start() for m in re.finditer(re.escape(ENV_COPY_STEP), text)]
        assert any(idx < up_index for idx in cp_indices), (
            f"{doc_path}: `{ENV_COPY_STEP}` должен встречаться раньше команды "
            f"{PROD_UP_CMD!r} в тексте страницы, а не только в разделе ниже"
        )
