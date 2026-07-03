"""Prod-compose secrets (T-06): no hardcoded default credentials for Postgres/MinIO.

Regression coverage for the finding that docker-compose.prod.yml shipped predictable
credentials (`minioadmin`/`minioadmin` for MinIO, `swb`/`swb` for Postgres) for the
optional Postgres/MinIO services — the first thing a security auditor would flag.
Sensitive variables must be required from the environment (`${VAR:?...}` / `${VAR?...}`),
with no literal default, and `.env.example` must document every variable the compose
file actually references.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMPOSE_PATH = REPO_ROOT / "docker-compose.prod.yml"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"

# Credentials that must not have a baked-in default value.
SENSITIVE_VARS = [
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
]

# Literal secret values the old compose file shipped; must never reappear unquoted.
BANNED_LITERALS = ["minioadmin"]

VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)")


def _compose_text() -> str:
    return COMPOSE_PATH.read_text(encoding="utf-8")


def _env_example_text() -> str:
    return ENV_EXAMPLE_PATH.read_text(encoding="utf-8")


def _required_syntax_re(var: str) -> re.Pattern[str]:
    # ${VAR:?message} or ${VAR?message} — fails hard if VAR is unset (or empty, for :?).
    return re.compile(r"\$\{" + re.escape(var) + r"(?::\?|\?)[^}]*\}")


def _default_syntax_re(var: str) -> re.Pattern[str]:
    # ${VAR:-something} — silently falls back to a default, which is exactly what
    # must NOT happen for a secret.
    return re.compile(r"\$\{" + re.escape(var) + r":-[^}]+\}")


def test_compose_file_is_valid_yaml():
    doc = yaml.safe_load(_compose_text())
    assert isinstance(doc, dict)
    assert "services" in doc
    for name in ("server", "web", "postgres", "minio"):
        assert name in doc["services"], f"сервис {name} исчез из docker-compose.prod.yml"


def test_no_hardcoded_default_credential_literals():
    text = _compose_text()
    for literal in BANNED_LITERALS:
        assert literal not in text, (
            f"docker-compose.prod.yml всё ещё содержит дефолтный секрет {literal!r}"
        )

    doc = yaml.safe_load(text)
    postgres_env = doc["services"]["postgres"]["environment"]
    minio_env = doc["services"]["minio"]["environment"]

    # Значения должны быть ссылками на переменные окружения, а не литералами.
    assert str(postgres_env["POSTGRES_USER"]).startswith("${POSTGRES_USER")
    assert str(postgres_env["POSTGRES_PASSWORD"]).startswith("${POSTGRES_PASSWORD")
    assert str(minio_env["MINIO_ROOT_USER"]).startswith("${MINIO_ROOT_USER")
    assert str(minio_env["MINIO_ROOT_PASSWORD"]).startswith("${MINIO_ROOT_PASSWORD")

    # POSTGRES_PASSWORD не должен быть буквальным "swb" (старый дефолт), даже
    # если бы кто-то завернул его в интерполяцию с фолбэком.
    assert postgres_env["POSTGRES_PASSWORD"] != "swb"


def test_sensitive_vars_use_required_syntax_without_default():
    text = _compose_text()
    for var in SENSITIVE_VARS:
        assert _required_syntax_re(var).search(text), (
            f"{var} должен использовать required-синтаксис ${{{var}:?сообщение}} "
            "(или ${VAR?...}) — без него docker compose должен падать явно, а не "
            "подставлять дефолт"
        )
        assert not _default_syntax_re(var).search(text), (
            f"{var} использует ${{{var}:-default}} с непустым дефолтом — "
            "это тихо возвращает дефолтный секрет вместо явной ошибки"
        )


def test_env_example_documents_every_compose_variable():
    compose_vars = set(VAR_REF_RE.findall(_compose_text()))
    assert compose_vars, "в docker-compose.prod.yml не найдено ни одной ${VAR} — подозрительно"

    env_example_text = _env_example_text()
    # Имя переменной в .env.example — то, что стоит перед "=" в начале строки.
    documented_vars = set(re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=", env_example_text))

    missing = compose_vars - documented_vars
    assert not missing, (
        ".env.example не документирует переменные, используемые в "
        f"docker-compose.prod.yml: {sorted(missing)}"
    )


def test_env_example_exists_and_has_no_banned_literal_values():
    assert ENV_EXAMPLE_PATH.exists(), ".env.example отсутствует в корне репозитория"
    text = _env_example_text()
    for literal in BANNED_LITERALS:
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue  # закомментированные примеры конфигурации — не действующее значение
            assert literal not in line, (
                f".env.example содержит незакомментированное значение {literal!r} "
                f"в строке: {line!r}"
            )
