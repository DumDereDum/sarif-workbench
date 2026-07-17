"""README-честность (T-04): утверждения в README не должны опережать реальный код.

Регрессионные проверки на конкретные несоответствия, найденные при аудите:
- ссылка на несуществующий cli/swb_cli.spec;
- безусловные заявления про полный офлайн-режим;
- сравнение с baseline подано как готовое, хотя не реализовано;
- (T-42) облачные AI-провайдеры не должны подаваться как включённые без оговорок —
  README обязан отражать disabled-by-default/opt-in модель, а не "planned"
  (локальный провайдер — реальный дефолт с T-42, это больше не "planned");
- (T-67) число тестов протухало дважды (83 -> 151 -> 356) быстрее, чем кто-то
  вспоминал его обновить — README больше не называет конкретную цифру, тест не
  даёт её туда вернуть;
- режим `force_fp` должен быть упомянут в описании AI-триажа.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
README = REPO_ROOT / "README.md"


def _readme_text() -> str:
    return README.read_text(encoding="utf-8")


def test_no_reference_to_nonexistent_pyinstaller_spec():
    text = _readme_text()
    assert "swb_cli.spec" not in text, (
        "README ссылается на cli/swb_cli.spec, которого нет в репозитории"
    )
    assert not (REPO_ROOT / "cli" / "swb_cli.spec").exists(), (
        "cli/swb_cli.spec появился в репозитории — README можно снова ссылаться на него, "
        "но тогда обнови этот тест"
    )


def test_no_unconditional_offline_claims():
    text = _readme_text()
    # Старые безусловные формулировки, обещавшие полный офлайн-режим, должны исчезнуть.
    banned_phrases = [
        "Works fully offline — built for air-gapped",
        "All components run offline — no external network calls required",
    ]
    for phrase in banned_phrases:
        assert phrase not in text, f"README всё ещё содержит безусловное заявление: {phrase!r}"

    # Если слово "offline" упоминается, оно должно соседствовать с оговоркой
    # (planned / roadmap / DeepSeek) — то есть не быть безусловным обещанием.
    for line in text.splitlines():
        if "offline" in line.lower():
            assert any(
                marker in line for marker in ("planned", "Roadmap", "DeepSeek", "roadmap")
            ), f"строка про offline без оговорки о текущем состоянии: {line!r}"


def test_baseline_comparison_marked_planned():
    text = _readme_text()
    for line in text.splitlines():
        if "Run comparison against a baseline" in line:
            assert "planned" in line.lower(), f"baseline-сравнение не помечено planned: {line!r}"


def test_cloud_providers_marked_disabled_by_default_not_planned():
    """T-42: локальный AI-провайдер (Ollama) — реальный дефолт из коробки, а не
    "planned" — README не должен больше обещать локальные провайдеры как будущее.
    Облачные провайдеры (DeepSeek и т.п.) поддержаны тем же реестром, но должны
    быть явно описаны как disabled-by-default / opt-in, не как готовые без оговорок."""
    text = _readme_text()

    perimeter_lines = [
        line for line in text.splitlines() if "Code must not leave the security perimeter" in line
    ]
    assert perimeter_lines, "не найдена строка про security perimeter в таблице 'What it does'"
    for line in perimeter_lines:
        assert "planned" not in line.lower(), (
            f"локальный провайдер работает уже сегодня (T-42) — не должен быть помечен planned: {line!r}"
        )
        assert "disabled by default" in line, (
            f"строка про периметр не отмечает облачные провайдеры disabled by default: {line!r}"
        )

    assert "SWB_ALLOW_REMOTE_PROVIDERS" in text, (
        "README не документирует флаг opt-in для удалённых провайдеров (T-42)"
    )


def test_force_fp_mode_mentioned():
    text = _readme_text()
    assert "force_fp" in text, "режим force_fp (server/swb_server/ai/prompts.py) не упомянут в README"


def test_no_hardcoded_test_count_in_readme():
    """T-67: конкретное число тестов в README дважды протухало (83 -> 151 -> 356)
    быстрее, чем кто-то вспоминал обновить строку — предыдущая версия этого теста
    проверяла только `documented <= actual`, поэтому дрейф проходил молча. Вместо
    гонки за актуальным числом README ссылается на живой источник (CI-бейдж вверху
    файла / `uv run pytest --collect-only -q tests/`). Тест не даёт снова
    закоммитить конкретную цифру рядом с "pytest test suite"."""
    text = _readme_text()
    found_line = False
    for line in text.splitlines():
        if "pytest test suite" in line:
            found_line = True
            assert not re.search(r"\d+\+?\s*tests?\b", line), (
                f"README снова содержит захардкоженное число тестов, которое будет "
                f"молча протухать: {line!r} — сошлись на CI-бейдж или "
                "`pytest --collect-only` вместо конкретной цифры"
            )
    assert found_line, "не найдена строка про pytest test suite в README (Development)"
