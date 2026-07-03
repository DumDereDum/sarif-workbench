"""README-честность (T-04): утверждения в README не должны опережать реальный код.

Регрессионные проверки на конкретные несоответствия, найденные при аудите:
- ссылка на несуществующий cli/swb_cli.spec;
- безусловные заявления про полный офлайн-режим (сейчас единственный AI-провайдер
  облачный DeepSeek);
- локальные LLM-провайдеры и сравнение с baseline поданы как готовые, хотя не
  реализованы;
- заявленное число тестов не должно превышать фактическое количество собранных
  pytest-тестов;
- режим `force_fp` должен быть упомянут в описании AI-триажа.
"""
from __future__ import annotations

import re
import subprocess
import sys
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


def test_local_providers_and_baseline_marked_planned():
    text = _readme_text()
    assert "vLLM, Ollama, GigaChat, YandexGPT" in text
    # Обе строки, где упоминаются локальные провайдеры, должны быть помечены как planned.
    for line in text.splitlines():
        if "GigaChat" in line and "YandexGPT" in line and "|" in line:
            assert "planned" in line.lower(), f"локальные провайдеры не помечены planned: {line!r}"

    for line in text.splitlines():
        if "Run comparison against a baseline" in line:
            assert "planned" in line.lower(), f"baseline-сравнение не помечено planned: {line!r}"


def test_manual_verdict_override_marked_done():
    text = _readme_text()
    assert "- [x] Manual verdict override UI" in text, (
        "Manual verdict override реализован (PATCH /findings/{fid}/verdict + UI в "
        "FindingDrawer.tsx), но в Roadmap не отмечен как done"
    )


def test_force_fp_mode_mentioned():
    text = _readme_text()
    assert "force_fp" in text, "режим force_fp (server/swb_server/ai/prompts.py) не упомянут в README"


def test_documented_test_count_does_not_overstate_reality():
    text = _readme_text()
    match = re.search(r"pytest test suite \((\d+)\+?\s*tests\)", text)
    assert match, "не найдена строка с числом тестов в README (Project structure)"
    documented = int(match.group(1))

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"сбор тестов упал:\n{result.stdout}\n{result.stderr}"

    summary_match = re.search(r"(\d+) tests? collected", result.stdout)
    assert summary_match, f"не удалось распарсить количество собранных тестов:\n{result.stdout}"
    actual = int(summary_match.group(1))

    assert documented <= actual, (
        f"README заявляет {documented} тестов, но реально собрано только {actual} — "
        "число в README не должно превышать действительность"
    )
