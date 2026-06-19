# Тесты

## Запуск

```bash
# все тесты
uv run pytest tests/

# с подробным выводом
uv run pytest tests/ -v

# один файл
uv run pytest tests/cli/test_parser.py -v

# один тест
uv run pytest tests/cli/test_enrich.py::test_sha256_matches_source_file -v
```

Запускать из корня репозитория. Если `uv` не в `PATH`: `~/.local/bin/uv run pytest tests/`.

## Структура

```
tests/
├── cli/
│   ├── test_parser.py     unit-тесты SARIF-парсера и _extract_text
│   ├── test_enrich.py     функциональные тесты команды enrich
│   └── test_code.py       unit-тесты extract_snippet и detect_lang
└── data/
    ├── src/               статичные исходники, на которые ссылаются SARIF-фикстуры
    │   ├── db.py          line 42 — CWE-89  SQL injection
    │   ├── exec.py        line 7  — CWE-78  command injection
    │   ├── files.py       line 55 — CWE-22  path traversal
    │   ├── utils.c        line 20 — CWE-476 null dereference
    │   └── views.py       line 10 — CWE-79  XSS
    ├── valid/             корректные SARIF для граничных случаев
    │   ├── minimal.sarif            один run, один результат
    │   ├── empty_runs.sarif         runs: []
    │   ├── no_results.sarif         run без findings
    │   ├── multi_run.sarif          два run в одном файле
    │   ├── duplicate_findings.sarif три одинаковые находки → occurrence 0/1/2
    │   ├── no_locations.sarif       finding без locations
    │   └── message_as_string.sarif  message как строка, не объект
    └── invalid/           сломанные данные — парсер должен падать
        ├── malformed_json.sarif     обрезанный JSON
        ├── empty_file.sarif         пустой файл
        ├── not_sarif.json           валидный JSON, но не SARIF
        └── wrong_type_runs.sarif    "runs" — строка вместо массива
```

## Разделение данных

`tests/data/` — фикстуры для unit и функциональных тестов. Файлы статичны и не меняются.

`samples/` — демо-приложения и реальные SARIF для e2e-тестов и бенчмарков. Там лежит живой код, который будет развиваться.
