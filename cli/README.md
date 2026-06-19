# swb-cli

CLI-инструмент для обогащения SARIF-отчётов метаданными. Запускается там, где есть исходный код и сгенерированный анализатором SARIF-файл — на CI-раннере или машине разработчика.

**Что делает:** читает `.sarif`, создаёт рядом файл `.sarif.swbmeta.json` с отпечатками находок, git-провенансом и (в будущем) фрагментами кода. Исходный SARIF не изменяется.

## Установка

Требуется [uv](https://docs.astral.sh/uv/).

```bash
# из корня монорепо
uv sync
```

После этого команда доступна как:

```bash
uv run swb-cli
```

## Использование

```bash
uv run swb-cli enrich <путь-к-sarif> [флаги]
```

### Пример

```bash
uv run swb-cli enrich build/report.sarif
# → build/report.sarif.swbmeta.json
```

```bash
uv run swb-cli enrich build/report.sarif \
  --repo-root /home/ci/project \
  --context-policy lines \
  --context-lines 5 \
  --out /tmp/meta.json
```

## Флаги

| Флаг | По умолчанию | Описание |
|---|---|---|
| `PATH` | — | Путь к SARIF-файлу (обязателен) |
| `--out PATH` | `<input>.swbmeta.json` | Путь выходного файла |
| `--repo-root PATH` | автоопределение | Корень репозитория для git-метаданных |
| `--context-policy` | `lines` | Сколько кода вкладывать: `none` / `line` / `lines` / `function` |
| `--context-lines N` | `5` | Строк контекста вокруг находки для режима `lines` |
| `--no-git` | выкл | Не собирать git-метаданные |
| `--fail-on-missing-source` | выкл | Завершиться с ошибкой если файл из находки не найден |
| `--log-level` | `info` | Уровень логов: `error` / `warn` / `info` / `debug` |

## Выходной файл

Создаётся рядом с исходным SARIF (или по `--out`). Имя: `<имя-sarif>.swbmeta.json`.

```json
{
  "schema": "swbmeta/v1",
  "generated_by": "swb-cli 0.1.0",
  "generated_at": "2026-06-18T07:41:30Z",
  "source_sarif": {
    "filename": "report.sarif",
    "sha256": "9f2c8a...",
    "size_bytes": 48120
  },
  "provenance": {
    "repo": "billing-service",
    "branch": "main",
    "commit": "a1b2c3d4...",
    "commit_short": "a1b2c3d",
    "is_dirty": false,
    "tool": "Semgrep OSS",
    "tool_version": "1.x.x",
    "scanned_at": "2026-06-18T07:41:30Z"
  },
  "context_policy": { "mode": "lines", "lines": 5 },
  "findings": [
    {
      "swb_id": "h:6cfba861453794c0",
      "occurrence": 0,
      "locator": {
        "run": 0,
        "result": 0,
        "rule_id": "CWE-89",
        "uri": "src/db/queries.py",
        "region": { "start_line": 88, "start_column": 5 }
      },
      "fingerprints": { "rule": "CWE-89" },
      "git": null,
      "code": null
    }
  ]
}
```

### Поля provenance

| Поле | Откуда берётся |
|---|---|
| `repo` | Имя директории репозитория |
| `branch` | `git rev-parse --abbrev-ref HEAD` |
| `commit` | `git rev-parse HEAD` |
| `is_dirty` | `git status --porcelain` (непустой вывод = `true`) |
| `tool` / `tool_version` | Из `runs[0].tool.driver` в SARIF |

Git-поля заполняются только если найден репозиторий (`.git`). Если git недоступен или передан `--no-git` — поля принимают значения-заглушки, команда завершается успешно.

## Коды возврата

| Код | Значение |
|---|---|
| `0` | Успех, файл записан |
| `1` | Невалидный SARIF (не парсится) |
| `2` | Ошибка ввода-вывода (файл не найден, нет прав) |
| `3` | Частичный успех: файл записан, часть метаданных не удалось собрать |

## Структура пакета

```
cli/
├── pyproject.toml
└── swb_cli/
    ├── swbmeta.py          Pydantic-схема выходного файла (swbmeta/v1)
    ├── __main__.py         Точка входа, argparse
    ├── commands/
    │   └── enrich.py       Логика команды enrich
    └── sarif/
        ├── models.py       Dataclass-модели для внутреннего представления SARIF
        └── parser.py       JSON-парсер SARIF 2.1.0
```

## Разработка

```bash
# установить зависимости
uv sync

# запустить напрямую
uv run swb-cli enrich samples/cpp-bank/report.sarif

# запустить на тестовом приложении (C++)
cd samples/cpp-bank
semgrep scan --config rules.yaml --sarif --output report.sarif --no-git-ignore main.cpp
uv run swb-cli enrich samples/cpp-bank/report.sarif --repo-root .
```
