# Справочник CLI

`swb-cli` — утилита командной строки для обогащения SARIF-отчётов и загрузки их на сервер.

Запускается **на машине с исходным кодом** — CI-раннере или рабочей станции разработчика — где доступны git-история и исходные файлы. Исходный SARIF никогда не изменяется.

---

## Установка

=== "uv (разработка)"

    ```bash
    # Из корня репозитория
    uv sync
    uv run swb-cli --help
    ```

=== "Бинарник PyInstaller (CI / air-gap)"

    ```bash
    uv sync
    uv run pyinstaller cli/swb_cli.spec --distpath dist/
    # Автономный бинарник — Python на целевой машине не нужен
    ./dist/swb-cli --help
    ```

---

## `swb-cli enrich`

Читает SARIF-файл и создаёт рядом `.swbmeta.json`-сайдкар с:

- **Сниппетами кода** — настраиваемое количество строк контекста вокруг находки
- **Git-метаданными** — blob SHA, blame-коммит, дата последнего изменения
- **Отпечатками** — хеши rule, content и context для идентификации находки
- **Провенансом** — репозиторий, ветка, коммит, имя и версия инструмента

Исходный SARIF **не изменяется**.

### Использование

```bash
swb-cli enrich <путь-к-sarif> [опции]
```

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `<путь-к-sarif>` | _(обязателен)_ | Путь к входному SARIF-файлу |
| `--out PATH` | `<input>.swbmeta.json` | Путь выходного сайдкара |
| `--repo-root PATH` | автоопределение | Корень репозитория для git-метаданных и разрешения путей |
| `--context-policy` | `lines` | Сколько кода вкладывать: `none` / `line` / `lines` |
| `--context-lines N` | `5` | Строк контекста выше и ниже находки (для режима `lines`) |
| `--no-git` | выкл | Не собирать git-метаданные |
| `--fail-on-missing-source` | выкл | Завершиться с ошибкой, если файл из находки не найден |
| `--log-level` | `info` | Уровень логов: `error` / `warn` / `info` / `debug` |

### Политика контекста

Флаг `--context-policy` управляет тем, сколько исходного кода вкладывается в сайдкар.
Это основная ручка приватности для air-gap-развёртываний:

| Режим | Что вкладывается |
|---|---|
| `none` | Код не вкладывается — только метаданные и отпечатки |
| `line` | Только строка находки |
| `lines` | Строка находки ± `--context-lines` строк **(по умолчанию)** |

### Примеры

```bash
# Базовый — корень репозитория определяется автоматически
swb-cli enrich build/report.sarif

# Явный корень репозитория и больший контекст
swb-cli enrich build/report.sarif \
  --repo-root /workspace/my-service \
  --context-lines 10

# Код не вкладывается (только метаданные и отпечатки)
swb-cli enrich build/report.sarif --context-policy none --no-git

# Падать если исходные файлы отсутствуют (неполный checkout)
swb-cli enrich build/report.sarif --fail-on-missing-source
```

### Коды возврата

| Код | Значение |
|---|---|
| `0` | Успех — сайдкар записан |
| `1` | Невалидный SARIF (ошибка парсинга или не SARIF) |
| `2` | Ошибка ввода-вывода (файл не найден, нет прав) |
| `3` | Частичный успех — сайдкар записан, часть метаданных не удалось собрать (см. лог) |

---

## `swb-cli upload`

Загружает пару SARIF + сайдкар на сервер.

Сервер автоматически создаёт проект из поля `provenance.repo` в сайдкаре.
Если этот же SARIF (по SHA-256) уже загружался — сервер возвращает существующий прогон (идемпотентность).

### Использование

```bash
swb-cli upload <путь-к-sarif> [опции]
```

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `<путь-к-sarif>` | _(обязателен)_ | Путь к SARIF-файлу (сайдкар должен лежать рядом) |
| `--server URL` | `http://localhost:8000` | Базовый URL сервера |
| `--meta PATH` | `<sarif>.swbmeta.json` | Явный путь к сайдкару, если он не рядом с SARIF |

### Примеры

```bash
# Загрузить на локальный сервер
swb-cli upload build/report.sarif

# Загрузить на удалённый сервер
swb-cli upload build/report.sarif --server https://swb.company.ru

# Сайдкар в другом месте
swb-cli upload build/report.sarif --meta /tmp/report.sarif.swbmeta.json
```

### Вывод

**Новый прогон (HTTP 201):**
```
INFO  Upload successful!
INFO    project : billing-service
INFO    run_id  : r-a1b2c3d4e5f6
INFO    findings: 42  (crit=2 high=11 med=19 low=8 note=2)
INFO    web     : http://localhost:8000/projects/billing-service/runs/r-a1b2c3d4e5f6
```

**Дубликат (HTTP 200, тот же SARIF уже загружен):**
```
WARNING Duplicate upload detected — this SARIF was already uploaded.
WARNING   run_id : r-a1b2c3d4e5f6
WARNING   uploaded_at: 2026-06-18T09:00:00Z
WARNING   web    : http://localhost:8000/projects/billing-service/runs/r-a1b2c3d4e5f6
```

---

## Формат сайдкара (`swbmeta/v1`)

Сайдкар — JSON-файл со следующей структурой:

```json
{
  "schema": "swbmeta/v1",
  "generated_by": "swb-cli 0.1.0",
  "generated_at": "2026-06-18T09:00:00Z",
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
      "fingerprints": {
        "rule": "CWE-89",
        "scope": "func:execute_query@src/db/queries.py",
        "content": "h:7d1e...",
        "context": "h:42af..."
      },
      "git": {
        "blob_sha": "e3b0c4...",
        "blame_commit": "a1b2c3d4...",
        "last_changed": "2026-05-30"
      },
      "code": {
        "lang": "python",
        "start_line": 83,
        "end_line": 93,
        "snippet": "..."
      }
    }
  ]
}
```

### `swb_id` — устойчивый ключ находки

`swb_id` — детерминированный хеш из `rule + scope + content + occurrence`. Идентифицирует одну и ту же логическую находку в разных прогонах, даже если номер строки сдвинулся из-за несвязанных изменений кода.

---

## Интеграция с CI/CD

### GitHub Actions

```yaml
- name: SAST triage upload
  run: |
    swb-cli enrich ${{ github.workspace }}/report.sarif \
      --repo-root ${{ github.workspace }}
    swb-cli upload ${{ github.workspace }}/report.sarif \
      --server ${{ secrets.SWB_SERVER_URL }}
```

### GitLab CI

```yaml
sast-upload:
  stage: post-test
  script:
    - swb-cli enrich report.sarif --repo-root .
    - swb-cli upload report.sarif --server $SWB_SERVER_URL
  artifacts:
    paths:
      - "*.swbmeta.json"
```
