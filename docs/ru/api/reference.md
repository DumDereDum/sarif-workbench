# API Reference

Все эндпоинты используют префикс `/api/v1`.

**Базовый URL:** `http://localhost:8000/api/v1`  
**Формат:** `application/json` (кроме загрузки: `multipart/form-data`)  
**Время:** UTC, ISO-8601

---

## Загрузка прогона

### `POST /api/v1/runs`

Загрузить пару SARIF + сайдкар. Вызывается `swb-cli upload` — не из Web UI.

**Content-Type:** `multipart/form-data`

| Часть | Тип | Описание |
|---|---|---|
| `sarif` | file | Оригинальный SARIF-файл (без изменений) |
| `meta` | file | Сайдкар-файл (`swbmeta/v1`) |

**Алгоритм:**

1. Посчитать `sha256` принятого SARIF
2. Сверить с `meta.source_sarif.sha256` — не совпало → `409 sha_mismatch`
3. Проверить `meta.schema` — неподдерживаемая версия → `422 unsupported_schema`
4. Определить проект из `meta.provenance.repo` (создать если нет)
5. **Идемпотентность:** если уже есть прогон с тем же SHA-256 → вернуть `200` с существующим прогоном
6. Создать прогон, сохранить блобы, распарсить находки и правила

**Ответ `201 Created`** (или `200` при дубликате):

```json
{
  "run_id": "r-a1b2c3d4e5f6",
  "project_id": "billing-service",
  "deduplicated": false,
  "finding_count": 42,
  "counts": {
    "critical": 2,
    "high": 11,
    "medium": 19,
    "low": 8,
    "note": 2
  }
}
```

---

## Проекты

### `GET /api/v1/projects`

Список всех проектов с сводкой по последнему прогону.

```json
{
  "projects": [
    {
      "id": "billing-service",
      "name": "billing-service",
      "repo": "billing-service",
      "last_run": {
        "id": "r-a1b2c3d4e5f6",
        "scanned_at": "2026-06-18T09:00:00Z",
        "commit": "a1b2c3d"
      },
      "counts": { "critical": 2, "high": 11, "medium": 19, "low": 8, "note": 2, "all": 42 },
      "counts_by_verdict": {
        "true_positive": 5,
        "false_positive": 12,
        "uncertain": 3,
        "unmarked": 22
      }
    }
  ]
}
```

### `GET /api/v1/projects/{id}/runs`

История прогонов проекта (для селектора прогонов и сравнения).

```json
{
  "runs": [
    {
      "id": "r-a1b2c3d4e5f6",
      "commit": "a1b2c3d",
      "branch": "main",
      "tool": "Semgrep OSS",
      "tool_version": "1.x.x",
      "scanned_at": "2026-06-18T09:00:00Z",
      "counts": { "critical": 2, "high": 11, "medium": 19, "low": 8, "note": 2 }
    }
  ]
}
```

---

## Прогоны

### `GET /api/v1/runs/{runId}`

Шапка прогона: проект, коммит, ветка, инструмент, даты, сводка по counts.

### `GET /api/v1/runs/{runId}/findings`

Пагинированный список находок (лёгкий — без сниппетов кода; они загружаются в `/findings/{fid}`).

**Query-параметры:**

| Параметр | Пример | Описание |
|---|---|---|
| `severity` | `critical,high` | Фильтр по severity (CSV) |
| `verdict` | `true_positive,uncertain` | Фильтр по вердикту (CSV) |
| `rule` | `CWE-89` | Фильтр по ID правила |
| `file` | `src/db/` | Префикс или подстрока пути файла |
| `q` | `sql` | Полнотекстовый поиск по файлу, правилу, сообщению, scope |
| `sort` | `severity` | Поле сортировки |
| `dir` | `asc` / `desc` | Направление сортировки |
| `page` | `1` | Страница (от 1) |
| `page_size` | `50` | Элементов на странице (по умолчанию 50, макс 200) |

**Ответ:**

```json
{
  "total": 42,
  "page": 1,
  "page_size": 50,
  "items": [
    {
      "id": "F1",
      "swb_id": "h:6cfba861453794c0",
      "severity": "critical",
      "rule_id": "CWE-89",
      "rule_name": "SQL Injection",
      "uri": "src/db/queries.py",
      "start_line": 88,
      "scope": "execute_query",
      "message": "Недоверенный user_id конкатенируется в SQL-запрос",
      "verdict": "true_positive",
      "verdict_source": "llm",
      "confidence": 91
    }
  ]
}
```

### `GET /api/v1/runs/{runId}/aggregations`

Группировки со счётчиками для панели фильтров. `?by=severity|verdict|rule|file|cwe`

```json
{
  "by": "rule",
  "groups": [
    { "key": "CWE-89", "label": "CWE-89 SQL Injection", "count": 3 },
    { "key": "CWE-79", "label": "CWE-79 Cross-site Scripting", "count": 2 }
  ]
}
```

### `GET /api/v1/runs/{runId}/sarif`

Возвращает оригинальный SARIF-блоб (байт-в-байт, без изменений).

### `POST /api/v1/runs/{runId}/analyze`

Запустить AI-триаж для всех неразмеченных находок прогона.

**Content-Type:** `application/json`

```json
{
  "provider": "ollama",
  "model": "llama3",
  "prompt_type": "honest"
}
```

`provider`/`model` необязательны — если не заданы, берётся дефолт с сервера (см.
`GET /api/v1/providers`). Поля `api_key` нет: ключи настраиваются на сервере, клиент их
никогда не отправляет (T-44).

**Ответ:** `text/event-stream` (SSE)

Каждое событие — JSON-объект:

```
data: {"type": "progress", "finding_id": "F1", "verdict": "false_positive", "confidence": 86, "done": 5, "total": 42}

data: {"type": "error", "finding_id": "F7", "message": "Rate limit exceeded"}

data: {"type": "done", "verdicts_set": 38, "errors": 4}
```

### `POST /api/v1/runs/{runId}/reset`

Сбросить все AI-вердикты прогона обратно в `unmarked`. Ручные (`human`) вердикты сохраняются.

**Ответ `200 OK`:**
```json
{ "reset_count": 38 }
```

### `GET /api/v1/runs/{runId}/report`

Сгенерировать и скачать PDF-отчёт.

**Query-параметры:**

| Параметр | Пример | Описание |
|---|---|---|
| `severity` | `critical,high` | Включать только эти severity (CSV) |
| `verdict` | `true_positive` | Включать только эти вердикты (CSV) |

**Ответ:** `application/pdf`

---

## Находки

### `GET /api/v1/findings/{fid}`

Полная детальная информация: сниппет кода, описание правила, codeFlow, git-инфо, полная история триажа.

```json
{
  "id": "F1",
  "swb_id": "h:6cfba861453794c0",
  "severity": "critical",
  "rule_id": "CWE-89",
  "rule_name": "SQL Injection",
  "rule_description": "Конкатенация недоверенного ввода в SQL-запрос...",
  "uri": "src/db/queries.py",
  "start_line": 88,
  "scope": "execute_query",
  "snippet": {
    "start_line": 83,
    "lines": ["...", "...", "    result = db.execute(query + user_id)", "..."],
    "hot_line": 88
  },
  "git": {
    "blob_sha": "e3b0c4...",
    "blame_commit": "a1b2c3d4...",
    "last_changed": "2026-05-30"
  },
  "verdict": {
    "verdict": "true_positive",
    "source": "llm",
    "confidence": 91,
    "rationale": "user_id передаётся непосредственно в строку SQL без параметризации.",
    "provider": "deepseek",
    "history": [
      { "source": "llm", "verdict": "true_positive", "at": "2026-06-18T10:00:00Z" }
    ]
  }
}
```

### `PATCH /api/v1/findings/{fid}/verdict`

Переопределить вердикт находки вручную.

**Запрос:**
```json
{
  "verdict": "false_positive",
  "rationale": "Ввод валидируется выше по стеку до попадания в эту функцию."
}
```

**Ответ `200 OK`:** обновлённый объект `verdict` с `source: "human"`.

---

## Промпты

### `GET /api/v1/prompts`

Список встроенных шаблонов промптов для AI-триажа.

```json
{
  "prompts": [
    {
      "id": "honest",
      "name": "Честный",
      "description": "Сбалансированная классификация — uncertain если доказательств недостаточно."
    },
    {
      "id": "force_fp",
      "name": "Force FP",
      "description": "Классифицировать как FP, если нет явных доказательств реальной уязвимости."
    }
  ]
}
```

---

## Провайдеры

### `GET /api/v1/providers`

Список AI-провайдеров, которые сейчас сконфигурированы *и* доступны (гейты T-42 уже
применены — заблокированный remote-провайдер просто отсутствует, а не только отказывает
при вызове). Web UI берёт отсюда варианты provider/model вместо хардкода (T-44); ключа
`api_key` в этом ответе нет и быть не может — ключи это конфиг сервера, клиент их не
хранит и не отправляет.

```json
{
  "providers": [
    { "name": "ollama", "local": true, "default_model": "llama3" }
  ],
  "default_provider": "ollama"
}
```

`default_provider` — `null`, если прямо сейчас недоступен ни один провайдер (например,
реестр только с remote-записями, которые ещё не разрешены). `POST .../analyze` вернёт
422 `no_provider` только если запрос ТАКЖЕ не назвал провайдера явно — явно указанный
провайдер всегда пробрасывается как есть, даже если он неизвестен или заблокирован, чтобы
эта более специфичная ошибка не маскировалась здесь.

---

## Маппинг severity {#severity-mapping}

Находки SARIF нормализуются к единой шкале серьёзности. Числовое свойство `security-severity` (0–10) имеет приоритет над полем `level`:

| `security-severity` | SARIF `level` | Severity |
|---|---|---|
| ≥ 9.0 | — | `critical` |
| 7.0–8.9 | — | `high` |
| 4.0–6.9 | — | `medium` |
| 0.1–3.9 | — | `low` |
| _(нет)_ | `error` | `high` |
| _(нет)_ | `warning` | `medium` |
| _(нет)_ | `note` | `low` |
| _(нет)_ | `none` / отсутствует | `note` |

---

## Ошибки

Все ошибки используют единый JSON-конверт:

```json
{ "error": "sha_mismatch", "message": "meta.source_sarif.sha256 не совпадает с загруженным SARIF" }
```

| HTTP | `error` | Когда |
|---|---|---|
| 400 | `bad_request` | Некорректный multipart / невалидные параметры |
| 404 | `not_found` | Проект / прогон / находка не найдены |
| 409 | `sha_mismatch` | Хеш SARIF не совпадает с `source_sarif.sha256` в сайдкаре |
| 422 | `unsupported_schema` | Версия `schema` сайдкара не поддерживается |
| 422 | `invalid_sarif` | SARIF не парсится или не соответствует схеме |
