# Развёртывание

SARIF Workbench поставляется как Docker Compose-стек. Dev-режим запускается одной командой; продакшн добавляет nginx и персистентные тома.

---

## Требования

- Docker Desktop или Docker Engine + Compose plugin
- Свободные порты: 8000 (API) и 5173 (dev UI) или 80 (prod)

---

## Dev-режим

Запускает API-сервер и Vite dev-сервер с hot reload. Исходный код монтируется напрямую — пересборка не нужна после изменений.

```bash
docker compose up          # запустить
docker compose down        # остановить
docker compose logs -f     # следить за логами сервера
```

| Сервис | URL |
|---|---|
| Web UI | http://localhost:5173 |
| API | http://localhost:8000 |
| API-документация (Swagger) | http://localhost:8000/docs |

### Debug-режим

`LOG_LEVEL=DEBUG` добавляет в логи дополнительные *метаданные* запроса/ответа:
id находки, длины промпта/ответа, латентность, HTTP-статус, число токенов,
имя провайдера и модели. Содержимое промптов/ответов — код из сниппетов,
текст rationale от LLM, API-ключи — в логи не пишется ни на одном уровне,
включая DEBUG (T-43).

```bash
make debug
# аналог: LOG_LEVEL=DEBUG docker compose up
```

---

## Продакшн-режим

Собирает оптимизированный React-бандл, отдаёт его через nginx на порту 80 и проксирует `/api/` на FastAPI. Данные хранятся в Docker-volume.

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

Откройте http://localhost после завершения сборки (первый запуск занимает ~2 минуты).

**Остановить:**
```bash
docker compose -f docker-compose.prod.yml down
```

---

## Переменные среды

Скопируйте шаблон и отредактируйте:

```bash
cp .env.example .env
```

| Переменная | По умолчанию | Описание |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Уровень логов сервера: `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_FILE` | _(пусто)_ | Путь к файлу логов. В Docker `./logs/server.log` монтируется в `/logs/server.log` |
| `DATA_DIR` | `/data` | Директория для SQLite DB и BLOB-файлов |
| `DATABASE_URL` | `sqlite:////data/swb.db` | Путь к SQLite-базе данных |

---

## Без Docker

Запустить сервер и Web UI напрямую на хосте для разработки:

```bash
# Установить зависимости Python
uv sync

# Установить зависимости Node
cd web && npm install && cd ..

# Терминал 1 — API-сервер (автоперезагрузка при изменениях)
uv run uvicorn swb_server.main:app --reload --app-dir server

# Терминал 2 — Web UI (hot reload)
cd web && npm run dev
```

Откройте http://localhost:5173.

---

## Справочник Make-команд

| Команда | Описание |
|---|---|
| `make dev` | Запустить dev-стек |
| `make dev-build` | Пересобрать образы и запустить |
| `make down` | Остановить все сервисы |
| `make logs` | Следить за логами сервера |
| `make debug` | Запустить с `LOG_LEVEL=DEBUG` |
| `make prod` | Собрать и запустить продакшн-стек |
| `make sample` | Обогатить и загрузить встроенный C++-семпл |
| `make enrich SARIF=путь/к/файлу.sarif` | Запустить `swb-cli enrich` на файле |
| `make upload SARIF=путь/к/файлу.sarif` | Запустить `swb-cli upload` на файле |

