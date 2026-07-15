.PHONY: dev dev-build prod down logs sample enrich upload

# ── Разработка ────────────────────────────────────────────────────────────────

## Поднять стек разработки (hot reload)
dev:
	docker compose up

## Пересобрать образы и поднять
dev-build:
	docker compose up --build

## Остановить
down:
	docker compose down
	docker compose -f docker-compose.prod.yml down 2>/dev/null || true

## Логи сервера в реальном времени
logs:
	docker compose logs -f server

## Поднять с LOG_LEVEL=DEBUG (метаданные запросов/ответов к LLM: длины,
## латентность, статус, токены — без содержимого промптов/ответов и ключей, T-43)
debug:
	LOG_LEVEL=DEBUG docker compose up

# ── Продакшн ─────────────────────────────────────────────────────────────────

## Собрать и запустить продакшн-стек
prod:
	docker compose -f docker-compose.prod.yml up --build -d
	@echo "→ http://localhost"

## Продакшн с Postgres + MinIO (будущий переход)
prod-full:
	docker compose -f docker-compose.prod.yml --profile postgres --profile s3 up --build -d

# ── CLI утилиты (запускаются на хосте) ───────────────────────────────────────

## Обогатить SARIF: make enrich SARIF=samples/cpp-bank/report.sarif
enrich:
ifndef SARIF
	$(error Укажи SARIF=путь/к/файлу.sarif)
endif
	uv run swb-cli enrich $(SARIF) $(if $(REPO_ROOT),--repo-root $(REPO_ROOT),)

## Загрузить на сервер: make upload SARIF=samples/cpp-bank/report.sarif
upload:
ifndef SARIF
	$(error Укажи SARIF=путь/к/файлу.sarif)
endif
	uv run swb-cli upload $(SARIF) $(if $(SERVER),--server $(SERVER),--server http://localhost:8000)

## Быстрый тест со встроенным семплом
sample:
	uv run swb-cli enrich samples/cpp-bank/report.sarif --repo-root samples/cpp-bank
	uv run swb-cli upload samples/cpp-bank/report.sarif --server http://localhost:8000
	@echo "→ http://localhost:5173"
