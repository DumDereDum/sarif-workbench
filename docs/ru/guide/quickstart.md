# Быстрый старт

Запустите SARIF Workbench за 5 минут.

## Требования

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (или Docker Engine + Compose plugin)
- SARIF 2.1.0-файл от вашего анализатора

!!! tip "Нет SARIF-файла?"
    В репозитории есть встроенный C++-семпл с заранее сгенерированным SARIF. Выполните `make sample`, чтобы попробовать.

---

## Шаг 1 — Запустить сервер

```bash
git clone https://github.com/DumDereDum/sarif-workbench
cd sarif-workbench
docker compose up
```

Запускаются:

| Сервис | URL | Описание |
|---|---|---|
| Web UI | http://localhost:5173 | React-интерфейс |
| API-сервер | http://localhost:8000 | FastAPI-бэкенд |

При первом запуске скачиваются образы — это занимает 1–2 минуты.

---

## Шаг 2 — Установить swb-cli

CLI запускается **на машине с исходным кодом** (CI-раннер или рабочая станция разработчика), не внутри Docker.

=== "uv (для разработки)"

    ```bash
    # Установить uv если нет
    curl -Ls https://astral.sh/uv/install.sh | sh

    # Из корня репозитория
    uv sync
    uv run swb-cli --help
    ```

=== "Бинарник PyInstaller"

    ```bash
    uv sync
    uv run pyinstaller cli/swb_cli.spec --distpath dist/
    sudo cp dist/swb-cli /usr/local/bin/
    swb-cli --help
    ```

---

## Шаг 3 — Обогатить и загрузить SARIF

```bash
# Обогащение: добавляет git-метаданные, сниппеты кода и отпечатки
swb-cli enrich путь/к/report.sarif --repo-root путь/к/исходному/коду

# Загрузка: отправляет SARIF + сайдкар на сервер
swb-cli upload путь/к/report.sarif --server http://localhost:8000
```

После успешной загрузки:

```
INFO  Upload successful!
INFO    project : my-service
INFO    run_id  : r-a1b2c3d4e5f6
INFO    findings: 42  (crit=2 high=11 med=19 low=8 note=2)
INFO    web     : http://localhost:8000/projects/my-service/runs/r-a1b2c3d4e5f6
```

Откройте напечатанный URL (или перейдите на **http://localhost:5173**), чтобы увидеть находки.

---

## Попробуйте встроенный семпл

В репозитории есть C++-приложение с известными уязвимостями:

```bash
make sample
```

Команда запускает `enrich` + `upload` на `samples/cpp-bank/report.sarif` и выводит ссылку на UI.

---

## Следующие шаги

- [Справочник CLI](cli.md) — все флаги, формат вывода, коды возврата
- [Развёртывание](deployment.md) — продакшн-настройка, переменные среды
- [API Reference](../api/reference.md) — REST-эндпоинты для интеграции
