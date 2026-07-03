"""Минимальный серверный харнесс для T-02 (полный харнесс придёт в T-14).

БД и блобы уводятся во временный каталог. Env выставляется ДО импорта
swb_server: db.py создаёт engine на уровне модуля из DATABASE_URL,
поэтому приложение импортируется внутри фикстуры, а не наверху модуля.
"""
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def app(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("swb-server")
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ["DATABASE_URL"] = f"sqlite:///{data_dir / 'swb.db'}"
    os.environ["LOG_FILE"] = ""  # не писать лог-файл из тестов
    from swb_server.main import app  # noqa: PLC0415 — импорт после установки env

    return app


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c
