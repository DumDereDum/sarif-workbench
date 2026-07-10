"""Env harness for importing swb_server modules directly (outside the `app`
fixture from tests/server/conftest.py) — mirrors that fixture's DATA_DIR /
DATABASE_URL setup so `swb_server.db` doesn't fall back to a real on-disk
path under server/ when this test module happens to be the first to import
swb_server in the process.
"""
import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _swb_server_env(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("swb-server-contract")
    os.environ.setdefault("DATA_DIR", str(data_dir))
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{data_dir / 'swb.db'}")
    os.environ.setdefault("LOG_FILE", "")
    yield
