import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .db import init_db
from .storage import init_storage
from .routers import findings, projects, runs, analyze, report

_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
_LOG_FILE = os.getenv("LOG_FILE", "")

_fmt = logging.Formatter(
    fmt="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

_root = logging.getLogger()
_root.setLevel(_LOG_LEVEL)

_console = logging.StreamHandler()
_console.setFormatter(_fmt)
_root.addHandler(_console)

if _LOG_FILE:
    from logging.handlers import RotatingFileHandler
    _log_path = Path(_LOG_FILE)
    _log_path.parent.mkdir(parents=True, exist_ok=True)
    _file_handler = RotatingFileHandler(
        _log_path,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=3,
        encoding="utf-8",
    )
    _file_handler.setFormatter(_fmt)
    _root.addHandler(_file_handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    init_storage()
    yield


app = FastAPI(title="SARIF Workbench", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router)
app.include_router(runs.router)
app.include_router(findings.router)
app.include_router(analyze.router)
app.include_router(report.router)

# Serve built web app if available
_web_dist = Path(__file__).parent.parent.parent / "web" / "dist"
if _web_dist.exists():
    app.mount("/", StaticFiles(directory=str(_web_dist), html=True), name="static")
