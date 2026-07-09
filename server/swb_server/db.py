import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def _default_data_dir() -> Path:
    # DATA_DIR env var → set in Docker; fall back to local dev path
    d = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent.parent / "data")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    return f"sqlite:///{_default_data_dir() / 'swb.db'}"


class Base(DeclarativeBase):
    pass


def _make_engine():
    url = _database_url()
    # T-32: конкурентные писатели (напр. параллельные PATCH /verdict) сериализуются
    # самим SQLite через файловую блокировку (единственный RESERVED-holder за раз) —
    # это и есть механизм сериализации read-modify-write для counts_by_verdict, без
    # отдельного прикладного лока. Дефолтный busy-timeout sqlite3 (5s) может не
    # хватить, чтобы дождаться своей очереди под ~20 одновременными PATCH — вместо
    # немедленной ошибки "database is locked" даём больше времени на ожидание.
    connect_args = {"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = _make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    _default_data_dir()  # ensure dir exists
    Base.metadata.create_all(bind=engine)
