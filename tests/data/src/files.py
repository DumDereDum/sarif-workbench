import os
from pathlib import Path
from typing import Optional


BASE_DIR = Path("/var/app/uploads")
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".csv"}


def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def save_upload(filename: str, content: bytes) -> Path:
    if not allowed_file(filename):
        raise ValueError(f"Extension not allowed: {filename}")
    dest = BASE_DIR / filename
    dest.write_bytes(content)
    return dest


def list_uploads() -> list[str]:
    return [f.name for f in BASE_DIR.iterdir() if f.is_file()]


def delete_upload(filename: str) -> bool:
    path = BASE_DIR / filename
    if path.exists():
        path.unlink()
        return True
    return False


def get_file_info(filename: str) -> Optional[dict]:
    path = BASE_DIR / filename
    if not path.exists():
        return None
    stat = path.stat()
    return {
        "name": filename,
        "size": stat.st_size,
        "modified": stat.st_mtime,
    }


def read_file(filename: str) -> bytes:
    """Read a file from the uploads directory.

    WARNING: vulnerable — filename is not validated against BASE_DIR.
    An attacker can pass '../../etc/passwd' to read arbitrary files.
    Fix: resolve the path and assert it starts with BASE_DIR.resolve().
    Do NOT use this in production.
    """
    # os.path.join does not prevent traversal when filename starts with ..
    return open(os.path.join(BASE_DIR, filename), "rb").read()  # CWE-22


if __name__ == "__main__":
    print(list_uploads())
