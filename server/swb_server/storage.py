"""
Blob storage abstraction.

Current backend: local filesystem (STORAGE_BACKEND=local, default).
Future backends:  STORAGE_BACKEND=s3  →  S3 / MinIO via boto3.

Env vars (local):
  DATA_DIR            root data directory (default: server/data)

Env vars (s3):
  S3_ENDPOINT         e.g. http://minio:9000
  S3_BUCKET           bucket name (default: swb)
  S3_ACCESS_KEY
  S3_SECRET_KEY
  S3_REGION           (default: us-east-1)
"""

import os
from pathlib import Path


def _data_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", str(Path(__file__).parent.parent / "data")))


def _backend() -> str:
    return os.environ.get("STORAGE_BACKEND", "local")


def init_storage() -> None:
    if _backend() == "local":
        (_data_dir() / "blobs").mkdir(parents=True, exist_ok=True)


def save_blob(key: str, data: bytes) -> str:
    if _backend() == "s3":
        return _s3_save(key, data)
    return _local_save(key, data)


def load_blob(key: str) -> bytes:
    if _backend() == "s3":
        return _s3_load(key)
    return _local_load(key)


# ── Local ──────────────────────────────────────────────────────────────────────

def _local_save(key: str, data: bytes) -> str:
    path = _data_dir() / "blobs" / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return key


def _local_load(key: str) -> bytes:
    path = _data_dir() / "blobs" / key
    if not path.exists():
        raise FileNotFoundError(f"Blob not found: {key}")
    return path.read_bytes()


# ── S3 / MinIO ─────────────────────────────────────────────────────────────────

def _s3_save(key: str, data: bytes) -> str:
    _s3_client().put_object(Bucket=_s3_bucket(), Key=key, Body=data)
    return key


def _s3_load(key: str) -> bytes:
    resp = _s3_client().get_object(Bucket=_s3_bucket(), Key=key)
    return resp["Body"].read()


def _s3_client():
    import boto3  # optional dep — install when STORAGE_BACKEND=s3
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("S3_ENDPOINT"),
        aws_access_key_id=os.environ.get("S3_ACCESS_KEY"),
        aws_secret_access_key=os.environ.get("S3_SECRET_KEY"),
        region_name=os.environ.get("S3_REGION", "us-east-1"),
    )


def _s3_bucket() -> str:
    return os.environ.get("S3_BUCKET", "swb")
