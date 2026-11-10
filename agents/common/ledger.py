"""Append-only incident ledger with in-memory and MinIO-compatible stores.

MinIO bucket versioning/object-lock policy is configured separately. The
writer never intentionally replaces an existing key; callers should share a
Ledger instance when appending concurrently in one process.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, Iterable, Optional, Protocol


class LedgerStore(Protocol):
    def keys(self, prefix: str) -> Iterable[str]: ...
    def put_if_absent(self, key: str, data: bytes) -> None: ...


class InMemoryLedgerStore:
    """Thread-safe store intended for tests and local development."""

    def __init__(self) -> None:
        self.objects: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def keys(self, prefix: str) -> Iterable[str]:
        with self._lock:
            return tuple(key for key in self.objects if key.startswith(prefix))

    def put_if_absent(self, key: str, data: bytes) -> None:
        with self._lock:
            if key in self.objects:
                raise FileExistsError(key)
            self.objects[key] = data


class MinioLedgerStore:
    """Adapter for ``minio.Minio``; bucket durability/locking is provisioned outside."""

    def __init__(self, client: Any, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    def keys(self, prefix: str) -> Iterable[str]:
        return (obj.object_name for obj in self.client.list_objects(
            self.bucket, prefix=prefix, recursive=True
        ))

    def put_if_absent(self, key: str, data: bytes) -> None:
        # MinIO's Python client does not expose a portable conditional PUT.
        # Check first to avoid ordinary accidental overwrites; object lock on
        # the bucket provides the server-side retention guarantee.
        try:
            self.client.stat_object(self.bucket, key)
        except Exception as exc:
            # Only a not-found response means the key is available. Preserve
            # connection/authentication errors instead of masking them.
            code = str(getattr(exc, "code", ""))
            if code not in {"NoSuchKey", "NoSuchObject", "NotFound"}:
                raise
        else:
            raise FileExistsError(key)

        self.client.put_object(
            self.bucket, key, BytesIO(data), length=len(data),
            content_type="application/json",
        )


@dataclass(frozen=True)
class LedgerEntry:
    incident_id: str
    sequence: int
    step: str
    key: str
    payload: Dict[str, Any]


class Ledger:
    def __init__(self, store: Optional[LedgerStore] = None) -> None:
        self.store: LedgerStore = store if store is not None else InMemoryLedgerStore()
        self._lock = threading.Lock()

    def append(self, incident_id: str, step: str, payload: Dict[str, Any]) -> LedgerEntry:
        if not incident_id or "/" in incident_id or incident_id in {".", ".."}:
            raise ValueError("incident_id must be a non-empty path segment")
        if not step or "/" in step or step in {".", ".."}:
            raise ValueError("step must be a non-empty path segment")
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict")

        with self._lock:
            prefix = f"incidents/{incident_id}/"
            sequences = []
            for key in self.store.keys(prefix):
                name = key[len(prefix):]
                try:
                    sequences.append(int(name.split("-", 1)[0]))
                except (ValueError, IndexError):
                    continue
            sequence = max(sequences, default=0) + 1
            key = f"{prefix}{sequence:06d}-{step}.json"
            record = {
                "incident_id": incident_id,
                "sequence": sequence,
                "step": step,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": payload,
            }
            data = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.store.put_if_absent(key, data)
            return LedgerEntry(incident_id, sequence, step, key, payload)
