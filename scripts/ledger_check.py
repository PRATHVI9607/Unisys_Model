"""Create a ledger entry in MinIO and test version-specific deletion protection.

The check uses the single authorized k3d context, reads credentials directly
from Kubernetes Secrets without printing them, and removes only the exact
temporary object version it created if object locking is not protecting it.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from minio import Minio
from minio.error import S3Error

from agents.common.ledger import Ledger, MinioLedgerStore


CONTEXT = "k3d-kubeheal"
NAMESPACE = "kubeheal"
BUCKET = "kubeheal-ledger"
_stage = "initializing"


def _secret_data(name: str) -> dict[str, str]:
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "get", "secret", name, "-o", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"Could not read required Kubernetes Secret {name} in {CONTEXT}/{NAMESPACE}")
    raw = json.loads(result.stdout).get("data", {})
    return {key: base64.b64decode(value).decode("utf-8") for key, value in raw.items()}


def _free_local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port_forward(process: subprocess.Popen, port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("kubectl port-forward stopped before MinIO became reachable")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("Timed out waiting for MinIO through kubectl port-forward")


def run_check() -> int:
    global _stage
    _stage = "reading credentials"
    root = _secret_data("kubeheal-minio-root")
    client_secrets = _secret_data("kubeheal-minio-client")
    for secret, keys in ((root, ("root-user", "root-password")),
                         (client_secrets, ("access-key", "secret-key"))):
        missing = [key for key in keys if not secret.get(key)]
        if missing:
            raise RuntimeError("A required MinIO Secret is missing expected keys")

    _stage = "starting port-forward"
    port = _free_local_port()
    forward = subprocess.Popen(
        ["kubectl", "--context", CONTEXT, "-n", NAMESPACE,
         "port-forward", "--address", "127.0.0.1", "svc/minio", f"{port}:9000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _stage = "connecting to MinIO"
        _wait_for_port_forward(forward, port)
        root_client = Minio(
            f"127.0.0.1:{port}",
            access_key=root["root-user"],
            secret_key=root["root-password"],
            secure=False,
        )
        writer = Minio(
            f"127.0.0.1:{port}",
            access_key=client_secrets["access-key"],
            secret_key=client_secrets["secret-key"],
            secure=False,
        )
        _stage = "appending through ledger writer"
        incident_id = f"ledger-check-{uuid.uuid4().hex}"
        entry = Ledger(MinioLedgerStore(writer, BUCKET)).append(
            incident_id,
            "integration_check",
            {"check": "disposable-object-lock"},
        )
        _stage = "reading created object metadata"
        stat = root_client.stat_object(bucket_name=BUCKET, object_name=entry.key)
        version_id = getattr(stat, "version_id", None)
        retention = None
        if version_id:
            _stage = "reading object retention"
            try:
                retention = root_client.get_object_retention(
                    bucket_name=BUCKET, object_name=entry.key, version_id=version_id
                )
            except S3Error:
                retention = None

        if not version_id:
            print(f"LEDGER_ENTRY_CREATED key={entry.key}; OBJECT_LOCK_UNAVAILABLE version_id_missing")
            return 2

        _stage = "attempting version-specific delete"
        try:
            root_client.remove_object(bucket_name=BUCKET, object_name=entry.key, version_id=version_id)
        except S3Error as exc:
            if retention is not None and getattr(retention, "mode", None):
                print(
                    "LEDGER_ENTRY_CREATED "
                    f"key={entry.key} version={version_id}; "
                    f"OBJECT_LOCK_REFUSED mode={retention.mode} code={exc.code}"
                )
                return 0
            print(f"LEDGER_ENTRY_CREATED key={entry.key}; DELETE_REFUSED_UNVERIFIED code={exc.code}")
            return 2
        else:
            print(f"LEDGER_ENTRY_CREATED key={entry.key}; OBJECT_LOCK_NOT_ENFORCED version={version_id}")
            return 1
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forward.kill()
            forward.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        return run_check()
    except Exception as exc:
        print(f"LEDGER_CHECK_FAILED stage={_stage} {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
