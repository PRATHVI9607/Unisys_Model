"""Read-only dump of the ledger entries of one incident (F3 evidence helper).

    python docs/kubeheal/demo-evidence/F3/ledger_dump.py <incident_id> [<incident_id> ...]
    python docs/kubeheal/demo-evidence/F3/ledger_dump.py --list-since <ISO time, UTC>   # every object key written since

Context k3d-kubeheal only. Reads the client credentials from the cluster Secret without printing them, opens a
kubectl port-forward to svc/minio, lists and reads `incidents/<id>/` objects (GET only, no write or delete) and
prints one JSON line per entry in sequence order."""
import base64
from datetime import datetime
import json
import socket
import subprocess
import sys
import time

from minio import Minio

CONTEXT, NAMESPACE, BUCKET = "k3d-kubeheal", "kubeheal", "kubeheal-ledger"


def secret(name):
    out = subprocess.run(["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "get", "secret", name, "-o", "json"],
                         capture_output=True, text=True, check=True).stdout
    return {k: base64.b64decode(v).decode() for k, v in json.loads(out)["data"].items()}


def main(incidents):
    creds = secret("kubeheal-minio-client")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    pf = subprocess.Popen(["kubectl", "--context", CONTEXT, "-n", NAMESPACE, "port-forward", "--address",
                           "127.0.0.1", "svc/minio", f"{port}:9000"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.25).close()
                break
            except OSError:
                time.sleep(0.2)
        client = Minio(f"127.0.0.1:{port}", access_key=creds["access-key"], secret_key=creds["secret-key"],
                       secure=False)
        if incidents[:1] == ["--list-since"]:
            since = datetime.fromisoformat(incidents[1].replace("Z", "+00:00"))
            for obj in sorted(client.list_objects(BUCKET, recursive=True), key=lambda o: o.object_name):
                if obj.last_modified and obj.last_modified >= since:
                    print(obj.last_modified.strftime("%H:%M:%S"), obj.object_name)
            return
        for incident in incidents:
            for obj in sorted(client.list_objects(BUCKET, prefix=f"incidents/{incident}/", recursive=True),
                              key=lambda o: o.object_name):
                resp = client.get_object(BUCKET, obj.object_name)
                try:
                    print(resp.read().decode())
                finally:
                    resp.close()
                    resp.release_conn()
    finally:
        pf.terminate()


if __name__ == "__main__":
    main(sys.argv[1:])
