"""Read-only: print the ledger entries of the given incident ids from MinIO (k3d-kubeheal only)."""
import base64
import json
import socket
import subprocess
import sys
import time

from minio import Minio

CTX, NS, BUCKET = "k3d-kubeheal", "kubeheal", "kubeheal-ledger"


def secret(name):
    out = subprocess.run(["kubectl", "--context", CTX, "-n", NS, "get", "secret", name, "-o", "json"],
                         capture_output=True, text=True, check=True).stdout
    return {k: base64.b64decode(v).decode() for k, v in json.loads(out)["data"].items()}


cl = secret("kubeheal-minio-client")
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
pf = subprocess.Popen(["kubectl", "--context", CTX, "-n", NS, "port-forward", "--address", "127.0.0.1",
                       "svc/minio", f"{port}:9000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.25).close()
            break
        except OSError:
            time.sleep(0.2)
    m = Minio(f"127.0.0.1:{port}", access_key=cl["access-key"], secret_key=cl["secret-key"], secure=False)
    for inc in sys.argv[1:]:
        print(f"== incident {inc}")
        for obj in sorted(m.list_objects(BUCKET, prefix=f"incidents/{inc}/", recursive=True),
                          key=lambda o: o.object_name):
            r = m.get_object(BUCKET, obj.object_name)
            rec = json.loads(r.read())
            r.close()
            print(rec["sequence"], rec["timestamp"], rec["step"], json.dumps(rec["payload"], sort_keys=True))
finally:
    pf.terminate()
