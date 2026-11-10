#!/usr/bin/env python3
"""
Golden baseline admin tool (the documented reset path for S-HA-2).

The Health Agent writes `kubeheal:baseline:<namespace>:<deployment>` once, with SET NX, the first
time it sees a labelled Deployment. Nothing else overwrites it. Use this tool when a configuration
change is intentional and the new configuration should become the golden baseline.

    python scripts/baseline_tool.py list
    python scripts/baseline_tool.py show  <namespace> <deployment>
    python scripts/baseline_tool.py reset <namespace> <deployment>

`reset` deletes the key. The agent records the live spec as the new golden baseline the next time
it sees an event for that Deployment (touch the Deployment, for example by adding an annotation).

Redis URL comes from REDIS_URL (default redis://localhost:6379). In the cluster, port-forward first:
    kubectl --context k3d-kubeheal -n kubeheal port-forward svc/redis-master 6379:6379
"""

import argparse
import json
import os
import sys

import redis

PREFIX = "kubeheal:baseline:"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for name in ("show", "reset"):
        p = sub.add_parser(name)
        p.add_argument("namespace")
        p.add_argument("deployment")
    args = ap.parse_args(argv)

    r = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"),
                             decode_responses=True)
    if args.cmd == "list":
        for key in sorted(r.scan_iter(PREFIX + "*")):
            rec = json.loads(r.get(key))
            print(f"{key[len(PREFIX):]}\tstored_at={rec.get('stored_at')}")
        return 0
    key = f"{PREFIX}{args.namespace}:{args.deployment}"
    if args.cmd == "show":
        raw = r.get(key)
        if raw is None:
            print("no baseline recorded", file=sys.stderr)
            return 1
        print(json.dumps(json.loads(raw), indent=2, sort_keys=True))
        return 0
    if args.cmd == "reset":
        print("deleted" if r.delete(key) else "no baseline recorded")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
