#!/usr/bin/env python3
"""
Golden baseline admin tool (an allowed overwrite path of the golden baseline).

The Health Agent writes `kubeheal:baseline:<namespace>:<deployment>` the first time it sees a labelled
Deployment (SET NX). After that the key is overwritten only by a PROMOTION (V5-D5: automatic in dev and staging
when the assessment is benign, certain and the rollout is complete; approved in the dashboard in prod, see
`agents/health_agent/baseline.py`) and by this tool. Use this tool when a configuration change is intentional and
the new configuration should become the golden baseline, or to put back a baseline kept in the ledger.

    python scripts/baseline_tool.py list
    python scripts/baseline_tool.py show       <namespace> <deployment>
    python scripts/baseline_tool.py reset      <namespace> <deployment>
    python scripts/baseline_tool.py candidates
    python scripts/baseline_tool.py restore    <namespace> <deployment> <ledger-entry.json> [--force]

`reset` deletes the key. The agent records the live spec as the new golden baseline the next time it sees an
event for that Deployment (touch the Deployment, for example by adding an annotation).

`candidates` lists the pending prod promotion candidates (`kubeheal:baseline-candidate:*`).

`restore` writes back the PREVIOUS golden record kept in a promotion's ledger entry: download the object
`incidents/baseline.<namespace>.<deployment>/NNNNNN-baseline_promoted.json` from the ledger bucket and pass the
file. The entry must belong to the same workload. `restore` prints the digest of the current golden record and
REFUSES unless --force when any of these holds: the current golden record's `promotion.ledger_key` is not the
entry being restored from (the entry's key is incidents/<incident_id>/<sequence>-<step>.json), so the restore
would not be a clean undo of the latest promotion; the current golden's `promotion.previous_text_sha256` differs
from the entry's (the chain does not match); the entry's `previous` record does not hash to its own
`previous_text_sha256` (the file was altered); or there is no current golden record (after `reset`).
A candidate assessed against the replaced baseline becomes
stale on its own (approving it reports `stale` and ledgers the supersession). Like `reset`, the tool is an
operator action and does not write a ledger entry itself.

Redis URL comes from REDIS_URL (default redis://localhost:6379). In the cluster, port-forward first:
    kubectl --context k3d-kubeheal -n kubeheal port-forward svc/redis-master 6379:6379
"""

import argparse
import hashlib
import json
import os
import sys

import redis

PREFIX = "kubeheal:baseline:"
CANDIDATE_PREFIX = "kubeheal:baseline-candidate:"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("candidates")
    for name in ("show", "reset"):
        p = sub.add_parser(name)
        p.add_argument("namespace")
        p.add_argument("deployment")
    rp = sub.add_parser("restore")
    rp.add_argument("namespace")
    rp.add_argument("deployment")
    rp.add_argument("ledger_entry", help="a baseline_promoted ledger entry (JSON file)")
    rp.add_argument("--force", action="store_true",
                    help="restore even when the entry is not the latest promotion of the current golden record")
    args = ap.parse_args(argv)

    r = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"),
                             decode_responses=True)
    if args.cmd == "list":
        for key in sorted(r.scan_iter(PREFIX + "*")):
            rec = json.loads(r.get(key))
            print(f"{key[len(PREFIX):]}\tstored_at={rec.get('stored_at')}")
        return 0
    if args.cmd == "candidates":
        for key in sorted(r.scan_iter(CANDIDATE_PREFIX + "*")):
            cand = json.loads(r.get(key) or "{}")
            print(f"{key[len(CANDIDATE_PREFIX):]}	candidate_id={cand.get('candidate_id')}	"
                  f"tier={cand.get('tier')}	created_at={cand.get('created_at')}")
        return 0
    key = f"{PREFIX}{args.namespace}:{args.deployment}"
    if args.cmd == "restore":
        with open(args.ledger_entry, encoding="utf-8") as fh:
            entry = json.load(fh)
        payload = entry.get("payload") or {}
        previous = payload.get("previous")
        if (entry.get("step") != "baseline_promoted" or not isinstance(previous, dict) or not previous.get("spec")
                or payload.get("namespace") != args.namespace or payload.get("deployment") != args.deployment):
            print("not a baseline_promoted ledger entry of this workload with a previous record", file=sys.stderr)
            return 1
        current_raw = r.get(key)
        current = json.loads(current_raw) if current_raw else None
        print("current golden digest: " + (hashlib.sha256(current_raw.encode()).hexdigest() if current_raw
                                           else "none (no golden record)"))
        entry_key = f"incidents/{entry.get('incident_id')}/{int(entry.get('sequence') or 0):06d}-{entry.get('step')}.json"
        promo = (current or {}).get("promotion") or {}
        problems = []
        if current is None:
            problems.append("there is no current golden record")
        elif promo.get("ledger_key") != entry_key:
            problems.append(f"the current golden record was written by {promo.get('ledger_key')!r}, not by {entry_key!r}")
        elif promo.get("previous_text_sha256") != payload.get("previous_text_sha256"):
            problems.append("the promotion chain does not match (previous_text_sha256 differs)")
        if hashlib.sha256(json.dumps(previous, sort_keys=True).encode()).hexdigest() != payload.get("previous_text_sha256"):
            problems.append("the entry's previous record does not match its own previous_text_sha256")
        if problems and not args.force:
            for problem in problems:
                print("refused: " + problem, file=sys.stderr)
            print("use --force to restore anyway", file=sys.stderr)
            return 1
        r.set(key, json.dumps(previous, sort_keys=True))
        print(f"restored the previous baseline of {args.namespace}/{args.deployment}"
              + (" (forced)" if problems else ""))
        return 0
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
