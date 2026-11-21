#!/usr/bin/env bash
# promtool syntax check of the KubeHeal alert rules (pinned prom/prometheus image; needs docker and a pull on first use).
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 -c 'import sys,yaml; print(yaml.safe_dump({"groups": yaml.safe_load(open(sys.argv[1]))["spec"]["groups"]}))' \
  deploy/k8s/base/alerts/kubeheal-rules.yaml > "$tmp/rules.yaml"
docker run --rm --entrypoint promtool -v "$tmp:/r:ro" prom/prometheus:v2.55.1 check rules /r/rules.yaml
