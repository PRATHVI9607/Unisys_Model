#!/usr/bin/env bash
# Delete the k3d lab cluster `kubeheal` and its context (kubeconfig selection: see create.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/deploy/k3d/lib.sh"
k3d cluster delete kubeheal
