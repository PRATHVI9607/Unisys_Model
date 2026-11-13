# Vendored demo charts

These pinned Helm chart packages are the complete external chart inputs used by `demo/k3d/up.ps1`.
The setup script installs these local archives directly and does not add or update a Helm repository.

| Chart | Version | Source | SHA-256 |
|---|---:|---|---|
| `kube-prometheus-stack` | 65.5.1 | `https://prometheus-community.github.io/helm-charts` | `85d955d80c6ba4238f68c69877637ef440913ed772530c9ceee4e9c65d8f11fd` |
| `prometheus-adapter` | 4.11.0 | `https://prometheus-community.github.io/helm-charts` | `5eca90ca7f3a15a8d6eac10320784b0c552e4691b520732e9ab0595ad755a7db` |

The kube-prometheus-stack archive includes its upstream `Chart.lock` and packaged subcharts, including
Grafana and kube-state-metrics. The adapter archive has no chart dependencies. Verify the archive hashes
before changing either pinned version. Container image availability remains separate from Helm chart
availability; a truly air-gapped installation also needs those images in the local registry.
