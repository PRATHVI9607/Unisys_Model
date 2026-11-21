# Changelog

## [1.0.0]

- Alerts use real metrics: `kubeheal_fusion_approvals_pending`, `kubeheal_fusion_circuit_opens_total`, `kubeheal_security_event_source`
  (`KubeHealSensorDown` skips Falco installs, env `EVENT_SOURCE`), and the `redis_exporter` sidecar (production only).
- Scripts find the Redis primary under Redis HA (`deploy/scripts/lib/redis.sh`). oauth2-proxy is digest-pinned.
- Smaller images: agents 464 to 335 MB, inference 425 to 296 MB, dashboard 249 to 180 MB.

- Multi-arch images (linux/amd64, linux/arm64) for inference, agents, dashboard, chaos and the eBPF sensor, published to
  `ghcr.io/prathvi9607/kubeheal-<name>:<version>`, signed with cosign (keyless) with SBOM and provenance attestations.
- Helm chart published as an OCI artifact: `oci://ghcr.io/prathvi9607/charts/kubeheal`; chart images default to the GHCR
  images at the chart `appVersion`. `values-dev.yaml` keeps the locally built `kubeheal.invalid/*` images.
- eBPF sensor runs on arm64 (AWS Graviton, Ampere, Apple-silicon k3d): arch-specific syscall-number mapping, per-arch BPF build.
- `install.sh --platform`; `--production` pushes multi-arch images with buildx.
