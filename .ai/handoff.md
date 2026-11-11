# Handoff

- **Agent/date:** Claude Code (builder, subagent), 2026-11-11. Task V5-I2, branch `wave/V5-I2` (worktree `Unisys_Model-wt-V5-I2`), based on `work` (d6852d6). Nothing pushed, no cluster command run.
- **Goal:** LightGBM inference service plus Helm wiring (replaces the neural Health, Security and DCM servers by default).
- **What changed:** `services/inference_server/main.py` (+ `requirements.txt`), `dockerfiles/Dockerfile.inference`, `deploy/helm/kubeheal/templates/inference.yaml`, `modelServers.legacy.enabled` (default false) gating the neural servers and their NetworkPolicies, `INFERENCE_URL` on the health and security agents, `inference:` values in every values file, `.dockerignore` keeps `models/bundles`, `eval/resource_profile.py` knows `kubeheal-inference`, tests (`tests/test_inference_server.py`, `tests/test_platform_chart.py`).
- **Demo scripts:** `demo/` exists only on the `demo` branch. Their change is one commit on branch `wave/V5-I2-demo` (on top of `demo`): `images.ps1`, `hpa_load.ps1`, `k6_health_model.js`. Merge it into `demo` after `wave/V5-I2` is in `work`.
- **Open issues:** Dockerfile never built (no registry network here); hardening on for the inference pod is unverified on a cluster; with defaults nothing scores until V5-D3, D4 and S2 land (set `modelServers.legacy.enabled=true` to keep the neural servers); cluster steps not done (`up.ps1 -Stage images`/`install`, `tests/test_rbac_k3d.py`, real `/readyz` output).
- **Next:** orchestrator review and merge, then the cluster steps in `docs/kubeheal/NEXT_FOR_CODEX.md` Step 2, then V5-D3.
