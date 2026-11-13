# F6 invalid request status

**Date:** 2026-11-13  
**Cluster:** `k3d-kubeheal`  
**Mode:** `test`

The Executor validates incident, namespace, deployment, and pod fields before action handling (`agents/executor/validation.py`). This deployment exposes no supported external request endpoint for submitting an arbitrary remediation request. The live action path is stream-driven.

**Status:** rejection-before-write is **not measured live**. Injecting a synthetic or unowned Redis stream entry would alter operational state and would not constitute a supported request. No request was injected and no write was attempted. Validation implementation remains covered by the repository's automated tests; this file records no live test result.
