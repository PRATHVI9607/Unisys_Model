# F4 HMAC evidence

## Demo image rerun, 2026-11-13

- Context: `k3d-kubeheal`; Helm revision 15; images built from `demo` with tag `b20261113071011`.
- Mode: `test` before and after.
- Command: `.venv\Scripts\python.exe scripts\containment_hmac_smoke.py --timeout-s 60`.
- Output: `hmac-smoke-demo-2026-11-13.txt`.
- Signed message: accepted as `dry_run`; result HMAC valid.
- Unsigned message: refused with `invalid_hmac`; signed refusal result verified.
- Tampered message: refused with `invalid_hmac`; signed refusal result verified.
- Run-owned Redis messages/results were removed. No Kubernetes workload write occurred. This proves signature validation in test mode, not enforcement behavior.
