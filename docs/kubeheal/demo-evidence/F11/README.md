# F11 HPA evidence index

- The first attempt on 2026-11-12 failed before measurement because PowerShell `Out-String -NoNewline` flattened the JS source and k6 reported `no exported functions in script`. Cleanup removed its temporary Job, ConfigMap, and NetworkPolicy.
- The staging fix is in `6f97f88`; the later successful run is recorded in [hpa-run-2026-11-12.md](hpa-run-2026-11-12.md).
- The earlier successful run is in `hpa-run-2026-11-12.md`. A post-merge repeat scaled 2 -> 8 -> 2 but had 12/99,431 connection refusals; its full output and Grafana dashboard/Prometheus API evidence are in that report and `grafana-hpa-api-2026-11-12.json`.
- Grafana has no image renderer installed and browser access was unavailable, so a visual dashboard screenshot is still pending for runbook rehearsal.
- The 2026-11-13 demo-image rerun also scaled 2 -> 8 -> 2 but had 12 first-timestamp connection refusals out of 72,328 requests; median 37.49 ms and p95 61.87 ms are observed only on this failed run. See [rerun transcript](hpa-run-2026-11-13.txt). It is not accepted as a clean result; exact refusal cause remains unproven.

## Clean 2026-11-13 rerun

- 32 VUs for 90 seconds, with 5 seconds for NetworkPolicy propagation before k6 pod creation and a further 5-second network settling delay before five sequential warm-up requests. All five returned 200. Warm-up requests remain included in k6 aggregate checks and request counts.
- The measured stage passed 113,873/113,873 checks with 0 failed requests. Median latency was 24.03 ms and p95 was 37.9 ms.
- Inference HPA scaled 2 -> 8 -> 2. It returned to 2/2 within the script's 330-second scale-down wait. The full rehearsal took 12m29s because it first waited for the previous P11 scale-down to reach the required 2/2 baseline.
- Raw transcript: [hpa-run-2026-11-13-clean-warmup.txt](hpa-run-2026-11-13-clean-warmup.txt).
- Grafana screenshot: [grafana-f11-2026-11-13.png](grafana-f11-2026-11-13.png). The initial screenshot had panel query errors because the dashboard used datasource UID `${DS_PROMETHEUS}`. The deployed datasource UID is `prometheus`; the dashboard was corrected, the live ConfigMap refreshed, and this screenshot shows the fixed dashboard. Some panels with no corresponding sample remain empty.

## First-request refusal investigation

The failed P11 and F11 warm-up requests received TCP `connection refused` from Service IP `10.43.219.57:8000`; no HTTP response was received. Both inference pods had been Ready for hours and were present in the Service EndpointSlice. F11 created its run-specific NetworkPolicy about 0.55 seconds before creating its k6 pod. Health-agent and inference-pod probes to the Service subsequently returned 200. After adding a 5-second policy settling wait and a 5-second in-pod network settling delay, P11 and F11 both completed cleanly with 5/5 warm-up requests and no failed measured requests. This supports a startup race on the new k6 pod's Service path; it does not identify whether kube-proxy, CNI policy programming, or another component issued the refusals.
