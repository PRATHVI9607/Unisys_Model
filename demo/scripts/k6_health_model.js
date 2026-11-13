import http from 'k6/http';
import { check } from 'k6';

// V5-I2: load on the LightGBM inference service, POST /v1/health/predict.
const endpoint = __ENV.INFERENCE_URL || 'http://kubeheal-inference:8000/v1/health/predict';

// Every feature name of the shipped health bundle (models/bundles/health/meta.json, "features") with an
// illustrative value for an unchanged, healthy workload. The values are plausible placeholders, NOT measured data.
// The service answers 422 for a name it does not know; tests/test_inference_server.py checks this list against
// the bundle when this file exists.
const features = {
  cpu_limit_ratio: 1.0, cpu_request_ratio: 1.0, mem_limit_ratio: 1.0, mem_request_ratio: 1.0,
  cpu_limit_removed: 0, mem_limit_removed: 0, replicas_ratio: 1.0, replicas_to_zero: 0,
  image_changed: 0, image_unpinned: 0, privileged_added: 0, root_user_added: 0, capabilities_added: 0,
  host_namespace_added: 0, host_path_added: 0, probe_changed: 0, probe_removed: 0,
  env_count_delta: 0, env_values_changed: 0, volume_mounts_removed: 0, containers_delta: 0,
  command_changed: 0, n_changed_fields: 0, spec_changed: 0,
  cpu_util_mean: 0.3, cpu_util_max: 0.5, cpu_throttle_mean: 0.0, mem_util_mean: 0.4, mem_util_max: 0.5,
  latency_p99_mean_s: 0.1, latency_p99_max_s: 0.2, latency_trend: 0.0, error_ratio: 0.0,
  request_rate_log: 2.0, restarts_delta: 0, ready_ratio: 1.0,
};
const body = JSON.stringify({ features });

export const options = {
  vus: Number(__ENV.K6_VUS || 32),
  duration: __ENV.K6_DURATION || '90s',
  discardResponseBodies: true,
  thresholds: { checks: ['rate>0.995'] },
};

// The startup investigation found first-timestamp refusals in previous runs. These five
// sequential setup requests are reported as warm-up and are never retried or discarded. k6's
// aggregate request/check metrics include setup requests, so the raw summary includes them.
export function setup() {
  const count = 5;
  console.log(`WARM-UP START: ${count} sequential inference requests before the measured VU stage`);
  let passed = 0;
  for (let i = 0; i < count; i++) {
    const response = http.post(endpoint, body, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '10s',
    });
    if (check(response, { 'warm-up inference returned 200': (r) => r.status === 200 })) passed++;
    if (response.status !== 200) {
      console.log(`WARM-UP FAILED: ${passed}/${count} returned 200; request ${i + 1} returned ${response.status}`);
      throw new Error(`warm-up request ${i + 1}/${count} returned ${response.status}`);
    }
  }
  console.log(`WARM-UP COMPLETE: ${passed}/${count} returned 200; all requests remain in aggregate k6 metrics`);
  return { warmupRequests: count, warmupSucceeded: passed };
}

export default function () {
  const response = http.post(endpoint, body, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
  });
  check(response, { 'inference returned 200': (r) => r.status === 200 });
}
