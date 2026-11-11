import http from 'k6/http';
import { check } from 'k6';

const endpoint = __ENV.HEALTH_MODEL_URL || 'http://kubeheal-health-model:8001/health/score';

export const options = {
  vus: Number(__ENV.K6_VUS || 32),
  duration: __ENV.K6_DURATION || '90s',
  discardResponseBodies: true,
  thresholds: { checks: ['rate>0.995'] },
};

export default function () {
  const response = http.post(endpoint, JSON.stringify({ old_spec: {}, new_spec: {} }), {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
  });
  check(response, { 'health model returned 200': (r) => r.status === 200 });
}
