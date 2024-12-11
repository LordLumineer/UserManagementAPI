import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  insecureSkipTLSVerify: true,
  noConnectionReuse: false,
  thresholds: {
    // Assert that 99% of requests finish within 3000ms.
    http_req_duration: ["p(99) < 3000"],
  },
  // Ramp the number of virtual users up and down
  stages: [
    { duration: '5m', target: 500 },
    { duration: '10m', target: 500 },
    { duration: '5m', target: 0 },
  ],
};

export default function () {
  const res = http.get('http://localhost/api/user/eef968e2-7989-4000-af26-2e874cae8e1c/image');
  // Validate response status
  check(res, { 'status was 200': (r) => r.status == 200 });
  sleep(1);
}