import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  insecureSkipTLSVerify: true,
  noConnectionReuse: false,
//   thresholds: {
//     // Assert that 99% of requests finish within 3000ms.
//     http_req_duration: ["p(99) < 3000"],
//   },
  // Ramp the number of virtual users up and down
  stages: [
    { duration: '1m', target: 500 },
    // { duration: '1m30s', target: 10 },
    // { duration: '20s', target: 0 },
  ],
};

export default function () {
  const res = http.get('http://localhost/api/user/b5403552-6cde-4eef-9cee-18dba0fd319e/image');
  // Validate response status
  check(res, { 'status was 200': (r) => r.status == 200 });
  sleep(1);
}