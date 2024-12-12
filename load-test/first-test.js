import http from 'k6/http';
import { check, sleep } from 'k6';

const file_bin = open('./img.png', 'rb');

export const options = {
  insecureSkipTLSVerify: true,
  noConnectionReuse: false,
//   thresholds: {
//     // Assert that 99% of requests finish within 3000ms.
//     http_req_duration: ["p(99) < 3000"],
//   },
  // Ramp the number of virtual users up and down
  stages: [
    { duration: '10s', target: 1 },
    // { duration: '1m30s', target: 10 },
    // { duration: '20s', target: 0 },
  ],
};

export default function () {
  const auth = http.post('http://localhost/api/auth/login', {
    username: 'admin',
    password: 'changeme',
    grant_type: 'password'
  }).json()
  const me = http.get('http://localhost/api/user/me', {
    headers: {
      Authorization: `Bearer ${auth.access_token}`
    }
  }).json()
  if (me.profile_picture) {
    const del = http.del('http://localhost/api/file/' + me.profile_picture.id, {
      headers: {
        Authorization: `Bearer ${auth.access_token}`
      }
    });
  }
  const img = http.get('http://localhost/api/user/' + me.uuid + '/image');
  const new_img = http.put('http://localhost/api/user/' + me.uuid + '/image', file_bin, {
    contentType: 'image/jpeg',
    headers: {
      Authorization: `Bearer ${auth.access_token}`
    }
  })
  const img_new = http.get('http://localhost/api/user/' + me.uuid + '/image');
  // Validate response status
  // check(img, { 'status was 200': (r) => r.status == 200 });
  sleep(1);
}