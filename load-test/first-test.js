import http from 'k6/http';
import { check, sleep } from 'k6';

const binFile = open('./img.png', 'b');

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
  // check if the user already exists
  const get_auth_exists = http.post('http://localhost/api/auth/login', {
    username: 'test_user',
    password: 'qwertyQWERTY1234!@#$',
    grant_type: 'password'
  })
  if (get_auth_exists.status != 200) {
    const user = http.post('http://localhost/api/auth/register', {
      username: 'test_user',
      email: 'user@example.com',
      password: 'qwertyQWERTY1234!@#$',
      confirm_password: 'qwertyQWERTY1234!@#$',
    }, {
      headers: {
        contentType: 'application/x-www-form-urlencoded'
      }
    }).json()
    http.post('http://localhost/api/auth/logout', null, {
      headers: {
        Authorization: `Bearer ${user.access_token}`
      }
    })
  }
  const get_auth = http.post('http://localhost/api/auth/login', {
    username: 'test_user',
    password: 'qwertyQWERTY1234!@#$',
    grant_type: 'password'
  }).json()
  let me = http.get('http://localhost/api/user/me', {
    headers: {
      Authorization: `Bearer ${get_auth.access_token}`
    }
  }).json()
  if (me.profile_picture) {
    http.del('http://localhost/api/file/' + me.profile_picture.id, null, {
      headers: {
        Authorization: `Bearer ${get_auth.access_token}`
      }
    });
    me = http.get('http://localhost/api/user/me', {
      headers: {
        Authorization: `Bearer ${get_auth.access_token}`
      }
    }).json()
  }
  const get_img_exists = http.get('http://localhost/api/user/' + me.uuid + '/image');
  if (!me.profile_picture) {
    const put_img_new = http.put('http://localhost/api/user/' + me.uuid + '/image', {
      file: http.file(binFile, 'test.png'),
    }, {
      headers: {
        Authorization: `Bearer ${get_auth.access_token}`
      }
    })
  }
  const get_img_new = http.get('http://localhost/api/user/' + me.uuid + '/image');
  const del_test_user = http.del('http://localhost/api/user/' + me.uuid, null, {
    headers: {
      Authorization: `Bearer ${get_auth.access_token}`
    }
  });
  // Validate response status
  // check(img, { 'status was 200': (r) => r.status == 200 });
  sleep(1);
}