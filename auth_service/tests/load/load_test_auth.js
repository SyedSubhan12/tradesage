import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 100 }, // ramp up to 100 users over 1 minute
    { duration: '3m', target: 100 }, // stay at 100 users for 3 minutes
    { duration: '1m', target: 0 },  // ramp down to 0 users over 1 minute
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500'], // 95% of requests should be below 500ms
    'http_req_failed': ['rate<0.01'],   // http errors should be less than 1%
  },
};

export default function () {
  const BASE_URL = 'http://localhost:8001'; // Adjust if your auth service runs on a different port

  // 1. Register a new user
  const registerPayload = JSON.stringify({
    email: `testuser_${__VU}_${__ITER}@example.com`,
    username: `testuser_${__VU}_${__ITER}`,
    password: 'TestPassword123!',
    first_name: 'Test',
    last_name: 'User',
    tenant_id: '00000000-0000-0000-0000-000000000001', // Use a fixed tenant ID for load testing
  });
  const registerHeaders = { 'Content-Type': 'application/json' };
  let res = http.post(`${BASE_URL}/register`, registerPayload, { headers: registerHeaders });
  check(res, { 'registered successfully': (resp) => resp.status === 200 });

  // 2. Login to get tokens
  const loginPayload = {
    username: `testuser_${__VU}_${__ITER}@example.com`,
    password: 'TestPassword123!',
    tenant_id: '00000000-0000-0000-0000-000000000001',
    grant_type: 'password',
  };
  const loginHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' };
  res = http.post(`${BASE_URL}/token`, loginPayload, { headers: loginHeaders });
  check(res, { 'logged in successfully': (resp) => resp.status === 200 });
  const accessToken = res.json('access_token');
  const refreshToken = res.json('refresh_token');

  // 3. Verify access token
  if (accessToken) {
    const authHeaders = { 'Authorization': `Bearer ${accessToken}` };
    res = http.get(`${BASE_URL}/verify-token`, { headers: authHeaders });
    check(res, { 'access token verified': (resp) => resp.status === 200 });
  }

  // 4. Refresh token (less frequent)
  if (__ITER % 5 === 0 && refreshToken) { // Refresh every 5 iterations for a given VU
    const refreshHeaders = { 'Authorization': `Bearer ${refreshToken}` };
    res = http.post(`${BASE_URL}/refresh`, null, { headers: refreshHeaders });
    check(res, { 'token refreshed': (resp) => resp.status === 200 });
  }

  sleep(1);
  }