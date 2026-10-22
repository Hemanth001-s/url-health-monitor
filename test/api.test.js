'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApp } = require('../src/server');
const { checkUrl, validateUrl, isPrivateIp } = require('../src/checker');
const log = require('../src/logger');

log.setSink(() => {}); // keep test output clean

let target, targetPort, app, base;
let flaky = 0;

before(async () => {
  target = http.createServer((req, res) => {
    if (req.url === '/ok') { res.writeHead(200); res.end('hi'); }
    else if (req.url === '/boom') { res.writeHead(500); res.end(); }
    else if (req.url === '/redir') { res.writeHead(302, { location: '/ok' }); res.end(); }
    else if (req.url === '/flaky') { res.writeHead(++flaky < 2 ? 503 : 200); res.end(); } // fails once, then recovers
    else if (req.url.startsWith('/slow')) { setTimeout(() => { res.writeHead(200); res.end('slow'); }, 300); }
    else if (req.url === '/hang') { /* never answers */ }
    else { res.writeHead(404); res.end(); }
  });
  await new Promise((r) => target.listen(0, '127.0.0.1', r));
  targetPort = target.address().port;
  app = createApp({ port: 0, dbPath: ':memory:', jwtSecret: 'test-secret', allowPrivateTargets: true, timeoutMs: 800, retries: 1,
    retryBaseMs: 10, concurrency: 10, adminEmail: 'admin@test.io', authRateLimitPerMin: 1000, schedulerTickMs: 3600_000 });
  base = `http://127.0.0.1:${await app.start()}`;
});
after(async () => { await app.stop(); target.close(); target.closeAllConnections?.(); });

const T = (p) => `http://127.0.0.1:${targetPort}${p}`;
async function api(method, path, { token, body } = {}) {
  const res = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => null), headers: res.headers };
}
async function signup(email) { const r = await api('POST', '/api/auth/signup', { body: { email, password: 'correct horse battery' } }); assert.equal(r.status, 201); return r.body.token; }
async function waitFor(fn, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = await fn(); if (v) return v; await new Promise((r) => setTimeout(r, 25)); }
  throw new Error('waitFor timed out');
}
const byUrl = async (token, suffix) => (await api('GET', '/api/urls', { token })).body.urls.find((u) => u.url.endsWith(suffix));

test('validateUrl and SSRF helpers', () => {
  assert.equal(validateUrl('not a url').ok, false);
  assert.equal(validateUrl('ftp://example.com').ok, false);
  assert.equal(validateUrl('https://user:pw@example.com').ok, false);
  assert.equal(validateUrl('https://www.google.com').url, 'https://www.google.com/');
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.9', '172.20.0.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:127.0.0.1']) assert.ok(isPrivateIp(ip), ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '2606:4700::1111']) assert.ok(!isPrivateIp(ip), ip);
});

test('auth: signup, duplicate, weak password, login, protected routes', async () => {
  assert.equal((await api('POST', '/api/auth/signup', { body: { email: 'bad', password: 'longenough1' } })).status, 400);
  assert.equal((await api('POST', '/api/auth/signup', { body: { email: 'a@test.io', password: 'short' } })).status, 400);
  await signup('a@test.io');
  assert.equal((await api('POST', '/api/auth/signup', { body: { email: 'A@test.io', password: 'correct horse battery' } })).status, 409);
  assert.equal((await api('POST', '/api/auth/login', { body: { email: 'a@test.io', password: 'wrong password!' } })).status, 401);
  const ok = await api('POST', '/api/auth/login', { body: { email: 'a@test.io', password: 'correct horse battery' } });
  assert.equal(ok.status, 200);
  assert.match(ok.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  assert.equal((await api('GET', '/api/urls')).status, 401);
  assert.equal((await api('GET', '/api/urls', { token: 'garbage.token.here' })).status, 401);
  assert.equal((await api('GET', '/api/me', { token: ok.body.token })).body.user.email, 'a@test.io');
  assert.ok(ok.headers.get('x-correlation-id'));
});

test('health checks: UP / DOWN / redirect / 5xx / invalid / DNS / timeout classified correctly', async () => {
  const token = await signup('checks@test.io');
  const add = await api('POST', '/api/urls', { token, body: { urls: [T('/ok'), T('/missing'), T('/boom'), T('/redir'), T('/hang'),
    'http://does-not-exist.invalid/', 'not a url', T('/ok')] } });
  assert.equal(add.status, 201);
  assert.equal(add.body.added.length, 6);
  assert.equal(add.body.rejected.length, 1);
  assert.equal(add.body.duplicates.length, 1);

  await waitFor(async () => (await api('GET', '/api/urls', { token })).body.urls.every((u) => u.last_status));
  const get = async (s) => byUrl(token, s);
  assert.equal((await get('/ok')).last_status, 'UP');
  assert.equal((await get('/redir')).last_status, 'UP');           // redirect followed to /ok
  const missing = await get('/missing');
  assert.equal(missing.last_status, 'DOWN'); assert.equal(missing.last_status_code, 404);
  assert.equal((await get('/boom')).last_error_type, 'HTTP_5XX');
  assert.equal((await get('/hang')).last_error_type, 'TIMEOUT');
  assert.equal((await get('.invalid/')).last_error_type, 'DNS_FAILURE');
});

test('checks run CONCURRENTLY, not sequentially', async () => {
  const token = await signup('conc@test.io');
  const urls = Array.from({ length: 20 }, (_, i) => T(`/slow${i}`)); // each takes 300ms
  await api('POST', '/api/urls', { token, body: { urls, check: false } });
  const t0 = Date.now();
  const r = await api('POST', '/api/checks/run', { token, body: {} });
  assert.equal(r.status, 202); assert.equal(r.body.queued, 20);
  await waitFor(async () => (await api('GET', '/api/urls', { token })).body.urls.every((u) => u.last_status));
  const elapsed = Date.now() - t0;
  // Sequential would be >= 6000ms. 20 jobs / 10 workers * 300ms ~= 600ms.
  assert.ok(elapsed < 2000, `took ${elapsed}ms`);
});

test('duplicate triggers are de-duplicated while a check is in flight', async () => {
  const token = await signup('dedupe@test.io');
  const { body } = await api('POST', '/api/urls', { token, body: { urls: [T('/slow-dedupe')], check: false } });
  const id = body.added[0].id;
  const a = await api('POST', '/api/checks/run', { token, body: { ids: [id] } });
  const b = await api('POST', '/api/checks/run', { token, body: { ids: [id] } });
  assert.equal(a.body.queued, 1); assert.equal(b.body.queued, 0); assert.equal(b.body.alreadyQueued, 1);
});

test('retry with backoff recovers from a transient 5xx and records attempts', async () => {
  flaky = 0;
  const r = await checkUrl(T('/flaky'), { timeoutMs: 800, retries: 2, retryBaseMs: 10, allowPrivateTargets: true });
  assert.equal(r.status, 'UP'); assert.equal(r.attempts, 2);
  const nr = await checkUrl(T('/missing'), { timeoutMs: 800, retries: 2, retryBaseMs: 10, allowPrivateTargets: true });
  assert.equal(nr.attempts, 1, '4xx is not retried');
});

test('SSRF: private targets are blocked unless explicitly allowed', async () => {
  const r = await checkUrl(T('/ok'), { timeoutMs: 800, retries: 0, retryBaseMs: 1, allowPrivateTargets: false });
  assert.equal(r.status, 'DOWN'); assert.equal(r.errorType, 'BLOCKED_TARGET');
});

test('multi-tenant isolation: users cannot see or modify each other\'s URLs', async () => {
  const a = await signup('iso-a@test.io'), b = await signup('iso-b@test.io');
  const { body } = await api('POST', '/api/urls', { token: a, body: { urls: [T('/ok')], check: false } });
  const id = body.added[0].id;
  assert.equal((await api('GET', '/api/urls', { token: b })).body.urls.length, 0);
  assert.equal((await api('DELETE', `/api/urls/${id}`, { token: b })).status, 404);
  assert.equal((await api('GET', `/api/urls/${id}/stats`, { token: b })).status, 404);
  assert.equal((await api('GET', `/api/urls/${id}/results`, { token: b })).status, 404);
  assert.equal((await api('POST', '/api/checks/run', { token: b, body: { ids: [id] } })).body.requested, 0);
  assert.equal((await api('DELETE', `/api/urls/${id}`, { token: a })).status, 200);
});

test('reports: summary, per-URL stats, paginated history', async () => {
  const token = await signup('report@test.io');
  const { body } = await api('POST', '/api/urls', { token, body: { urls: [T('/ok'), T('/missing')], check: false } });
  const [missing, ok] = body.added.map((u) => u.id); // newest first not guaranteed; map by url instead
  const okId = body.added.find((u) => u.url.endsWith('/ok')).id;
  const missId = body.added.find((u) => u.url.endsWith('/missing')).id;
  for (let i = 0; i < 3; i++) {
    await api('POST', '/api/checks/run', { token, body: {} });
    await waitFor(async () => (await api('GET', `/api/urls/${okId}/results`, { token })).body.results.length >= i + 1 && (await api('GET', `/api/urls/${missId}/results`, { token })).body.results.length >= i + 1);
  }
  const s = (await api('GET', '/api/summary', { token })).body;
  assert.equal(s.totalUrls, 2); assert.equal(s.checks, 6); assert.equal(s.failures, 3);
  assert.equal(s.uptimePct, 50); assert.equal(s.failureRatePct, 50); assert.equal(s.currentlyUp, 1); assert.equal(s.currentlyDown, 1);
  assert.ok(s.avgResponseMs >= 0);
  const st = (await api('GET', `/api/urls/${okId}/stats`, { token })).body;
  assert.equal(st.uptimePct, 100); assert.equal(st.checks, 3); assert.ok(st.p95ResponseMs >= 0); assert.ok(st.hourly.length >= 1);
  const p1 = (await api('GET', `/api/urls/${okId}/results?limit=2`, { token })).body;
  assert.equal(p1.results.length, 2);
  const p2 = (await api('GET', `/api/urls/${okId}/results?limit=2&before=${p1.nextBefore}`, { token })).body;
  assert.equal(p2.results.length, 1);
});

test('scheduling: due URLs are enqueued by the scheduler and rescheduled', async () => {
  const token = await signup('sched@test.io');
  const { body } = await api('POST', '/api/urls', { token, body: { urls: [T('/ok')], intervalMinutes: 5, check: false } });
  const id = body.added[0].id;
  assert.equal(app.service.enqueueDue(), 0); // not due yet
  app.db.prepare('UPDATE urls SET next_check_at=? WHERE id=?').run(Date.now() - 1000, id);
  assert.equal(app.service.enqueueDue(), 1);
  await waitFor(async () => (await byUrl(token, '/ok')).last_status === 'UP');
  const row = app.db.prepare('SELECT next_check_at FROM urls WHERE id=?').get(id);
  assert.ok(row.next_check_at > Date.now() + 4 * 60_000);
  const hist = (await api('GET', `/api/urls/${id}/results`, { token })).body.results;
  assert.equal(hist[0].trigger, 'scheduled');
  assert.equal((await api('PATCH', `/api/urls/${id}`, { token, body: { intervalMinutes: 0 } })).status, 200);
  assert.equal((await api('PATCH', `/api/urls/${id}`, { token, body: { intervalMinutes: 99999 } })).status, 400);
});

test('role-based access: admin endpoints', async () => {
  const user = await signup('plain@test.io');
  const admin = await signup('admin@test.io');
  assert.equal((await api('GET', '/api/admin/users', { token: user })).status, 403);
  const users = await api('GET', '/api/admin/users', { token: admin });
  assert.equal(users.status, 200); assert.ok(users.body.users.some((u) => u.role === 'admin'));
  const ov = (await api('GET', '/api/admin/overview', { token: admin })).body;
  assert.ok(ov.queue.concurrency === 10 && ov.checksSinceBoot.total > 0);
});

test('SSE pushes live check results', async () => {
  const token = await signup('sse@test.io');
  const res = await fetch(base + '/api/events', { headers: { authorization: `Bearer ${token}` } });
  assert.equal(res.headers.get('content-type'), 'text/event-stream');
  const reader = res.body.getReader();
  await api('POST', '/api/urls', { token, body: { urls: [T('/ok')] } });
  let buf = '';
  const dec = new TextDecoder();
  await waitFor(async () => { const { value } = await reader.read(); buf += dec.decode(value || new Uint8Array()); return buf.includes('event: check.completed'); });
  assert.match(buf, /"status":"UP"/);
  await reader.cancel();
});

test('rate limiting on auth endpoints and CSRF guards', async () => {
  const limited = createApp({ port: 0, dbPath: ':memory:', jwtSecret: 's', authRateLimitPerMin: 3, schedulerTickMs: 3600_000 });
  const url = `http://127.0.0.1:${await limited.start()}`;
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await fetch(url + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"email":"x@y.zz","password":"nopenope1"}' })).status);
  assert.deepEqual(codes, [401, 401, 401, 429, 429]);
  await limited.stop();
  // cookie-authenticated mutation without JSON content-type is rejected, as is a foreign Origin
  const token = await signup('csrf@test.io');
  const form = await fetch(base + '/api/urls', { method: 'POST', headers: { cookie: `token=${token}`, 'content-type': 'text/plain' }, body: '{}' });
  assert.equal(form.status, 415);
  const xo = await fetch(base + '/api/urls', { method: 'POST', headers: { cookie: `token=${token}`, 'content-type': 'application/json', origin: 'http://evil.example' }, body: '{}' });
  assert.equal(xo.status, 403);
});

test('structured JSON logs carry correlation ids from request to worker', async () => {
  const lines = []; log.setSink((l) => lines.push(JSON.parse(l)));
  const token = await signup('logs@test.io');
  const r = await fetch(base + '/api/urls', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'x-correlation-id': 'trace-abc-12345' },
    body: JSON.stringify({ urls: [T('/missing')] }) });
  assert.equal(r.headers.get('x-correlation-id'), 'trace-abc-12345');
  await waitFor(() => lines.some((l) => l.msg === 'check.failed'));
  log.setSink(() => {});
  const failed = lines.find((l) => l.msg === 'check.failed');
  assert.equal(failed.correlationId, 'trace-abc-12345'); // worker log traces back to the HTTP request
  assert.equal(failed.level, 'warn');
  assert.ok(lines.some((l) => l.msg === 'http.request' && l.correlationId === 'trace-abc-12345' && typeof l.durationMs === 'number'));
});

test('behind a proxy, rate limits are per real client IP (TRUST_PROXY)', async () => {
  const a = createApp({ port: 0, dbPath: ':memory:', jwtSecret: 's', authRateLimitPerMin: 2, trustProxy: true, schedulerTickMs: 3600_000 });
  const url = `http://127.0.0.1:${await a.start()}/api/auth/login`;
  const hit = async (ip) => (await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': `spoofed, ${ip}` }, body: '{"email":"x@y.zz","password":"nopenope1"}' })).status;
  assert.deepEqual([await hit('1.1.1.1'), await hit('1.1.1.1'), await hit('1.1.1.1')], [401, 401, 429]);
  assert.equal(await hit('2.2.2.2'), 401); // a different client is unaffected
  await a.stop();
});
