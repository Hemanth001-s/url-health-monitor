'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadConfig } = require('./config');
const { openDb } = require('./db');
const { hashPassword, verifyPassword, signToken, verifyToken, parseCookies } = require('./auth');
const { JobQueue } = require('./queue');
const { Hub } = require('./hub');
const { createService } = require('./service');
const log = require('./logger');

const SESSION_TTL = 12 * 3600;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' };
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }

// Fixed-window in-memory rate limiter. (Multi-instance deployments would back this with Redis INCR+EXPIRE.)
function createLimiter() {
  const hits = new Map();
  const timer = setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, 60_000);
  timer.unref();
  return {
    check(key, max) {
      const now = Date.now();
      let e = hits.get(key);
      if (!e || e.reset < now) { e = { count: 0, reset: now + 60_000 }; hits.set(key, e); }
      e.count++;
      return { ok: e.count <= max, retryAfter: Math.ceil((e.reset - now) / 1000) };
    },
    close: () => clearInterval(timer),
  };
}

function createApp(overrides = {}) {
  const cfg = loadConfig(overrides);
  const secret = cfg.jwtSecret || crypto.randomBytes(32).toString('hex');
  if (!cfg.jwtSecret) log.warn('config.jwt_secret_missing', { note: 'Using a random per-boot secret; sessions reset on restart. Set JWT_SECRET in production.' });

  const db = openDb(cfg.dbPath);
  const hub = new Hub();
  const limiter = createLimiter();
  const queue = new JobQueue({ concurrency: cfg.concurrency, handler: (job) => service.runCheckJob(job) });
  const service = createService({ db, cfg, hub, queue });
  const httpStats = { total: 0, byClass: {} };
  const startedAt = Date.now();

  const userByEmail = db.prepare('SELECT * FROM users WHERE email=?');
  const insertUser = db.prepare('INSERT INTO users (email,password_hash,role,created_at) VALUES (?,?,?,?)');
  // Pre-computed hash used to burn equal CPU time when an email doesn't exist (prevents user enumeration by timing).
  let dummyHash; hashPassword('dummy-password').then((h) => { dummyHash = h; });

  // ---------- helpers ----------
  const json = (res, status, body) => {
    const s = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(s), 'cache-control': 'no-store' });
    res.end(s);
  };

  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = []; let size = 0;
      req.on('data', (c) => { size += c.length; if (size > 1_000_000) { reject(new HttpError(413, 'Request body too large')); req.destroy(); } else chunks.push(c); });
      req.on('end', () => {
        if (!size) return resolve({});
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { reject(new HttpError(400, 'Invalid JSON body')); }
      });
      req.on('error', reject);
    });
  }

  function authenticate(req) {
    const bearer = /^Bearer (.+)$/i.exec(req.headers.authorization || '')?.[1];
    const token = bearer || parseCookies(req.headers.cookie).token;
    const p = verifyToken(token, secret);
    return p ? { id: p.sub, email: p.email, role: p.role, viaCookie: !bearer } : null;
  }

  function setSession(res, user) {
    const token = signToken({ sub: user.id, email: user.email, role: user.role }, secret, SESSION_TTL);
    res.setHeader('set-cookie', `token=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}${cfg.cookieSecure ? '; Secure' : ''}`);
    return token;
  }

  const intervalOf = (v) => {
    if (v == null || v === '' || v === 0) return null;
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1 || n > 1440) throw new HttpError(400, 'intervalMinutes must be an integer between 1 and 1440 (or null)');
    return n;
  };
  const idOf = (s) => { const n = Number(s); if (!Number.isInteger(n) || n < 1) throw new HttpError(400, 'Invalid id'); return n; };

  // ---------- routes ----------
  const routes = [];
  const route = (method, pattern, opts, handler) => routes.push({ method, re: new RegExp(`^${pattern}$`), opts, handler });
  const PUB = { auth: false }, USER = { auth: true }, ADMIN = { auth: true, admin: true };

  route('GET', '/healthz', PUB, ({ res }) => json(res, 200, { status: 'ok', uptimeSec: Math.round((Date.now() - startedAt) / 1000) }));

  route('POST', '/api/auth/signup', { auth: false, authLimit: true }, async ({ res, body }) => {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Enter a valid email address');
    if (password.length < 8 || password.length > 128) throw new HttpError(400, 'Password must be 8-128 characters');
    if (userByEmail.get(email)) throw new HttpError(409, 'An account with this email already exists');
    const role = cfg.adminEmail && email === cfg.adminEmail ? 'admin' : 'user';
    const r = insertUser.run(email, await hashPassword(password), role, Date.now());
    const user = { id: Number(r.lastInsertRowid), email, role };
    log.info('auth.signup', { userId: user.id, role });
    json(res, 201, { user, token: setSession(res, user) });
  });

  route('POST', '/api/auth/login', { auth: false, authLimit: true }, async ({ res, body }) => {
    const email = String(body.email || '').trim().toLowerCase();
    const row = userByEmail.get(email);
    const ok = await verifyPassword(String(body.password || ''), row ? row.password_hash : (dummyHash || 'x$x$x$x$x$x'));
    if (!row || !ok) { log.warn('auth.login_failed', { email }); throw new HttpError(401, 'Invalid email or password'); }
    const user = { id: row.id, email: row.email, role: row.role };
    log.info('auth.login', { userId: user.id });
    json(res, 200, { user, token: setSession(res, user) });
  });

  route('POST', '/api/auth/logout', PUB, ({ res }) => {
    res.setHeader('set-cookie', 'token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    json(res, 200, { ok: true });
  });

  route('GET', '/api/me', USER, ({ res, user }) => json(res, 200, { user: { id: user.id, email: user.email, role: user.role } }));

  route('GET', '/api/summary', USER, ({ res, user, query }) =>
    json(res, 200, service.summary(user.id, Math.min(Math.max(+query.get('hours') || 24, 1), 720))));

  route('GET', '/api/urls', USER, ({ res, user }) => json(res, 200, { urls: service.listUrls(user.id) }));

  route('POST', '/api/urls', USER, ({ res, user, body }) => {
    // Accepts {urls:[...strings or {url}], intervalMinutes?, check?} -- same shape as the JSON upload in the UI.
    const items = Array.isArray(body) ? body : body.urls;
    if (!Array.isArray(items) || !items.length) throw new HttpError(400, 'Provide a non-empty "urls" array');
    if (items.length > 500) throw new HttpError(400, 'Maximum 500 URLs per request');
    const r = service.addUrls(user.id, items, intervalOf(body.intervalMinutes));
    if (body.check !== false && r.added.length) service.enqueueChecks(user.id, r.added.map((u) => u.id), 'initial');
    log.info('urls.added', { userId: user.id, added: r.added.length, rejected: r.rejected.length, duplicates: r.duplicates.length });
    for (const a of r.added) hub.emit(user.id, 'url.added', { urlId: a.id });
    json(res, 201, r);
  });

  route('DELETE', '/api/urls/(?<id>\\d+)', USER, ({ res, user, params }) => {
    const id = idOf(params.id);
    if (!service.deleteUrl(user.id, id)) throw new HttpError(404, 'URL not found');
    log.info('url.removed', { userId: user.id, urlId: id });
    hub.emit(user.id, 'url.removed', { urlId: id });
    json(res, 200, { ok: true });
  });

  route('PATCH', '/api/urls/(?<id>\\d+)', USER, ({ res, user, params, body }) => {
    const id = idOf(params.id);
    if (!('intervalMinutes' in body)) throw new HttpError(400, 'intervalMinutes is required');
    if (!service.setSchedule(user.id, id, intervalOf(body.intervalMinutes))) throw new HttpError(404, 'URL not found');
    json(res, 200, { ok: true });
  });

  route('POST', '/api/checks/run', USER, ({ res, user, body }) => {
    const ids = Array.isArray(body.ids) ? body.ids.map(idOf) : [];
    const r = service.enqueueChecks(user.id, ids, 'manual');
    log.info('checks.requested', { userId: user.id, ...r });
    json(res, 202, r); // 202 Accepted: work is queued, results arrive via SSE / polling
  });

  route('GET', '/api/urls/(?<id>\\d+)/results', USER, ({ res, user, params, query }) => {
    const rows = service.results(user.id, idOf(params.id), { limit: query.get('limit'), before: query.get('before') });
    if (!rows) throw new HttpError(404, 'URL not found');
    json(res, 200, { results: rows, nextBefore: rows.length ? rows[rows.length - 1].id : null });
  });

  route('GET', '/api/urls/(?<id>\\d+)/stats', USER, ({ res, user, params, query }) => {
    const s = service.urlStats(user.id, idOf(params.id), Math.min(Math.max(+query.get('hours') || 24, 1), 720));
    if (!s) throw new HttpError(404, 'URL not found');
    json(res, 200, s);
  });

  route('GET', '/api/events', USER, ({ req, res, user }) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-transform', connection: 'keep-alive', 'x-accel-buffering': 'no' });
    res.write('retry: 3000\n\n');
    hub.add(user.id, res);
    log.debug('sse.connected', { userId: user.id });
    req.on('close', () => log.debug('sse.disconnected', { userId: user.id }));
    return 'stream';
  });

  // ---- admin (role-based access) ----
  route('GET', '/api/admin/users', ADMIN, ({ res }) => json(res, 200, { users: db.prepare(
    `SELECT u.id,u.email,u.role,u.created_at,(SELECT COUNT(*) FROM urls WHERE user_id=u.id) url_count FROM users u ORDER BY u.id`).all() }));

  route('GET', '/api/admin/overview', ADMIN, ({ res }) => {
    const m = service.metrics;
    json(res, 200, {
      system: service.summary(null, 24),
      users: db.prepare('SELECT COUNT(*) c FROM users').get().c,
      queue: { depth: queue.depth(), running: queue.running, concurrency: queue.concurrency, ...queue.stats },
      process: { uptimeSec: Math.round((Date.now() - startedAt) / 1000), sseClients: hub.count(), memoryMb: Math.round(process.memoryUsage().rss / 1048576) },
      checksSinceBoot: { total: m.checksTotal, failed: m.checksFailed, avgResponseMs: m.responseMsCount ? Math.round(m.responseMsSum / m.responseMsCount) : null,
        failureRatePct: m.checksTotal ? +(100 * m.checksFailed / m.checksTotal).toFixed(2) : null },
      http: httpStats,
    });
  });

  // ---------- static files ----------
  function serveStatic(req, res, pathname) {
    const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
    const file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) return json(res, 403, { error: 'Forbidden' }); // path traversal guard
    fs.readFile(file, (err, data) => {
      if (err) return json(res, 404, { error: 'Not found' });
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(data);
    });
  }

  // ---------- request pipeline ----------
  async function handle(req, res) {
    const started = performance.now();
    const url = new URL(req.url, 'http://localhost');
    const correlationId = /^[\w-]{8,64}$/.test(req.headers['x-correlation-id'] || '') ? req.headers['x-correlation-id'] : log.newId();
    res.setHeader('x-correlation-id', correlationId);
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('content-security-policy', "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'");
    const ctx = { userId: null };

    res.on('close', () => log.withContext({ correlationId }, () => { // 'close' can fire outside the original async context (e.g. long-lived SSE)
      const status = res.statusCode, ms = Math.round(performance.now() - started);
      httpStats.total++; httpStats.byClass[`${Math.floor(status / 100)}xx`] = (httpStats.byClass[`${Math.floor(status / 100)}xx`] || 0) + 1;
      if (url.pathname !== '/healthz') log[status >= 500 ? 'error' : 'info']('http.request', { method: req.method, path: url.pathname, status, durationMs: ms, userId: ctx.userId });
    }));

    try {
      const r = routes.find((x) => x.method === req.method && x.re.test(url.pathname));
      if (!r) {
        if (req.method === 'GET' && !url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
        throw new HttpError(404, 'Not found');
      }
      // Behind a trusted proxy the socket IP is the proxy's. The LAST X-Forwarded-For entry is the one the proxy itself appended
      // (earlier entries are client-controlled and spoofable).
      const fwd = cfg.trustProxy ? String(req.headers['x-forwarded-for'] || '').split(',').pop().trim() : '';
      const ip = fwd || req.socket.remoteAddress || 'unknown';
      let user = null;
      if (r.opts.auth) {
        user = authenticate(req);
        if (!user) throw new HttpError(401, 'Authentication required');
        ctx.userId = user.id;
        if (r.opts.admin && user.role !== 'admin') { log.warn('auth.forbidden', { userId: user.id, path: url.pathname }); throw new HttpError(403, 'Admin access required'); }
      }
      // Rate limiting: strict per-IP for login/signup (brute force), generous per-user/IP elsewhere.
      const rl = r.opts.authLimit ? limiter.check(`auth:${ip}`, cfg.authRateLimitPerMin) : limiter.check(`api:${user ? 'u' + user.id : ip}`, cfg.rateLimitPerMin);
      if (!rl.ok) { res.setHeader('retry-after', rl.retryAfter); log.warn('rate_limited', { ip, path: url.pathname }); throw new HttpError(429, 'Too many requests'); }

      let body = {};
      if (req.method !== 'GET') {
        // CSRF defence-in-depth on top of SameSite=Strict: same-origin + JSON content-type
        // (a cross-site <form> cannot send application/json without a CORS preflight).
        const origin = req.headers.origin;
        if (origin && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Cross-origin request blocked');
        if ((!user || user.viaCookie) && !/application\/json/.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Content-Type must be application/json');
        body = await readBody(req);
      }
      const out = await r.handler({ req, res, body, user, query: url.searchParams, params: url.pathname.match(r.re).groups || {} });
      if (out !== 'stream' && !res.writableEnded) res.end();
    } catch (err) {
      if (err instanceof HttpError) {
        if (!res.headersSent) json(res, err.status, { error: err.message, correlationId });
      } else {
        log.error('request.unhandled_error', log.errFields(err));
        if (!res.headersSent) json(res, 500, { error: 'Internal server error', correlationId });
      }
    }
  }

  const server = http.createServer((req, res) => {
    const correlationId = /^[\w-]{8,64}$/.test(req.headers['x-correlation-id'] || '') ? req.headers['x-correlation-id'] : log.newId();
    // Re-use same id inside handle(): set header again there is harmless; ALS gives every log line the id.
    req.headers['x-correlation-id'] = correlationId;
    log.withContext({ correlationId }, () => handle(req, res));
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;

  // ---------- lifecycle ----------
  let schedulerTimer, pruneTimer;
  const app = {
    cfg, db, queue, service, server,
    async start() {
      await new Promise((r) => server.listen(cfg.port, r));
      schedulerTimer = setInterval(() => { try { service.enqueueDue(); } catch (e) { log.error('scheduler.error', log.errFields(e)); } }, cfg.schedulerTickMs);
      pruneTimer = setInterval(() => { try { service.pruneOldResults(); } catch (e) { log.error('retention.error', log.errFields(e)); } }, 6 * 3600_000);
      schedulerTimer.unref(); pruneTimer.unref();
      service.enqueueDue(); // catch up on anything that came due while we were down
      log.info('server.started', { port: server.address().port, concurrency: cfg.concurrency, timeoutMs: cfg.timeoutMs, retries: cfg.retries });
      return server.address().port;
    },
    async stop() {
      clearInterval(schedulerTimer); clearInterval(pruneTimer); limiter.close();
      hub.close();
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
      await Promise.race([queue.onIdle(), new Promise((r) => setTimeout(r, 10_000))]); // let in-flight checks finish
      db.close();
      log.info('server.stopped');
    },
  };
  return app;
}

module.exports = { createApp };
