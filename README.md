# URL Health & Observability Platform  **Live demo:** https://url-health-monitor-3sdc.onrender.com
**Source:** https://github.com/Hemanth001-s/url-health-monitor

> **Note on the hosted demo:** it runs on a free hosting tier, which has two limits:
> 1. **Ephemeral storage** – the SQLite database is reset whenever the service restarts or redeploys, so accounts and history
>    do not persist. Sign up again and add the sample URLs (`sample-urls.json`) to try it.
> 2. **Idle sleep** – the first request after a quiet period can take up to a minute while the service wakes up, and scheduled
>    checks only run while it is awake.
>
> For production I would attach a persistent disk (the app already supports `DB_PATH` on a mounted volume) or move to managed
> Postgres + Redis, as described in *Design decisions & trade-offs*.

Full-stack monitor: sign up, add URLs (typed or JSON upload), run checks concurrently or on a schedule,
watch live status, response-time charts, uptime/failure metrics, with structured logging throughout.

**Zero runtime dependencies.** Node 22+ only (`node:sqlite`, `node:crypto`, `fetch`, `node:http`).

## Quick start
```bash
node -v                     # needs >= 22.5
npm start                   # http://localhost:3000
npm test                    # 14 integration tests
# or
JWT_SECRET=$(openssl rand -hex 32) docker compose up --build
```
Sign up in the UI, paste the URLs from `sample-urls.json` (or use *Upload JSON…*).
Set `ADMIN_EMAIL=you@x.com` before signing up with that address to get the admin role.

| Env var | Default | Meaning |
|---|---|---|
| `PORT` | 3000 | HTTP port |
| `DB_PATH` | ./data/monitor.db | SQLite file |
| `JWT_SECRET` | random per boot | **Set in production** |
| `WORKER_CONCURRENCY` | 10 | parallel checks |
| `CHECK_TIMEOUT_MS` / `CHECK_RETRIES` | 10000 / 1 | per-attempt deadline / extra attempts |
| `RETENTION_DAYS` | 30 | raw history kept (hourly rollups kept forever) |
| `ALLOW_PRIVATE_TARGETS` | false | allow monitoring localhost/private IPs (disables SSRF guard) |
| `TRUST_PROXY` | false | set `true` behind a proxy/PaaS so rate limits use the real client IP |
| `COOKIE_SECURE` | false | set `true` behind HTTPS |
| `LOG_LEVEL` | info | debug / info / warn / error |

## Architecture
```
Browser (vanilla JS SPA, SVG charts)
   │  REST + cookie session            ▲ SSE (live events)
   ▼                                   │
HTTP server ── auth, rate limit, validation, correlation id
   │                       │
   ▼                       ▼
Service layer ──enqueue──▶ JobQueue (N concurrent workers) ──▶ Checker (DNS→SSRF guard→fetch→classify→retry)
   ▲                                  │ result
Scheduler (tick 10s: due URLs) ───────┘  ▼
                              SQLite: users | urls | check_results | url_hourly_stats
```
* **Checker** – one deadline (`AbortSignal.timeout`) over DNS+TLS+headers; classifies `HTTP_ERROR`, `HTTP_5XX`, `TIMEOUT`, `DNS_FAILURE`, `TLS_ERROR`, `CONNECTION_ERROR`, `BLOCKED_TARGET`, `TOO_MANY_REDIRECTS`. Retries transient errors with exponential backoff + jitter. 4xx/DNS-not-found are not retried.
* **Queue** – bounded worker pool, de-duplicates by URL so a slow check is never double-queued. Same contract as BullMQ (`enqueue` / handler).
* **Scheduler** – `next_check_at` lives in the DB, so schedules survive restarts. `next_check_at` is advanced *before* enqueueing to avoid double scheduling.
* **Reports** – every check upserts an hourly rollup row in the same transaction as the raw row. Dashboards/uptime/SLA read only rollups.
* **Realtime** – Server-Sent Events per user; the UI falls back to 15s polling if the stream drops.

## API (all JSON, cookie or `Authorization: Bearer`)
`POST /api/auth/signup|login|logout` · `GET /api/me` · `GET/POST /api/urls` · `PATCH/DELETE /api/urls/:id` ·
`POST /api/checks/run {ids?}` · `GET /api/urls/:id/results?limit&before` · `GET /api/urls/:id/stats?hours` ·
`GET /api/summary?hours` · `GET /api/events` (SSE) · `GET /api/admin/users|overview` (admin) · `GET /healthz`

## Design decisions & trade-offs
| Decision | Why | Trade-off / production path |
|---|---|---|
| SQLite (WAL) | zero setup, transactional, upserts, partial indexes | single writer → move to Postgres (schema is portable; use `FOR UPDATE SKIP LOCKED` in the scheduler, partition `check_results` by month) |
| In-process queue | simple, testable, no infra | jobs lost on restart (scheduled ones re-derive from DB) → Redis + BullMQ, separate worker processes |
| Hourly rollup table | O(hours) dashboard queries instead of O(checks) | p95 still needs raw rows (capped, retention-bound) |
| SSE not WebSocket | one-way push, plain HTTP, auto-reconnect | multi-instance needs Redis pub/sub fan-out |
| HttpOnly SameSite=Strict cookie + Origin/Content-Type checks | JS can't read the token (XSS-safe), CSRF-resistant | non-browser clients use Bearer |
| scrypt + HS256 JWT via `node:crypto` | no dependency, constant-time compare, fixed algorithm | no token revocation before expiry (12h) → add a session table/denylist if needed |
| SSRF guard + manual redirect validation | users make *our server* fetch URLs | DNS-rebinding window between lookup and connect; mitigate with an egress proxy |
| Response time = time to response headers | measures server latency without download size noise | not full page-load time |
| Keyset pagination | stays fast on deep history | no random page jump |

## Observability
JSON log line per event (`time, level, msg, correlationId, …`). A correlation id is accepted from `x-correlation-id` or generated,
returned in the response, stored on every check row, and propagated into queue workers via `AsyncLocalStorage`.
Events: `http.request`, `check.completed` (info), `check.failed` / `url.status_changed` / `rate_limited` / `auth.login_failed` (warn), `request.unhandled_error` / `job.failed` (error), scheduler/retention/lifecycle events.
Metrics: `GET /api/admin/overview` – queue depth, avg response time, failure rate, HTTP status counts, SSE clients, memory.

## Testing
`npm test` runs 14 integration tests against a real server and a local target server: auth, classification of every failure type,
concurrency (20×300ms checks finish in ~0.7s, not 6s), de-duplication, retry/backoff, SSRF, tenant isolation, reports + pagination,
scheduling, RBAC, SSE, rate limiting/CSRF, and log correlation.

## How AI was used
*(Edit this to reflect your own process before submitting.)* I used Claude to turn the brief into a requirement checklist, propose the
architecture and alternatives, write the first implementation and tests, and review security (SSRF, CSRF, timing attacks).
I then ran the tests, drove the UI in a headless browser, found and fixed issues (e.g. a UI race where fast checks finished before the
"queued" state was recorded), and I can explain and defend each design decision.

## Deploying publicly
Needs: an always-on host (the scheduler runs inside the process), **a persistent disk/volume** for `DB_PATH`, and HTTPS.
Set: `JWT_SECRET` (long random), `COOKIE_SECURE=true`, `TRUST_PROXY=true`, `DB_PATH=/data/monitor.db` (on the volume), optionally `ADMIN_EMAIL`.
The platform provides `PORT`. Use the included `Dockerfile`. Health check path: `/healthz`. Run exactly **one** instance (SQLite + in-process queue).
