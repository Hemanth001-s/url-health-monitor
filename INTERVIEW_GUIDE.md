# Interview Guide — URL Health & Observability Platform

## 0. The 30-second pitch
"I built a multi-user URL monitoring platform. Users sign up, add URLs by typing or uploading JSON, and the system checks them
concurrently through a bounded worker pool, manually or on a schedule. Each check records UP/DOWN, response time and a classified
error. Results are stored as raw history plus an hourly rollup so dashboards stay fast at scale. The UI updates live over SSE.
Everything is logged as structured JSON with correlation IDs that follow a request into the background worker. I also added
SSRF protection, rate limiting, retries with backoff, RBAC and tests."

## 1. How to approach it (say this out loud in the interview)
1. **Clarify** – who are users? how many URLs? how often? (assume ≤1k URLs/user, 1–60 min intervals).
2. **Split into 6 subsystems** exactly as the brief does: auth, checker, concurrency/scheduling, DB, UI, observability.
3. **Pick the simplest thing that satisfies each requirement, and name the upgrade path** (SQLite→Postgres, in-process queue→Redis/BullMQ).
4. **Call out failure modes early**: timeouts, DNS failure, invalid URL, slow targets, restarts, duplicate scheduling, hostile input.
5. **Test the risky parts** (concurrency, retries, tenant isolation, SSRF).

## 2. Requirement → design (the core of the answer)

### 2.1 Authentication & users
* Signup/login with email + password. Passwords hashed with **scrypt** (memory-hard, per-user random salt), compared with `timingSafeEqual`.
* Session = **JWT (HS256)** in an **HttpOnly, SameSite=Strict cookie** → JavaScript can't steal it (XSS), cross-site requests don't send it (CSRF).
  Extra CSRF layer: reject non-JSON content types and foreign `Origin`. API clients can use `Authorization: Bearer`.
* Algorithm is fixed server-side (never read from the token header) → no `alg:none` attack.
* Login failure is generic ("Invalid email or password") and we burn a dummy hash for unknown emails → no user enumeration by message or timing.
* **Authorization:** every query includes `user_id`; asking for someone else's URL returns 404 (not 403, so existence isn't leaked). This is the multi-tenant isolation and is tested.
* **RBAC bonus:** `role` column (`user`/`admin`); admin-only routes check it. Admin = signup email equal to `ADMIN_EMAIL`.
* Rate limit: 10 auth attempts/min/IP (brute force), 300 req/min/user otherwise.

### 2.2 Monitoring engine (`src/checker.js`)
* **Input:** textarea (one per line), pasted JSON array, or uploaded `.json` — the UI parses to the same `{urls:[…]}` payload. Server validates each URL
  (http/https only, no embedded credentials, ≤2048 chars), dedupes, and returns `{added, rejected, duplicates}` so one bad URL never fails the batch
  (the sample input has an invalid-path Wikipedia URL → recorded as DOWN, HTTP 404).
* **UP** = status 200–299, else **DOWN**. Stored: status, HTTP code, response time (ms), timestamp, error type/message, attempts, trigger.
* **Response time** = start → response headers received (includes DNS+TCP+TLS). We cancel the body: we measure server latency, not download size.
* **Graceful failure handling:** a single `AbortSignal.timeout` bounds the *whole* attempt (DNS lookup has no abort support so it's raced against the signal).
  Errors are mapped to stable categories: `DNS_FAILURE`, `TIMEOUT`, `TLS_ERROR`, `CONNECTION_ERROR`, `HTTP_5XX`, `HTTP_ERROR`, `BLOCKED_TARGET`, `TOO_MANY_REDIRECTS`.
  `checkUrl` never throws — it always returns a result, so one bad URL can't crash a worker.
* **Retries (bonus):** only *transient* failures (timeout, connection refused, 5xx, DNS temporary failure) retry, with exponential backoff `base·2^n` + 25% jitter
  (jitter prevents synchronized retry storms). 4xx and "host not found" are not retried — retrying can't fix them.
* **SSRF protection (security highlight):** our server fetches user-supplied URLs, so a user could point us at `127.0.0.1`, `10.x`, or the cloud metadata
  address `169.254.169.254`. We resolve DNS, reject private/loopback/link-local IPs, and follow redirects **manually** re-checking each hop.
  Known residual risk: DNS-rebinding between lookup and connect → in production use an egress proxy / pinned IP connection.

### 2.3 Concurrency & scheduling
* **Concurrent:** `JobQueue` is a worker pool with `WORKER_CONCURRENCY` (default 10). Checks are I/O-bound so one Node process handles hundreds concurrently.
  Test: 20 checks × 300 ms finish in ~0.7 s (sequential would be 6 s).
* **Why a bounded pool and not `Promise.all`?** Unbounded fan-out with 10k URLs would exhaust sockets/FDs and DNS, and hammer our own DB. A pool gives backpressure.
* **De-duplication:** key `url:<id>` — a URL queued or running can't be queued again (double-click, or scheduler tick overlapping a slow check).
* **Manual:** `POST /api/checks/run` returns **202 Accepted** immediately; results arrive over SSE.
* **Scheduled:** each URL has `interval_minutes` and `next_check_at`. A 10-second tick selects `next_check_at <= now` (a **partial index** makes this cheap), **advances
  `next_check_at` first**, then enqueues. Advancing first = a slow check can't be scheduled twice. State is in the DB → survives restarts, and on boot we catch up on overdue URLs.
* **Queue-based bonus:** the queue is the seam. `enqueue(job,key)` + `handler(job)` is the same contract as BullMQ; moving to Redis means producers stay the same and
  workers become separate processes.

### 2.4 Database (`src/db.js`)
```
users(id, email UNIQUE, password_hash, role, created_at)
urls(id, user_id→users, url, interval_minutes, next_check_at, last_status/…, UNIQUE(user_id,url))
check_results(id, url_id→urls, status, status_code, response_time_ms, error_type, attempts, trigger, correlation_id, checked_at)   -- append-only, big
url_hourly_stats(url_id, bucket_hour, total, up, sum_ms_up, max_ms)  PK(url_id,bucket)                                           -- aggregated report
```
* **Denormalised "current state"** on `urls` (`last_status`, `last_response_ms`…) → the dashboard list is one cheap query, no "latest row per group" join.
* **Indexes match queries:** `(url_id, checked_at DESC)` for history/charts; `(next_check_at) WHERE interval_minutes IS NOT NULL` for the scheduler; `(checked_at)` for retention.
* **Aggregation:** every check does, in **one transaction**, insert raw row + upsert hourly row + update `urls`. Uptime% = ΣUP/Σtotal over hourly rows. Avg response uses UP checks only
  (a timeout's 10 s would distort "how fast is the site"). p95 can't come from sums, so it uses raw rows (bounded by window and retention).
* **Scale math:** 1,000 URLs × every 5 min = 288k rows/day ≈ 8.6M rows/30 days, but a 30-day uptime query reads only 1,000 × 720 = 720k tiny rollup rows — or per URL just 720.
* **Retention:** raw rows pruned after `RETENTION_DAYS`; rollups kept → long-term SLA reports remain possible.
* **Keyset pagination** (`WHERE id < ?`) instead of `OFFSET`, so page 1000 is as fast as page 1.
* **Postgres path:** same schema; `BIGSERIAL`, `TIMESTAMPTZ`; **range-partition `check_results` by month** (drop old partitions instead of DELETE); `FOR UPDATE SKIP LOCKED` in the scheduler so several instances don't pick the same URL; BRIN index on `checked_at`.

### 2.5 UI
* Vanilla JS single page (no build step). Add/remove URLs, JSON upload, per-URL schedule dropdown, "Check" / "Check all".
* Tiles: **Total URLs, Up/Down now, Uptime %, Failures + failure rate, Avg response**. Detail panel: response-time line chart (last 100 checks, failures as red dots), hourly uptime bars, p95/max, recent checks table. Charts are hand-written SVG.
* **Real-time:** SSE stream per user → row updates instantly, toast on status change ("github.com is now DOWN"). If the stream drops, it shows "reconnecting" and polls every 15 s.
* **XSS-safe by construction:** all user text inserted with `textContent`, never `innerHTML` (URLs are attacker-controlled). CSP header `default-src 'self'` as a second layer.

### 2.6 Logging & observability
* **Structured JSON**, levels info/warn/error (debug optional), one event per line → ready for Loki/ELK/Datadog.
* **Correlation ID:** taken from `x-correlation-id` or generated; returned as a response header; carried by `AsyncLocalStorage` so *every* log line inside the request has it
  **and** the queue captures it when enqueuing, so the worker's `check.failed` log is traceable back to the click that caused it. It's also stored in `check_results.correlation_id`.
* **What's logged:** every request (method, path, status, duration, userId), check results (warn on failure with error type), status changes, auth failures, rate limiting, scheduler, retention, lifecycle.
* **Metrics:** queue depth/running/completed/failed/deduped, avg response time, failure rate, HTTP status classes, SSE clients, RSS memory (`/api/admin/overview`).
* Next step: expose Prometheus format + OpenTelemetry traces.

## 3. Walk through one request end-to-end (great for "explain your flow")
1. User clicks **Check all** → `POST /api/checks/run` with cookie; correlation id `abc` assigned.
2. Auth middleware verifies JWT → rate limiter → CSRF checks → handler.
3. Service selects the user's URL ids (scoped by `user_id`), `queue.enqueue` each with key `url:id` → returns **202** with `{queued, alreadyQueued}`.
4. Workers (≤10 at a time) pick jobs; context `abc` restored. `checkUrl` → DNS → SSRF check → `fetch` with deadline → classify → retry if transient.
5. One DB transaction writes raw result, hourly rollup, current state. Log `check.completed/failed` (id `abc`).
6. Hub pushes `check.completed` (+ `status.changed` if flipped) over SSE; UI updates the row; summary tiles refresh (coalesced).

## 4. Likely interview questions (with answers)
**Why Node?** I/O-bound workload — thousands of concurrent sockets on one event loop; the brief prefers it.
**Why SQLite instead of Postgres?** Zero-setup so reviewers run it with one command, and it still gives transactions, upserts, partial indexes. Honest limit: single writer. The schema and queries port to Postgres directly; I'd move when running multiple instances.
**Why no frameworks / dependencies?** Package installation was restricted in my build environment, so I used Node 22 built-ins; it turned out to be a feature (nothing to audit, tiny image). With Express/Postgres/BullMQ the structure is identical — routes → service → queue/checker → DB.
**What if the server restarts mid-check?** In-flight and queued manual jobs are lost (user clicks again); scheduled work isn't, because `next_check_at` is in the DB and boot catches up. With Redis/BullMQ they'd be durable with at-least-once delivery.
**What if checks take longer than the interval?** Dedup key prevents overlap; `next_check_at` already moved forward, so the next run starts one interval after the *scheduled* time, not piling up.
**How do you scale to 100k URLs?** Postgres + partitioned results; Redis queue; N stateless worker processes (horizontal) possibly per region; scheduler with `SKIP LOCKED`; batch inserts; Redis pub/sub for SSE across API nodes; per-host concurrency limits.
**How do you avoid hammering a target?** Per-host concurrency cap and minimum interval (1 min) — planned; today the interval floor and dedup limit it.
**Why 202 for manual checks?** Work is asynchronous; the client shouldn't hold a connection open for 10 s×retries. Results come via SSE/polling.
**Why response time of UP-only in averages?** Timeouts would inflate the average; failures are reported separately via failure rate.
**HEAD vs GET?** GET: many servers mishandle HEAD, and GET reflects real behaviour; we cancel the body so cost is small.
**How is the 'UP' definition handled for redirects?** Redirects are followed (≤5) and the *final* status decides; each hop is SSRF-checked.
**JWT vs sessions?** Stateless JWT keeps it simple and scales horizontally; downside is no instant revocation — fix with a short TTL + refresh or a server-side denylist.
**Why cookie not localStorage?** localStorage tokens are readable by any XSS; HttpOnly cookies aren't.
**How did you test concurrency?** 20 targets that each sleep 300 ms; assert total < 2 s (sequential ≥ 6 s).
**Multi-tenant?** Row-level scoping by `user_id` in every query + tests proving user B gets 404 for user A's resources. Organisations/teams would add an `org_id` column.
**Alerts via email?** On `status.changed` (already emitted) enqueue a notification job; add debounce (N consecutive failures) to avoid flapping alerts.
**Uptime SLA?** `uptime = up_checks / total_checks` over a window from rollups (`/stats?hours=720` for 30 days). Caveat: it's sampled, accuracy depends on interval.

## 5. Known limitations (volunteer these — it shows maturity)
* Single-process queue; no Redis. No email alerts. No per-host rate limiting. Rate limiter is in-memory (per instance).
* DNS-rebinding window in SSRF defence. JWT can't be revoked early. No password reset / email verification.
* External-site checks were not exercised in my build sandbox (no outbound DNS) — verified against local targets that simulate 200/404/5xx/timeouts/redirects/flaky/DNS failure. Run it on your machine to see google/github go UP.

## 6. Demo script (3 minutes)
1. `npm start`, open the app, sign up. 2. Upload `sample-urls.json` → google/github UP, Wikipedia DOWN (404), with different response times.
3. Add `not-a-url` → show rejected list. Add a `http://localhost` URL → show it blocked (SSRF) with `BLOCKED_TARGET`.
4. Set schedule to 1 min → show it re-checking and the row updating live. 5. Open detail → chart, p95, hourly bars.
6. Show terminal JSON logs; copy a `correlationId` from the HTTP request and show the same id on `check.failed`.
7. `npm test` → 14 passing.

## 7. If asked "what would you do with another week?"
Postgres + Redis/BullMQ with separate worker process (docker-compose), email/webhook alerts with flap-damping, per-host throttling,
Prometheus `/metrics` + OpenTelemetry, React/Next.js frontend, password reset, org/team model, status pages, multi-region probes.
