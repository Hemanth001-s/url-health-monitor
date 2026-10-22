'use strict';
// Business logic + data access. Every query that touches user data is scoped by user_id,
// which is what gives us per-user (multi-tenant) isolation.
const { tx } = require('./db');
const { checkUrl, validateUrl } = require('./checker');
const log = require('./logger');

const HOUR = 3600_000;
const DAY = 24 * HOUR;
const bucketOf = (t) => Math.floor(t / HOUR) * HOUR;

function createService({ db, cfg, hub, queue }) {
  const metrics = { checksTotal: 0, checksFailed: 0, responseMsSum: 0, responseMsCount: 0 };

  const q = {
    insertResult: db.prepare(`INSERT INTO check_results (url_id,status,status_code,response_time_ms,error_type,error_message,attempts,trigger,correlation_id,checked_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`),
    upsertHour: db.prepare(`INSERT INTO url_hourly_stats (url_id,bucket,total,up,sum_ms_up,max_ms) VALUES (?,?,1,?,?,?)
      ON CONFLICT(url_id,bucket) DO UPDATE SET total=total+1, up=up+excluded.up, sum_ms_up=sum_ms_up+excluded.sum_ms_up, max_ms=MAX(max_ms,excluded.max_ms)`),
    updateUrl: db.prepare(`UPDATE urls SET last_status=?,last_status_code=?,last_response_ms=?,last_error_type=?,last_checked_at=? WHERE id=?`),
    getUrl: db.prepare('SELECT * FROM urls WHERE id=?'),
    getOwnedUrl: db.prepare('SELECT * FROM urls WHERE id=? AND user_id=?'),
    countUrls: db.prepare('SELECT COUNT(*) c FROM urls WHERE user_id=?'),
    insertUrl: db.prepare('INSERT OR IGNORE INTO urls (user_id,url,interval_minutes,next_check_at,created_at) VALUES (?,?,?,?,?)'),
    deleteUrl: db.prepare('DELETE FROM urls WHERE id=? AND user_id=?'),
    due: db.prepare('SELECT id,user_id,interval_minutes FROM urls WHERE interval_minutes IS NOT NULL AND next_check_at <= ? ORDER BY next_check_at LIMIT 500'),
    reschedule: db.prepare('UPDATE urls SET next_check_at=? WHERE id=?'),
    setInterval: db.prepare('UPDATE urls SET interval_minutes=?, next_check_at=? WHERE id=? AND user_id=?'),
    prune: db.prepare('DELETE FROM check_results WHERE checked_at < ?'),
  };

  // ---------- running checks (this is the worker's job handler) ----------
  async function runCheckJob({ urlId, trigger }) {
    const row = q.getUrl.get(urlId);
    if (!row) return; // deleted while queued
    const result = await checkUrl(row.url, cfg);
    const ok = result.status === 'UP';

    // One transaction: raw row + hourly rollup + "current state" on the url row stay consistent.
    tx(db, () => {
      q.insertResult.run(urlId, result.status, result.statusCode, result.responseTimeMs, result.errorType, result.errorMessage,
        result.attempts, trigger, log.currentCorrelationId() ?? null, result.checkedAt);
      q.upsertHour.run(urlId, bucketOf(result.checkedAt), ok ? 1 : 0, ok ? result.responseTimeMs : 0, ok ? result.responseTimeMs : 0);
      q.updateUrl.run(result.status, result.statusCode, result.responseTimeMs, result.errorType, result.checkedAt, urlId);
    });

    metrics.checksTotal++;
    if (!ok) metrics.checksFailed++;
    else { metrics.responseMsSum += result.responseTimeMs; metrics.responseMsCount++; }

    const fields = { urlId, url: row.url, status: result.status, statusCode: result.statusCode, responseTimeMs: result.responseTimeMs, attempts: result.attempts, trigger };
    if (ok) log.info('check.completed', fields);
    else log.warn('check.failed', { ...fields, errorType: result.errorType, errorMessage: result.errorMessage }); // timeouts, DNS, 4xx/5xx...

    const payload = { urlId, status: result.status, statusCode: result.statusCode, responseTimeMs: result.responseTimeMs,
      errorType: result.errorType, errorMessage: result.errorMessage, checkedAt: result.checkedAt };
    hub.emit(row.user_id, 'check.completed', payload);
    if (row.last_status && row.last_status !== result.status) {
      log.warn('url.status_changed', { urlId, url: row.url, from: row.last_status, to: result.status });
      hub.emit(row.user_id, 'status.changed', { urlId, url: row.url, from: row.last_status, to: result.status });
    }
  }

  // Enqueue checks for URLs owned by userId (all of them if ids is empty). Returns counts.
  function enqueueChecks(userId, ids, trigger = 'manual') {
    const rows = ids?.length
      ? ids.map((id) => q.getOwnedUrl.get(Number(id), userId)).filter(Boolean)
      : db.prepare('SELECT id FROM urls WHERE user_id=?').all(userId);
    let queued = 0;
    for (const r of rows) if (queue.enqueue({ urlId: r.id, trigger }, `url:${r.id}`)) queued++;
    return { requested: rows.length, queued, alreadyQueued: rows.length - queued };
  }

  // ---------- URL management ----------
  function addUrls(userId, items, intervalMinutes) {
    const added = [], rejected = [], duplicates = [];
    const seen = new Set();
    let room = cfg.maxUrlsPerUser - q.countUrls.get(userId).c;
    const now = Date.now();
    const next = intervalMinutes ? now + intervalMinutes * 60_000 : null;
    tx(db, () => {
      for (const input of items) {
        const raw = typeof input === 'string' ? input : input?.url;
        const v = validateUrl(raw);
        if (!v.ok) { rejected.push({ input: String(raw ?? '').slice(0, 200), reason: v.reason }); continue; }
        if (seen.has(v.url)) { duplicates.push(v.url); continue; }
        seen.add(v.url);
        if (room <= 0) { rejected.push({ input: v.url, reason: `Limit of ${cfg.maxUrlsPerUser} URLs reached` }); continue; }
        const r = q.insertUrl.run(userId, v.url, intervalMinutes || null, next, now);
        if (r.changes === 0) { duplicates.push(v.url); continue; }
        room--;
        added.push(q.getUrl.get(Number(r.lastInsertRowid)));
      }
    });
    return { added, rejected, duplicates };
  }

  function setSchedule(userId, id, intervalMinutes) {
    const next = intervalMinutes ? Date.now() + intervalMinutes * 60_000 : null;
    return q.setInterval.run(intervalMinutes || null, next, id, userId).changes > 0;
  }

  function listUrls(userId, hours = 24) {
    return db.prepare(`SELECT u.id,u.url,u.interval_minutes,u.next_check_at,u.last_status,u.last_status_code,u.last_response_ms,
        u.last_error_type,u.last_checked_at,u.created_at,
        (SELECT ROUND(100.0*SUM(up)/SUM(total),2) FROM url_hourly_stats s WHERE s.url_id=u.id AND s.bucket>=?) AS uptime_pct
      FROM urls u WHERE u.user_id=? ORDER BY u.id DESC`).all(bucketOf(Date.now() - hours * HOUR), userId);
  }

  // ---------- scheduler ----------
  function enqueueDue() {
    const now = Date.now();
    const due = q.due.all(now);
    for (const d of due) {
      // Move next_check_at forward FIRST so a slow check can't be scheduled twice.
      q.reschedule.run(now + d.interval_minutes * 60_000, d.id);
      queue.enqueue({ urlId: d.id, trigger: 'scheduled' }, `url:${d.id}`);
    }
    if (due.length) log.info('scheduler.enqueued', { count: due.length });
    return due.length;
  }

  function pruneOldResults() {
    const r = q.prune.run(Date.now() - cfg.retentionDays * DAY);
    log.info('retention.pruned', { deleted: Number(r.changes), retentionDays: cfg.retentionDays });
  }

  // ---------- reports ----------
  // Summary reads ONLY the small hourly rollup table. userId=null => whole system (admin).
  function summary(userId, hours = 24) {
    const since = bucketOf(Date.now() - hours * HOUR);
    const scope = userId == null ? '' : 'AND u.user_id = ?';
    const args = userId == null ? [] : [userId];
    const cur = db.prepare(`SELECT COUNT(*) total, SUM(last_status='UP') up, SUM(last_status='DOWN') down FROM urls u WHERE 1=1 ${scope}`).get(...args);
    const agg = db.prepare(`SELECT COALESCE(SUM(s.total),0) checks, COALESCE(SUM(s.up),0) up, COALESCE(SUM(s.sum_ms_up),0) ms
      FROM url_hourly_stats s JOIN urls u ON u.id=s.url_id WHERE s.bucket>=? ${scope}`).get(since, ...args);
    const failures = agg.checks - agg.up;
    return {
      windowHours: hours,
      totalUrls: cur.total, currentlyUp: cur.up || 0, currentlyDown: cur.down || 0, neverChecked: cur.total - (cur.up || 0) - (cur.down || 0),
      checks: agg.checks, failures,
      uptimePct: agg.checks ? +(100 * agg.up / agg.checks).toFixed(2) : null,
      failureRatePct: agg.checks ? +(100 * failures / agg.checks).toFixed(2) : null,
      avgResponseMs: agg.up ? Math.round(agg.ms / agg.up) : null,
    };
  }

  function urlStats(userId, id, hours = 24) {
    const row = q.getOwnedUrl.get(id, userId);
    if (!row) return null;
    const since = Date.now() - hours * HOUR;
    const buckets = db.prepare('SELECT bucket t,total,up,sum_ms_up,max_ms FROM url_hourly_stats WHERE url_id=? AND bucket>=? ORDER BY bucket').all(id, bucketOf(since));
    const total = buckets.reduce((a, b) => a + b.total, 0), up = buckets.reduce((a, b) => a + b.up, 0);
    const ms = buckets.reduce((a, b) => a + b.sum_ms_up, 0);
    // p95 needs the raw samples (can't be derived from hourly sums); capped for safety.
    const samples = db.prepare(`SELECT response_time_ms v FROM check_results WHERE url_id=? AND checked_at>=? AND status='UP' ORDER BY response_time_ms LIMIT 20000`)
      .all(id, since).map((r) => r.v);
    return {
      urlId: id, url: row.url, windowHours: hours, checks: total, failures: total - up,
      uptimePct: total ? +(100 * up / total).toFixed(3) : null,
      avgResponseMs: up ? Math.round(ms / up) : null,
      p95ResponseMs: samples.length ? samples[Math.min(samples.length - 1, Math.ceil(samples.length * 0.95) - 1)] : null,
      maxResponseMs: buckets.reduce((a, b) => Math.max(a, b.max_ms), 0) || null,
      hourly: buckets.map((b) => ({ t: b.t, checks: b.total, up: b.up, avgMs: b.up ? Math.round(b.sum_ms_up / b.up) : null })),
    };
  }

  function results(userId, id, { limit = 100, before } = {}) {
    if (!q.getOwnedUrl.get(id, userId)) return null;
    limit = Math.min(Math.max(+limit || 100, 1), 1000);
    // Keyset pagination on (checked_at, id): stays O(log n) however deep you page, unlike OFFSET.
    return db.prepare(`SELECT id,status,status_code,response_time_ms,error_type,error_message,attempts,trigger,checked_at
      FROM check_results WHERE url_id=? ${before ? 'AND id<?' : ''} ORDER BY id DESC LIMIT ?`)
      .all(...(before ? [id, +before, limit] : [id, limit]));
  }

  return {
    metrics, runCheckJob, enqueueChecks, addUrls, setSchedule, listUrls, deleteUrl: (u, id) => q.deleteUrl.run(id, u).changes > 0,
    getOwnedUrl: (u, id) => q.getOwnedUrl.get(id, u), enqueueDue, pruneOldResults, summary, urlStats, results,
  };
}

module.exports = { createService };
