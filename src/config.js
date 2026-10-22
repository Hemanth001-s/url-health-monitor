'use strict';
// All tunables come from env vars so the same build runs locally, in Docker and in CI.
const int = (k, d) => {
  const v = parseInt(process.env[k], 10);
  return Number.isFinite(v) ? v : d;
};

function loadConfig(overrides = {}) {
  return {
    port: int('PORT', 3000),
    dbPath: process.env.DB_PATH || './data/monitor.db',
    jwtSecret: process.env.JWT_SECRET || null, // random per-boot if unset (dev only)
    adminEmail: (process.env.ADMIN_EMAIL || '').toLowerCase(), // this email becomes admin on signup
    concurrency: int('WORKER_CONCURRENCY', 10), // parallel health checks
    timeoutMs: int('CHECK_TIMEOUT_MS', 10000),
    retries: int('CHECK_RETRIES', 1), // extra attempts for transient failures
    retryBaseMs: int('RETRY_BASE_MS', 300), // exponential backoff base
    schedulerTickMs: int('SCHEDULER_TICK_MS', 10000),
    retentionDays: int('RETENTION_DAYS', 30), // raw results pruned after this
    maxUrlsPerUser: int('MAX_URLS_PER_USER', 1000),
    allowPrivateTargets: process.env.ALLOW_PRIVATE_TARGETS === 'true', // SSRF guard off switch
    trustProxy: process.env.TRUST_PROXY === 'true', // behind a reverse proxy/PaaS: use X-Forwarded-For for client IP
    cookieSecure: process.env.COOKIE_SECURE === 'true',
    rateLimitPerMin: int('RATE_LIMIT_PER_MIN', 300),
    authRateLimitPerMin: int('AUTH_RATE_LIMIT_PER_MIN', 10),
    ...overrides,
  };
}
module.exports = { loadConfig };
