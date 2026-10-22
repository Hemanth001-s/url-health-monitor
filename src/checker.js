'use strict';
// The health-check engine: validates URLs, performs one HTTP check, classifies every
// failure mode, and retries transient failures with exponential backoff + jitter.
const dns = require('node:dns').promises;
const net = require('node:net');

const MAX_REDIRECTS = 5;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- URL validation ----------
function validateUrl(raw) {
  let u;
  try { u = new URL(String(raw).trim()); } catch { return { ok: false, reason: 'Not a valid URL' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, reason: 'Only http/https URLs are supported' };
  if (u.username || u.password) return { ok: false, reason: 'URLs with embedded credentials are not allowed' };
  if (u.href.length > 2048) return { ok: false, reason: 'URL too long' };
  return { ok: true, url: u.href };
}

// ---------- SSRF protection ----------
// Users submit URLs and OUR server fetches them. Without this guard a user could make us
// probe 127.0.0.1, cloud metadata (169.254.169.254) or internal services.
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const v = ip.toLowerCase();
  if (v === '::1' || v === '::') return true;
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v.startsWith('fc') || v.startsWith('fd') || /^fe[89ab]/.test(v);
}

class CheckFailure extends Error {
  constructor(type, message, retryable = false) { super(message); this.type = type; this.retryable = retryable; }
}

function classifyError(err) {
  if (err instanceof CheckFailure) return err;
  if (err.name === 'TimeoutError' || err.name === 'AbortError') return new CheckFailure('TIMEOUT', 'Request timed out', true);
  const code = err.code || err.cause?.code || '';
  if (code === 'ENOTFOUND') return new CheckFailure('DNS_FAILURE', 'DNS lookup failed: host not found', false);
  if (code === 'EAI_AGAIN') return new CheckFailure('DNS_FAILURE', 'DNS lookup failed: temporary failure', true);
  if (/CERT|SSL|TLS/.test(code)) return new CheckFailure('TLS_ERROR', `TLS error: ${code}`, false);
  if (code === 'ECONNREFUSED') return new CheckFailure('CONNECTION_ERROR', 'Connection refused', true);
  if (code) return new CheckFailure('CONNECTION_ERROR', `Connection error: ${code}`, true);
  return new CheckFailure('UNKNOWN_ERROR', err.message || 'Unknown error', true);
}

async function assertPublicHost(hostname, cfg, signal) {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (!cfg.allowPrivateTargets && isPrivateIp(host)) throw new CheckFailure('BLOCKED_TARGET', 'Target resolves to a private address');
    return;
  }
  // dns.lookup has no AbortSignal support, so race it against the deadline.
  const addrs = await Promise.race([
    dns.lookup(host, { all: true }),
    new Promise((_, rej) => signal.addEventListener('abort', () => rej(signal.reason), { once: true })),
  ]);
  if (!cfg.allowPrivateTargets && addrs.some((a) => isPrivateIp(a.address))) {
    throw new CheckFailure('BLOCKED_TARGET', 'Target resolves to a private address');
  }
}

// ---------- one attempt ----------
async function attemptOnce(url, cfg) {
  const started = performance.now();
  const signal = AbortSignal.timeout(cfg.timeoutMs); // one deadline across DNS + redirects + TLS + headers
  let current = url;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      await assertPublicHost(new URL(current).hostname, cfg, signal);
      // Redirects are followed manually so every hop is re-validated (SSRF via redirect).
      const res = await fetch(current, { method: 'GET', redirect: 'manual', signal, headers: { 'user-agent': 'UrlHealthMonitor/1.0' } });
      res.body?.cancel().catch(() => {}); // we only need status + time-to-headers, not the body
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        current = new URL(res.headers.get('location'), current).href;
        continue;
      }
      const ms = Math.round(performance.now() - started);
      const up = res.status >= 200 && res.status <= 299;
      return {
        status: up ? 'UP' : 'DOWN', statusCode: res.status, responseTimeMs: ms,
        errorType: up ? null : res.status >= 500 ? 'HTTP_5XX' : 'HTTP_ERROR',
        errorMessage: up ? null : `HTTP ${res.status}`,
        retryable: res.status >= 500,
      };
    }
    throw new CheckFailure('TOO_MANY_REDIRECTS', `More than ${MAX_REDIRECTS} redirects`);
  } catch (err) {
    const f = classifyError(err);
    return {
      status: 'DOWN', statusCode: null, responseTimeMs: Math.round(performance.now() - started),
      errorType: f.type, errorMessage: f.message, retryable: f.retryable,
    };
  }
}

// ---------- public API: attempt + retry with exponential backoff ----------
async function checkUrl(url, cfg) {
  let result, attempts = 0;
  for (let i = 0; i <= cfg.retries; i++) {
    attempts++;
    result = await attemptOnce(url, cfg);
    if (result.status === 'UP' || !result.retryable || i === cfg.retries) break;
    // 300ms, 600ms, 1200ms ... plus up to 25% jitter so retries from many URLs don't sync up.
    const delay = cfg.retryBaseMs * 2 ** i;
    await sleep(delay + Math.random() * delay * 0.25);
  }
  const { retryable, ...out } = result;
  return { ...out, attempts, checkedAt: Date.now() };
}

module.exports = { checkUrl, validateUrl, isPrivateIp, classifyError };
