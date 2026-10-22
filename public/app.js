'use strict';
// Plain-JS single page app. All user-controlled text is inserted with textContent
// (never innerHTML), so a hostile URL string cannot inject script (XSS-safe by construction).

const state = { user: null, urls: [], summary: null, selected: null, hours: 24, es: null, pollTimer: null, queued: new Map() };
const $app = document.getElementById('app');

// ---------- tiny helpers ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (v !== false && v != null) el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(kid));
  return el;
}
const svg = (tag, attrs, ...kids) => {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  el.append(...kids);
  return el;
};
async function api(method, path, body) {
  const res = await fetch(path, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && state.user) { logoutLocal(); throw new Error('Session expired, please sign in again'); }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
function toast(msg) { const t = h('div', { class: 'toast' }, msg); document.getElementById('toasts').append(t); setTimeout(() => t.remove(), 4000); }
const fmtMs = (v) => (v == null ? '–' : `${v} ms`);
const fmtPct = (v) => (v == null ? '–' : `${v}%`);
const ago = (t) => { if (!t) return 'never'; const s = Math.round((Date.now() - t) / 1000); return s < 5 ? 'just now' : s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`; };
const hostOf = (u) => { try { return new URL(u).host; } catch { return u; } };

// ---------- auth view ----------
function renderAuth(mode = 'login') {
  const err = h('div', { class: 'err', role: 'alert' });
  const email = h('input', { type: 'email', id: 'email', autocomplete: 'email', required: true });
  const pw = h('input', { type: 'password', id: 'pw', autocomplete: mode === 'login' ? 'current-password' : 'new-password', required: true, minlength: 8 });
  const form = h('form', { onsubmit: async (e) => {
    e.preventDefault(); err.textContent = '';
    try { const r = await api('POST', `/api/auth/${mode === 'login' ? 'login' : 'signup'}`, { email: email.value, password: pw.value }); state.user = r.user; await start(); }
    catch (ex) { err.textContent = ex.message; }
  } },
    h('label', { for: 'email' }, 'Email'), email,
    h('label', { for: 'pw' }, mode === 'login' ? 'Password' : 'Password (min 8 characters)'), pw, err,
    h('button', { class: 'primary', type: 'submit' }, mode === 'login' ? 'Sign in' : 'Create account'));
  $app.replaceChildren(h('div', { class: 'card auth' },
    h('h1', {}, 'URL Health Monitor'), h('p', { class: 'muted' }, mode === 'login' ? 'Sign in to see your monitors.' : 'Create an account to start monitoring.'),
    form, h('p', { class: 'small muted' }, mode === 'login' ? 'No account? ' : 'Already registered? ',
      h('a', { href: '#', onclick: (e) => { e.preventDefault(); renderAuth(mode === 'login' ? 'signup' : 'login'); } }, mode === 'login' ? 'Sign up' : 'Sign in'))));
}

// ---------- dashboard ----------
function renderShell() {
  $app.replaceChildren(
    h('div', { class: 'topbar' },
      h('div', {}, h('h1', {}, 'URL Health Monitor'), h('span', { class: 'muted small', id: 'whoami' }, `${state.user.email}${state.user.role === 'admin' ? ' · admin' : ''}`)),
      h('div', { class: 'row' }, h('span', { class: 'live', id: 'live' }, h('span', { class: 'dot' }), h('span', {}, 'connecting')),
        h('button', { onclick: async () => { await api('POST', '/api/auth/logout'); logoutLocal(); } }, 'Sign out'))),
    h('div', { class: 'tiles', id: 'tiles' }),
    h('div', { class: 'card', id: 'addcard' }),
    h('div', { class: 'card', id: 'listcard' }),
    h('div', { class: 'card', id: 'detail', hidden: true }));
  renderAddForm();
}

function renderTiles() {
  const s = state.summary; if (!s) return;
  const tile = (v, l) => h('div', { class: 'tile' }, h('div', { class: 'v' }, v), h('div', { class: 'l' }, l));
  document.getElementById('tiles').replaceChildren(
    tile(s.totalUrls, 'Total URLs'), tile(`${s.currentlyUp} / ${s.currentlyDown}`, 'Up / Down now'),
    tile(fmtPct(s.uptimePct), 'Uptime (24h)'), tile(s.failures, `Failures (24h) · ${fmtPct(s.failureRatePct)}`), tile(fmtMs(s.avgResponseMs), 'Avg response (24h)'));
}

function renderAddForm() {
  const ta = h('textarea', { id: 'newurls', placeholder: 'One URL per line, or paste a JSON array:\nhttps://www.google.com\nhttps://www.github.com', 'aria-label': 'URLs to monitor' });
  const interval = h('select', { id: 'interval', 'aria-label': 'Schedule' },
    h('option', { value: '' }, 'Manual only'), ...[1, 5, 15, 30, 60, 1440].map((m) => h('option', { value: m, selected: m === 5 }, m === 1440 ? 'Every day' : m === 60 ? 'Every hour' : `Every ${m} min`)));
  const rejected = h('div', { class: 'rejected' });
  const file = h('input', { type: 'file', accept: 'application/json,.json', hidden: true, onchange: async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try { const data = JSON.parse(await f.text()); if (!Array.isArray(data)) throw new Error(); ta.value = JSON.stringify(data, null, 1); toast(`Loaded ${data.length} entries from ${f.name}`); }
    catch { toast('That file is not a JSON array of URLs'); } e.target.value = '';
  } });
  const parse = () => {
    const t = ta.value.trim(); if (!t) return [];
    if (t.startsWith('[')) { try { return JSON.parse(t); } catch { throw new Error('Invalid JSON'); } }
    return t.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  };
  const addBtn = h('button', { class: 'primary', onclick: async () => {
    rejected.textContent = '';
    try {
      const urls = parse(); if (!urls.length) return toast('Enter at least one URL');
      addBtn.disabled = true;
      const r = await api('POST', '/api/urls', { urls, intervalMinutes: interval.value ? +interval.value : null });
      ta.value = '';
      toast(`Added ${r.added.length}${r.duplicates.length ? `, ${r.duplicates.length} duplicate` : ''}${r.rejected.length ? `, ${r.rejected.length} rejected` : ''}`);
      if (r.rejected.length) rejected.textContent = 'Rejected: ' + r.rejected.map((x) => `${x.input} (${x.reason})`).join('; ');
      await refresh();
    } catch (e) { toast(e.message); } finally { addBtn.disabled = false; }
  } }, 'Add URLs');
  document.getElementById('addcard').replaceChildren(h('h2', {}, 'Add URLs'), ta,
    h('div', { class: 'row' }, addBtn, interval, h('button', { onclick: () => file.click() }, 'Upload JSON…'), file,
      h('span', { class: 'muted small' }, 'Checks start immediately; scheduled URLs recheck automatically.')), rejected);
}

function statusBadge(u) {
  if (Date.now() - (state.queued.get(u.id) || 0) < 60000) // expires, so a missed event can never leave a stuck spinner
     return h('span', { class: 'badge queued' }, 'Checking…');
  return h('span', { class: `badge ${u.last_status || 'none'}`, title: u.last_error_type || '' }, u.last_status || 'Pending');
}

function renderList() {
  const card = document.getElementById('listcard');
  const head = h('div', { class: 'topbar' }, h('h2', {}, 'Monitored URLs'),
    h('div', { class: 'row' }, h('button', { class: 'primary', disabled: !state.urls.length, onclick: async () => {
      // Mark BEFORE the request: fast checks can finish (and emit their SSE event) before the response returns.
      state.urls.forEach((u) => state.queued.set(u.id, Date.now())); renderList();
      const r = await api('POST', '/api/checks/run', {}); toast(`Queued ${r.queued} checks`);
    } }, 'Check all now')));
  if (!state.urls.length) { card.replaceChildren(head, h('p', { class: 'muted' }, 'No URLs yet. Add some above to get started.')); return; }
  const rows = state.urls.map((u) => h('tr', { class: state.selected === u.id ? 'sel' : '' },
    h('td', {}, statusBadge(u)),
    h('td', { class: 'url', title: u.url, onclick: () => select(u.id) }, u.url),
    h('td', { class: 'num' }, fmtMs(u.last_response_ms)),
    h('td', { class: 'num hide-sm' }, fmtPct(u.uptime_pct)),
    h('td', { class: 'hide-sm muted small' }, ago(u.last_checked_at), u.last_error_type ? ` · ${u.last_error_type}` : ''),
    h('td', { class: 'hide-sm' }, scheduleSelect(u)),
    h('td', {}, h('div', { class: 'row' },
      h('button', { onclick: async () => { state.queued.set(u.id, Date.now()); renderList(); await api('POST', '/api/checks/run', { ids: [u.id] }); } }, 'Check'),
      h('button', { class: 'danger', 'aria-label': `Remove ${u.url}`, onclick: async () => {
        if (!confirm(`Stop monitoring ${hostOf(u.url)}? Its history will be deleted.`)) return;
        await api('DELETE', `/api/urls/${u.id}`); if (state.selected === u.id) state.selected = null; await refresh();
      } }, 'Remove')))));
  card.replaceChildren(head, h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ...['Status', 'URL', 'Response', 'Uptime 24h', 'Last check', 'Schedule', ''].map((t, i) => h('th', { class: i >= 3 && i <= 5 ? 'hide-sm' : '' }, t)))),
    h('tbody', {}, rows))));
}

function scheduleSelect(u) {
  const sel = h('select', { 'aria-label': 'Schedule', onchange: async () => { await api('PATCH', `/api/urls/${u.id}`, { intervalMinutes: sel.value ? +sel.value : null }); toast('Schedule updated'); await refresh(); } },
    h('option', { value: '' }, 'Manual'), ...[1, 5, 15, 30, 60, 1440].map((m) => h('option', { value: m, selected: u.interval_minutes === m }, m === 1440 ? 'Daily' : m === 60 ? 'Hourly' : `${m} min`)));
  return sel;
}

// ---------- detail + charts ----------
async function select(id) { state.selected = id; renderList(); await renderDetail(); document.getElementById('detail').scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }

async function renderDetail() {
  const box = document.getElementById('detail');
  if (!state.selected) { box.hidden = true; return; }
  const u = state.urls.find((x) => x.id === state.selected); if (!u) { box.hidden = true; return; }
  const [stats, res] = await Promise.all([api('GET', `/api/urls/${u.id}/stats?hours=${state.hours}`), api('GET', `/api/urls/${u.id}/results?limit=100`)]);
  const points = res.results.slice().reverse();
  const hoursSel = h('select', { 'aria-label': 'Time window', onchange: () => { state.hours = +hoursSel.value; renderDetail(); } },
    ...[[1, '1 hour'], [24, '24 hours'], [168, '7 days'], [720, '30 days']].map(([v, l]) => h('option', { value: v, selected: v === state.hours }, l)));
  const stat = (v, l) => h('div', {}, h('b', {}, v), h('span', { class: 'muted small' }, l));
  box.hidden = false;
  box.replaceChildren(
    h('div', { class: 'topbar' }, h('h2', { title: u.url }, u.url), h('div', { class: 'row' }, hoursSel, h('button', { onclick: () => { state.selected = null; box.hidden = true; renderList(); } }, 'Close'))),
    h('div', { class: 'stats' }, stat(fmtPct(stats.uptimePct), 'Uptime'), stat(stats.checks, 'Checks'), stat(stats.failures, 'Failures'),
      stat(fmtMs(stats.avgResponseMs), 'Avg'), stat(fmtMs(stats.p95ResponseMs), 'p95'), stat(fmtMs(stats.maxResponseMs), 'Max')),
    h('h2', {}, 'Response time (last 100 checks)'), responseChart(points),
    h('h2', {}, `Hourly uptime (${hoursSel.selectedOptions[0].text})`), uptimeBars(stats.hourly),
    h('h2', {}, 'Recent checks'), recentTable(res.results.slice(0, 10)));
}

function responseChart(points) {
  const W = 1000, H = 220, pad = { l: 46, r: 10, t: 10, b: 24 };
  const el = svg('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Response time chart' });
  if (!points.length) { el.append(svg('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle' }, 'No data yet')); return el; }
  const max = Math.max(50, ...points.map((p) => p.response_time_ms || 0)) * 1.1;
  const x = (i) => pad.l + (points.length === 1 ? (W - pad.l - pad.r) / 2 : (i * (W - pad.l - pad.r)) / (points.length - 1));
  const y = (v) => pad.t + (1 - v / max) * (H - pad.t - pad.b);
  for (let i = 0; i <= 4; i++) {
    const v = (max * i) / 4, yy = y(v);
    el.append(svg('line', { class: 'grid', x1: pad.l, x2: W - pad.r, y1: yy, y2: yy }), svg('text', { x: pad.l - 6, y: yy + 4, 'text-anchor': 'end' }, `${Math.round(v)}`));
  }
  const up = points.map((p, i) => [p, i]).filter(([p]) => p.status === 'UP');
  if (up.length > 1) {
    const d = up.map(([p, i], k) => `${k ? 'L' : 'M'}${x(i)},${y(p.response_time_ms)}`).join(' ');
    el.append(svg('path', { class: 'area', d: `${d} L${x(up[up.length - 1][1])},${y(0)} L${x(up[0][1])},${y(0)} Z` }), svg('path', { class: 'line', d, 'vector-effect': 'non-scaling-stroke' }));
  }
  points.forEach((p, i) => {
    const c = svg('circle', { class: p.status === 'UP' ? 'good' : 'bad', cx: x(i), cy: p.status === 'UP' ? y(p.response_time_ms) : y(0), r: p.status === 'UP' ? 3 : 5 });
    c.append(svg('title', {}, `${new Date(p.checked_at).toLocaleString()} · ${p.status} · ${p.response_time_ms} ms${p.error_type ? ' · ' + p.error_type : ''}`));
    el.append(c);
  });
  el.append(svg('text', { x: pad.l, y: H - 6 }, new Date(points[0].checked_at).toLocaleTimeString()), svg('text', { x: W - pad.r, y: H - 6, 'text-anchor': 'end' }, new Date(points[points.length - 1].checked_at).toLocaleTimeString()),
    svg('text', { x: 2, y: 10 }, 'ms'));
  return el;
}

function uptimeBars(hourly) {
  const W = 1000, H = 70;
  const el = svg('svg', { class: 'chart short', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Hourly uptime' });
  if (!hourly.length) { el.append(svg('text', { x: W / 2, y: 40, 'text-anchor': 'middle' }, 'No data yet')); return el; }
  const bw = Math.min(40, W / hourly.length);
  hourly.forEach((b, i) => {
    const pct = b.checks ? b.up / b.checks : 0, x = W - (hourly.length - i) * bw;
    const r = svg('rect', { class: pct === 1 ? 'good' : 'bad', x: x + 1, y: 4 + (1 - Math.max(pct, 0.06)) * 56, width: bw - 2, height: Math.max(pct, 0.06) * 56, rx: 2 });
    r.append(svg('title', {}, `${new Date(b.t).toLocaleString()} · ${(pct * 100).toFixed(1)}% up (${b.up}/${b.checks})${b.avgMs != null ? ' · avg ' + b.avgMs + ' ms' : ''}`));
    el.append(r);
  });
  return el;
}

function recentTable(rows) {
  if (!rows.length) return h('p', { class: 'muted' }, 'No checks yet.');
  return h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...['Time', 'Result', 'HTTP', 'Response', 'Attempts', 'Trigger', 'Error'].map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.map((r) => h('tr', {}, h('td', { class: 'small' }, new Date(r.checked_at).toLocaleString()), h('td', {}, h('span', { class: `badge ${r.status}` }, r.status)),
      h('td', { class: 'num' }, r.status_code ?? '–'), h('td', { class: 'num' }, fmtMs(r.response_time_ms)), h('td', { class: 'num' }, r.attempts), h('td', { class: 'small' }, r.trigger),
      h('td', { class: 'small muted' }, r.error_message || ''))))));
}

// ---------- data + real-time ----------
async function refresh() {
  const [{ urls }, summary] = await Promise.all([api('GET', '/api/urls'), api('GET', '/api/summary')]);
  state.urls = urls; state.summary = summary;
  for (const id of [...state.queued.keys()]) { const u = urls.find((x) => x.id === id); if (!u) state.queued.delete(id); }
  renderTiles(); renderList();
  if (state.selected) renderDetail().catch(() => {});
}

let refreshTimer = null;
const refreshSoon = () => { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => refresh().catch(() => {}), 250); }; // coalesce bursts

function connectEvents() {
  const live = document.getElementById('live');
  const setLive = (on, text) => { if (!live) return; live.firstChild.className = `dot${on ? ' on' : ''}`; live.lastChild.textContent = text; };
  state.es?.close();
  const es = new EventSource('/api/events'); state.es = es;
  es.onopen = () => { setLive(true, 'live'); clearInterval(state.pollTimer); state.pollTimer = null; };
  es.onerror = () => { setLive(false, 'reconnecting (polling)'); if (!state.pollTimer) state.pollTimer = setInterval(() => refresh().catch(() => {}), 15000); }; // polling fallback
  es.addEventListener('check.completed', (e) => {
    const d = JSON.parse(e.data); state.queued.delete(d.urlId);
    const u = state.urls.find((x) => x.id === d.urlId);
    if (u) { u.last_status = d.status; u.last_response_ms = d.responseTimeMs; u.last_checked_at = d.checkedAt; u.last_error_type = d.errorType; u.last_status_code = d.statusCode; renderList(); }
    refreshSoon();
  });
  es.addEventListener('status.changed', (e) => { const d = JSON.parse(e.data); toast(`${hostOf(d.url)} is now ${d.to}`); });
  for (const t of ['url.added', 'url.removed']) es.addEventListener(t, refreshSoon);
}

function logoutLocal() { state.es?.close(); clearInterval(state.pollTimer); state.user = null; state.urls = []; state.selected = null; state.queued.clear(); renderAuth(); }

async function start() {
  renderShell();
  await refresh();
  connectEvents();
  setInterval(() => { if (state.user && state.urls.length) renderList(); }, 30000); // refresh the "x ago" labels
}

(async () => {
  try { state.user = (await (await fetch('/api/me')).json()).user; } catch { /* not logged in */ }
  if (state.user) start().catch((e) => toast(e.message)); else renderAuth();
})();
