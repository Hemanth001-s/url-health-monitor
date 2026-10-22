'use strict';
// Server-Sent Events hub: pushes live updates to every open dashboard tab of a user.
// SSE (vs WebSocket) is one-directional, works over plain HTTP, auto-reconnects in the
// browser and passes through proxies easily -- exactly what a "live dashboard" needs.
class Hub {
  constructor() {
    this.clients = new Map(); // userId -> Set<res>
    this.timer = setInterval(() => this._each((res) => res.write(': ping\n\n')), 25000);
    this.timer.unref();
  }
  _each(fn) { for (const set of this.clients.values()) for (const res of set) { try { fn(res); } catch { /* socket gone */ } } }
  add(userId, res) {
    if (!this.clients.has(userId)) this.clients.set(userId, new Set());
    this.clients.get(userId).add(res);
    res.on('close', () => { const s = this.clients.get(userId); s?.delete(res); if (s && !s.size) this.clients.delete(userId); });
  }
  emit(userId, event, data) {
    const set = this.clients.get(userId);
    if (!set) return;
    const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of set) { try { res.write(msg); } catch { /* ignore */ } }
  }
  count() { let n = 0; for (const s of this.clients.values()) n += s.size; return n; }
  close() { clearInterval(this.timer); this._each((res) => res.end()); this.clients.clear(); }
}
module.exports = { Hub };
