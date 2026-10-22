'use strict';
// In-process job queue with a fixed-size worker pool. This is the seam where Redis/BullMQ
// would plug in: producers call enqueue(), workers run `handler(job)`. Same contract.
const log = require('./logger');

class JobQueue {
  constructor({ concurrency, handler }) {
    this.concurrency = concurrency;
    this.handler = handler;
    this.pending = [];          // FIFO
    this.keys = new Set();      // keys queued or running -> de-duplication
    this.running = 0;
    this.stats = { enqueued: 0, completed: 0, failed: 0, deduped: 0 };
    this.idleWaiters = [];
  }

  // key = e.g. "url:42"; a URL that is already queued/running is not queued twice.
  enqueue(data, key) {
    if (key && this.keys.has(key)) { this.stats.deduped++; return false; }
    if (key) this.keys.add(key);
    // Capture the caller's correlation id so worker logs trace back to the originating request.
    this.pending.push({ data, key, correlationId: log.currentCorrelationId() });
    this.stats.enqueued++;
    setImmediate(() => this._drain());
    return true;
  }

  _drain() {
    while (this.running < this.concurrency && this.pending.length) {
      const job = this.pending.shift();
      this.running++;
      log.withContext({ correlationId: job.correlationId }, async () => {
        try { await this.handler(job.data); this.stats.completed++; }
        catch (err) { this.stats.failed++; log.error('job.failed', { ...log.errFields(err), job: job.data }); }
        finally {
          if (job.key) this.keys.delete(job.key);
          this.running--;
          this._drain();
          if (!this.running && !this.pending.length) this.idleWaiters.splice(0).forEach((r) => r());
        }
      });
    }
  }

  depth() { return this.pending.length; }
  onIdle() { return this.running || this.pending.length ? new Promise((r) => this.idleWaiters.push(r)) : Promise.resolve(); }
}

module.exports = { JobQueue };
