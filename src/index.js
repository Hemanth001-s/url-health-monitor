'use strict';
const { createApp } = require('./server');
const log = require('./logger');

const app = createApp();
app.start().catch((err) => { log.error('server.start_failed', log.errFields(err)); process.exit(1); });

let stopping = false;
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    if (stopping) return; stopping = true;
    log.info('server.shutdown_requested', { signal: sig });
    await app.stop();
    process.exit(0);
  });
}
process.on('unhandledRejection', (e) => log.error('unhandled_rejection', log.errFields(e)));
