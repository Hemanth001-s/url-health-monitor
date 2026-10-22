'use strict';
// Structured JSON logger with levels + correlation IDs carried via AsyncLocalStorage.
// Every log line emitted while handling a request (or running a job spawned by it)
// automatically carries the same correlationId, without passing it around by hand.
const { AsyncLocalStorage } = require('node:async_hooks');
const crypto = require('node:crypto');

const als = new AsyncLocalStorage();
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
let minLevel = LEVELS[process.env.LOG_LEVEL] || LEVELS.info;
let sink = (line) => process.stdout.write(line + '\n');

const newId = () => crypto.randomUUID();
const withContext = (ctx, fn) => als.run({ ...(als.getStore() || {}), ...ctx }, fn);
const currentCorrelationId = () => als.getStore()?.correlationId;

function errFields(err) {
  if (!err) return {};
  return { error: { name: err.name, message: err.message, code: err.code || err.cause?.code } };
}

function log(level, msg, fields = {}) {
  if (LEVELS[level] < minLevel) return;
  const ctx = als.getStore() || {};
  sink(JSON.stringify({ time: new Date().toISOString(), level, msg, correlationId: ctx.correlationId, ...fields }));
}

module.exports = {
  debug: (m, f) => log('debug', m, f),
  info: (m, f) => log('info', m, f),
  warn: (m, f) => log('warn', m, f),
  error: (m, f) => log('error', m, f),
  errFields, newId, withContext, currentCorrelationId,
  setLevel: (l) => { minLevel = LEVELS[l] || minLevel; },
  setSink: (fn) => { sink = fn; }, // used by tests
};
