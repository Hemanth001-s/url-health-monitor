'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS urls (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  url              TEXT NOT NULL,
  interval_minutes INTEGER,            -- NULL = manual only
  next_check_at    INTEGER,            -- epoch ms, set when scheduled
  last_status      TEXT,               -- denormalised "current state" (UP/DOWN/NULL)
  last_status_code INTEGER,
  last_response_ms INTEGER,
  last_error_type  TEXT,
  last_checked_at  INTEGER,
  created_at       INTEGER NOT NULL,
  UNIQUE (user_id, url)
);
CREATE INDEX IF NOT EXISTS idx_urls_user ON urls(user_id);
-- Scheduler hot path: only scheduled rows are indexed (partial index).
CREATE INDEX IF NOT EXISTS idx_urls_due ON urls(next_check_at) WHERE interval_minutes IS NOT NULL;

-- Append-only history. The big table. Index matches the dominant query:
-- "latest N results for URL X" / "results for X in a time range".
CREATE TABLE IF NOT EXISTS check_results (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  url_id           INTEGER NOT NULL REFERENCES urls(id) ON DELETE CASCADE,
  status           TEXT NOT NULL CHECK (status IN ('UP','DOWN')),
  status_code      INTEGER,
  response_time_ms INTEGER,
  error_type       TEXT,
  error_message    TEXT,
  attempts         INTEGER NOT NULL DEFAULT 1,
  trigger          TEXT NOT NULL DEFAULT 'manual',
  correlation_id   TEXT,
  checked_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_url_time ON check_results(url_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_results_time ON check_results(checked_at);  -- retention pruning

-- Aggregated report table: one row per URL per hour, upserted on every check.
-- Dashboards/uptime/SLA read this (tiny) instead of scanning raw history.
CREATE TABLE IF NOT EXISTS url_hourly_stats (
  url_id    INTEGER NOT NULL REFERENCES urls(id) ON DELETE CASCADE,
  bucket    INTEGER NOT NULL,          -- epoch ms truncated to the hour
  total     INTEGER NOT NULL DEFAULT 0,
  up        INTEGER NOT NULL DEFAULT 0,
  sum_ms_up INTEGER NOT NULL DEFAULT 0, -- response time sum over UP checks only
  max_ms    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (url_id, bucket)
) WITHOUT ROWID;
`;

function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);
  return db;
}

// Small transaction helper (node:sqlite has none built in).
function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

module.exports = { openDb, tx };
