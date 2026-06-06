// ─── db.js — Wallet Hunter v4 ────────────────────────────────────────────────
// Schema simplified: no mnemonic, no derivation path, no chain
// Just: private_key (hex) + address (TRON base58check)
// ─────────────────────────────────────────────────────────────────────────────

import Database from 'better-sqlite3';
import { join }  from 'node:path';

const DB_PATH = join(process.cwd(), 'wallet-hunter.db');

let db;
let _insertStmt;
let _insertBatch;

export function initDB() {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous  = NORMAL');
  db.pragma('cache_size   = -32000');   // 32 MB cache

  db.exec(`
    CREATE TABLE IF NOT EXISTS wallets (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      private_key TEXT    NOT NULL UNIQUE,
      address     TEXT    NOT NULL,
      created_at  INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_address    ON wallets (address);
    CREATE INDEX IF NOT EXISTS idx_created_at ON wallets (created_at);
  `);

  _insertStmt = db.prepare(
    `INSERT OR IGNORE INTO wallets (private_key, address)
     VALUES (@privateKey, @address)`
  );
  _insertBatch = db.transaction((rows) => {
    for (const row of rows) _insertStmt.run(row);
  });
}

export function saveWallets(rows) {
  if (!rows?.length) return;
  try { _insertBatch(rows); }
  catch (err) { process.stderr.write(`[db] ${err.message}\n`); }
}

export function getStats() {
  return db ? db.prepare('SELECT COUNT(*) AS n FROM wallets').get().n : 0;
}
