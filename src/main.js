#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// main.js — Wallet Hunter v5  (Phase-0 optimized)
//
//   ► Interactive startup when run with no arguments
//   ► CLI args still work exactly as before (backward-compatible)
//   ► Targets decoded once to raw 20-byte buffers at startup
//     Workers receive a flat Uint8Array — no string comparison in hot path
// ═══════════════════════════════════════════════════════════════════════════════

import { Worker }                    from 'node:worker_threads';
import { cpus }                      from 'node:os';
import { fileURLToPath }             from 'node:url';
import { dirname, join }             from 'node:path';
import { existsSync, readFileSync }  from 'node:fs';
import { createInterface }           from 'node:readline';
import { initDB, saveWallets, getStats } from './db.js';

const __dirname   = dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = join(__dirname, 'worker.js');

// ── ANSI ──────────────────────────────────────────────────────────────────────
const R   = '\x1b[0m';
const B   = '\x1b[1m';
const DIM = '\x1b[2m';
const GRN = '\x1b[32m';
const CYN = '\x1b[36m';
const YLW = '\x1b[33m';
const RED = '\x1b[31m';
const MAG = '\x1b[35m';
const EL  = '\x1b[2K\r';

// ── Number formatting ─────────────────────────────────────────────────────────
function fmt(n) {
  if (typeof n === 'bigint') n = Number(n);
  if (n >= 1e12) return (n / 1e12).toFixed(2) + 'T';
  if (n >= 1e9)  return (n / 1e9 ).toFixed(2) + 'B';
  if (n >= 1e6)  return (n / 1e6 ).toFixed(2) + 'M';
  if (n >= 1e3)  return (n / 1e3 ).toFixed(1) + 'K';
  return String(Math.round(n));
}

function fmtRate(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M/s';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K/s';
  return Math.round(n) + '/s';
}

function fmtTime(ms) {
  const s  = Math.floor(ms / 1000);
  const hh = String(Math.floor(s / 3600)).padStart(2, '0');
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

// ── Base58 decode (startup only — BigInt is fine here) ────────────────────────
const _B58     = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const _B58_INV = new Uint8Array(256).fill(0xff);
for (let i = 0; i < _B58.length; i++) _B58_INV[_B58.charCodeAt(i)] = i;

function tronAddrToBytes(addr) {
  addr = addr.trim();
  if (addr.length !== 34 || addr[0] !== 'T') {
    throw new Error(`Invalid TRON address (must be 34 chars, start with T): ${addr}`);
  }
  let n = 0n;
  for (const c of addr) {
    const d = _B58_INV[c.charCodeAt(0)];
    if (d === 0xff) throw new Error(`Invalid base58 char '${c}' in address: ${addr}`);
    n = n * 58n + BigInt(d);
  }
  const bytes = new Uint8Array(25);
  for (let i = 24; i >= 0; i--) { bytes[i] = Number(n & 0xffn); n >>= 8n; }
  if (bytes[0] !== 0x41) throw new Error(`Not a TRON address (prefix = 0x${bytes[0].toString(16)}): ${addr}`);
  return bytes.subarray(1, 21);   // 20 raw address bytes
}

// ── CLI arg parser ─────────────────────────────────────────────────────────────
function parseArgs() {
  const argv = process.argv.slice(2);
  const opts = { workers: cpus().length, targets: [], saveAll: false };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-w': case '--workers':     opts.workers = parseInt(argv[++i], 10); break;
      case '-t': case '--target':      opts.targets.push(argv[++i].trim()); break;
      case '--save-all':               opts.saveAll = true; break;
      case '--targets-file': {
        const path = argv[++i];
        if (existsSync(path)) {
          readFileSync(path, 'utf8')
            .split('\n').map(l => l.trim()).filter(Boolean)
            .forEach(a => opts.targets.push(a));
        } else {
          process.stderr.write(`${RED}warn: targets file not found: ${path}${R}\n`);
        }
        break;
      }
    }
  }
  return opts;
}

// ── Help ──────────────────────────────────────────────────────────────────────
function printHelp() {
  console.log(`
  ${B}TRON HUNTER${R}  v5.0  ${DIM}(Phase-0 optimized)${R}

  ${DIM}Pure secp256k1 — no mnemonic, no PBKDF2, no BIP32.
  Each iteration: random 32 bytes → EC pubkey → keccak256 → TRON address.
  Hunt mode: raw byte compare, no base58 / sha256 on non-matching addresses.${R}

  ${DIM}Usage${R}
    node src/main.js [options]
    node src/main.js                  ${DIM}← interactive setup${R}

  ${DIM}Options${R}
    ${CYN}-w, --workers <n>${R}       Worker threads  (default: ${cpus().length})
    ${CYN}-t, --target <addr>${R}     TRON target address  (repeat for multiple)
    ${CYN}--targets-file <path>${R}   File with one TRON address per line
    ${CYN}--save-all${R}              Save every generated wallet to DB
    ${CYN}-h, --help${R}             Show this help

  ${DIM}Examples${R}
    node src/main.js -w 12
    node src/main.js -t TLm2haFEW9NXHKqyNgu2sHzggH88oAiryp -w 16
    node src/main.js --targets-file targets.txt -w 8
    node src/main.js --save-all -w 4
`);
}

// ── Interactive setup (runs when no CLI args given) ───────────────────────────
async function interactiveSetup() {
  const rl  = createInterface({ input: process.stdin, output: process.stdout });
  const ask = (prompt, def = '') => new Promise(res => {
    const hint = def ? ` ${DIM}[${def}]${R}` : '';
    rl.question(`  ${CYN}?${R}  ${prompt}${hint}: `, a => res(a.trim() || def));
  });

  const numCPUs = cpus().length;
  const LINE    = `${DIM}${'─'.repeat(55)}${R}`;

  process.stdout.write('\x1b[2J\x1b[H');
  console.log(`
  ${B}TRON HUNTER${R}  ${DIM}v5.0  ·  interactive setup${R}

  ${LINE}
`);

  // Workers
  const wStr   = await ask('Worker threads', String(numCPUs));
  const workers = Math.max(1, parseInt(wStr, 10) || numCPUs);

  // Targets (allow multiple, one per prompt)
  const targets = [];
  console.log(`\n  ${DIM}Enter target addresses one by one. Press Enter with no input when done.${R}`);
  let addrIdx = 1;
  for (;;) {
    const raw = await ask(`Target #${addrIdx} (or Enter to ${targets.length === 0 ? 'scan' : 'start'})`, '');
    if (!raw) break;
    try {
      tronAddrToBytes(raw);   // validate
      targets.push(raw);
      console.log(`  ${GRN}✓${R}  Added: ${DIM}${raw}${R}`);
      addrIdx++;
    } catch (e) {
      console.log(`  ${RED}✗${R}  ${e.message}`);
    }
  }

  // Save-all (only relevant in scan mode)
  let saveAll = false;
  if (targets.length === 0) {
    const sv = await ask('Save all wallets to DB? (y/N)', 'n');
    saveAll = sv.toLowerCase() === 'y';
  }

  rl.close();
  return { workers, targets, saveAll };
}

// ── Validate and decode targets → 20-byte raw buffers ────────────────────────
function decodeTargets(rawAddrs) {
  const decoded = [];
  for (const addr of rawAddrs) {
    try {
      decoded.push({ addr, bytes: tronAddrToBytes(addr) });
    } catch (e) {
      process.stderr.write(`${RED}warn: ${e.message}${R}\n`);
    }
  }
  return decoded;
}

// Build flat Uint8Array: 20 bytes × numTargets (for transfer to workers)
function buildTargetFlat(decoded) {
  const flat = new Uint8Array(decoded.length * 20);
  decoded.forEach(({ bytes }, i) => flat.set(bytes, i * 20));
  return flat;
}

// ── Entry ─────────────────────────────────────────────────────────────────────
const rawArgs = process.argv.slice(2);

if (rawArgs.includes('-h') || rawArgs.includes('--help')) {
  printHelp();
  process.exit(0);
}

const hasMeaningfulArgs = rawArgs.some(a =>
  ['-w','--workers','-t','--target','--targets-file','--save-all'].includes(a)
);

const opts = hasMeaningfulArgs ? parseArgs() : await interactiveSetup();

opts.workers = Math.max(1, Math.min(512, Number.isFinite(opts.workers) ? opts.workers : cpus().length));

const decoded        = decodeTargets(opts.targets);
const targetBytesFlat = buildTargetFlat(decoded);
const numTargets     = decoded.length;
const huntMode       = numTargets > 0;

initDB();

// SharedArrayBuffer — index 0: BigInt64 total address counter
const sab      = new SharedArrayBuffer(8);
const counters = new BigInt64Array(sab);

// ── Header ────────────────────────────────────────────────────────────────────
process.stdout.write('\x1b[2J\x1b[H');

const modeLabel = huntMode
  ? `${GRN}${B}HUNT${R}  ${DIM}·  ${numTargets} target${numTargets === 1 ? '' : 's'}${R}`
  : opts.saveAll
    ? `${CYN}SCAN${R}  ${DIM}·  save-all${R}`
    : `${CYN}SCAN${R}`;

const LINE = `${DIM}${'─'.repeat(55)}${R}`;

console.log(`
  ${B}TRON HUNTER${R}  ${DIM}v5.0  ·  secp256k1  ·  no mnemonic  ·  Phase-0${R}

  ${DIM}workers${R}  ${B}${opts.workers}${R}      ${DIM}mode${R}  ${modeLabel}
  ${DIM}db     ${R}  ${DIM}wallet-hunter.db${R}

  ${LINE}
`);

if (huntMode) {
  for (const { addr } of decoded) {
    console.log(`  ${DIM}target ${R}  ${MAG}${addr}${R}`);
  }
  console.log(`\n  ${DIM}${LINE}${R}`);
}

console.log(`  ${DIM}Ctrl+C to stop${R}\n`);

// ── Spawn workers ─────────────────────────────────────────────────────────────
const workers = [];

for (let i = 0; i < opts.workers; i++) {
  const w = new Worker(WORKER_PATH, {
    workerData: {
      sab,
      targetBytesFlat,   // Uint8Array(20 × numTargets) — decoded at startup
      numTargets,
      saveAll: opts.saveAll,
    },
  });

  w.on('message', (msg) => {
    switch (msg.type) {
      case 'match': {
        saveWallets(msg.hits);
        process.stdout.write(EL);
        for (const hit of msg.hits) {
          console.log(`  ${GRN}${B}★ HIT${R}  ${B}${hit.address}${R}`);
          console.log(`         ${DIM}priv${R}  ${YLW}${hit.privateKey}${R}`);
          console.log('');
        }
        break;
      }
      case 'wallets': {
        saveWallets(msg.wallets);
        break;
      }
      case 'error': {
        process.stderr.write(`  ${RED}[w${i}] ${msg.message}${R}\n`);
        break;
      }
    }
  });

  w.on('error', err => process.stderr.write(`  ${RED}[w${i}] ${err.message}${R}\n`));
  workers.push(w);
}

// ── Display loop — polls SharedArrayBuffer, zero IPC overhead ─────────────────
let lastCount   = 0n;
let totalCount  = 0n;
let lastTime    = Date.now();
const startTime = Date.now();

const displayInterval = setInterval(() => {
  const current = Atomics.load(counters, 0);
  const delta   = current - lastCount;
  lastCount     = current;
  totalCount   += delta;

  const now     = Date.now();
  const elapsed = (now - lastTime) / 1000 || 0.001;
  lastTime      = now;

  const rate    = Number(delta) / elapsed;
  const runtime = fmtTime(now - startTime);

  process.stdout.write(
    `${EL}  ${CYN}⚡${R}  ` +
    `${B}${fmtRate(rate)}${R}  ${DIM}·${R}  ` +
    `${fmt(totalCount)} checked  ${DIM}·${R}  ` +
    `${DIM}${opts.workers}W${R}  ${DIM}·${R}  ` +
    `${DIM}${runtime}${R}  `
  );
}, 1000);

// ── Graceful shutdown ─────────────────────────────────────────────────────────
async function shutdown() {
  clearInterval(displayInterval);
  process.stdout.write(EL);

  console.log('\n  Stopping…');
  for (const w of workers) w.terminate();

  const saved   = getStats();
  const runtime = fmtTime(Date.now() - startTime);

  console.log(`
  ${DIM}checked${R}  ${B}${fmt(totalCount)}${R}
  ${DIM}saved  ${R}  ${B}${saved}${R}
  ${DIM}time   ${R}  ${B}${runtime}${R}

  ${DIM}Goodbye.${R}
`);
  process.exit(0);
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);
