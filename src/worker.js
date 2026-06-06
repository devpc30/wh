// ═══════════════════════════════════════════════════════════════════════════════
// worker.js — Wallet Hunter v5  (Phase-0 optimized)
//
// Hot path per address:
//   prgFill           → 32-byte private key  (xoshiro128++, zero syscalls)
//   publicKeyCreate   → 65-byte uncompressed pubkey  (native C)
//   keccak_256        → 32-byte hash  (@noble, pure JS — phase 1 will replace)
//
//   HUNT mode (optimized):
//     kHash[12..31]   → raw 20-byte compare vs. decoded target bytes
//     ★ NO sha256d, NO base58Encode on non-matching addresses
//
//   SCAN / save-all mode:
//     sha256(sha256(payload)) → 4-byte checksum   (node:crypto — native OpenSSL)
//     base58Encode             → "T…" TRON address
//
// Phase-0 wins vs v4:
//   ✓ BATCH 256 → 2048      — 8× less loop overhead
//   ✓ node:crypto sha256     — ~3× faster than @noble for sha256d
//   ✓ hunt mode: skip sha256d + base58 entirely  — ~11% saved on hunt path
//   ✓ Buffer view for privKey — one less 32-byte copy per iteration
// ═══════════════════════════════════════════════════════════════════════════════

import { workerData, parentPort }   from 'node:worker_threads';
import { randomBytes, createHash }  from 'node:crypto';   // ← native sha256
import { keccak_256 }               from '@noble/hashes/sha3';
import { createRequire }            from 'node:module';

const { publicKeyCreate } = createRequire(import.meta.url)('secp256k1');

const { sab, targetBytesFlat, numTargets, saveAll } = workerData;

const counters = new BigInt64Array(sab);
const huntMode = numTargets > 0;

// ── Target list — views into the flat buffer (no copy) ────────────────────────
const _targets = [];
for (let i = 0; i < numTargets; i++) {
  _targets.push(
    new Uint8Array(targetBytesFlat.buffer, targetBytesFlat.byteOffset + i * 20, 20)
  );
}

// ── xoshiro128++ PRNG ─────────────────────────────────────────────────────────
// Period: 2^128 − 1  |  BigCrush pass  |  one OS syscall per worker lifetime
const _s = (() => {
  const seed = randomBytes(16);
  const s    = new Uint32Array(4);
  const v    = new DataView(seed.buffer, seed.byteOffset, 16);
  s[0] = v.getUint32(0,  true) || 1;
  s[1] = v.getUint32(4,  true) || 2;
  s[2] = v.getUint32(8,  true) || 3;
  s[3] = v.getUint32(12, true) || 4;
  return s;
})();

const _rotl32 = (x, k) => ((x << k) | (x >>> (32 - k))) >>> 0;

function _next32() {
  const r = (_rotl32((_s[0] + _s[3]) >>> 0, 7) + _s[0]) >>> 0;
  const t = (_s[1] << 9) >>> 0;
  _s[2] ^= _s[0]; _s[3] ^= _s[1];
  _s[1] ^= _s[2]; _s[0] ^= _s[3];
  _s[2] ^= t;
  _s[3] = _rotl32(_s[3], 11);
  return r;
}

function prgFill(buf) {
  const u32 = new Uint32Array(buf.buffer, buf.byteOffset, buf.byteLength >>> 2);
  for (let i = 0; i < u32.length; i++) u32[i] = _next32();
  let r = _next32(), rem = buf.byteLength & 3, off = u32.length << 2;
  while (rem-- > 0) { buf[off++] = r & 0xff; r >>>= 8; }
}

// ── Pre-allocated buffers ─────────────────────────────────────────────────────
const BATCH    = 2048;                           // ← 8× larger (was 256)
const _pool    = new Uint8Array(32 * BATCH);
const _payload = new Uint8Array(21);             // 0x41 ‖ 20-byte hash
const _addrBuf = new Uint8Array(25);             // payload ‖ 4-byte checksum

// ── node:crypto SHA-256 — native OpenSSL, ~3× @noble ─────────────────────────
// Called only in save-all mode or on a hit — NOT for every non-matching address
function _sha256(buf) { return createHash('sha256').update(buf).digest(); }

// ── base58 ────────────────────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  const digits = [0];
  for (let i = 0; i < buf.length; i++) {
    let carry = buf[i];
    for (let j = 0; j < digits.length; j++) {
      carry     += digits[j] << 8;
      digits[j]  = carry % 58;
      carry      = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let s = '';
  for (let i = 0; i < buf.length && buf[i] === 0; i++) s += '1';
  return s + digits.reverse().map(d => B58[d]).join('');
}

// Build TRON address string from a keccak32 result
// Only called for save-all (every address) or on a hunt hit (rare event)
function buildAddrFromKhash(kHash) {
  _payload[0] = 0x41;
  _payload.set(kHash.subarray(12), 1);
  const cs = _sha256(_sha256(_payload));          // native sha256 ×2
  _addrBuf.set(_payload);
  _addrBuf.set(cs.subarray(0, 4), 21);
  return base58Encode(_addrBuf);
}

// ── Hunt-mode: raw byte compare — NO base58, NO sha256 ───────────────────────
// Compares kHash[12..31] (the 20 address bytes) against pre-decoded targets
function matchesAnyTarget(kHash) {
  outer: for (let t = 0; t < numTargets; t++) {
    const tb = _targets[t];
    for (let i = 0; i < 20; i++) {
      if (kHash[12 + i] !== tb[i]) continue outer;
    }
    return true;
  }
  return false;
}

// ── Hot loop ──────────────────────────────────────────────────────────────────
for (;;) {
  try {
    prgFill(_pool);

    let hits  = null;
    let batch = saveAll ? [] : null;

    for (let b = 0; b < BATCH; b++) {
      try {
        // Create a Buffer VIEW of the pool slice (no 32-byte copy)
        const off     = b * 32;
        const privKey = Buffer.from(_pool.buffer, _pool.byteOffset + off, 32);

        const pub65  = publicKeyCreate(privKey, false);   // native C → 65 bytes
        const kHash  = keccak_256(pub65.subarray(1));     // pure JS  → 32 bytes

        if (huntMode) {
          // ★ FAST PATH: only raw-byte compare — sha256d + base58 eliminated
          if (matchesAnyTarget(kHash)) {
            const addr = buildAddrFromKhash(kHash);       // hit only (very rare)
            if (!hits) hits = [];
            hits.push({ privateKey: privKey.toString('hex'), address: addr });
          }
        } else if (saveAll) {
          const addr = buildAddrFromKhash(kHash);
          batch.push({ privateKey: privKey.toString('hex'), address: addr });
        }

      } catch { /* private key = 0 or ≥ curve order — probability ≈ 2^−128 */ }
    }

    Atomics.add(counters, 0, BigInt(BATCH));

    if (hits?.length)  parentPort.postMessage({ type: 'match',   hits });
    if (batch?.length) parentPort.postMessage({ type: 'wallets', wallets: batch });

  } catch (err) {
    parentPort.postMessage({ type: 'error', message: err.message });
  }
}
