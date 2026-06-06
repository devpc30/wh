# TRON Wallet Hunter — v5.0 (Phase-0 Optimized)

Pure `secp256k1` TRON address scanner. No mnemonic, no BIP32, no PBKDF2.  
Random 32-byte private keys → EC pubkey → keccak256 → TRON address.

---

## Phase-0 Changes (vs v4)

| Optimization | Detail | Speedup |
|---|---|---|
| `BATCH 256 → 2048` | 8× less per-batch overhead | ~5–8% |
| `node:crypto sha256` | Native OpenSSL vs @noble pure JS | ~3× on sha256d |
| **Hunt mode: skip sha256d + base58** | Raw 20-byte compare only | ~11% on hunt path |
| Buffer view for privKey | No 32-byte copy per iteration | Minor GC relief |

**Total CPU improvement: ~1.4–1.7× vs v4**

### Why hunt mode is faster

In v4, for every address:
```
privKey → pubKey → keccak → payload → sha256d → base58 → Set.has(string)
```

In v5, for every address in hunt mode:
```
privKey → pubKey → keccak → kHash[12..31] == targetBytes?  ← DONE
```
`sha256d` and `base58Encode` are skipped entirely for non-matching addresses.  
Target addresses are decoded once at startup to raw 20-byte buffers.

---

## Install

```bash
npm install
```

> **Note:** `secp256k1` requires native compilation. You'll need build tools:
> - Linux: `build-essential`, `python3`
> - Windows: Visual C++ Build Tools

---

## Usage

### Interactive (no args)

```bash
node src/main.js
```

Prompts for workers, target addresses, and save-all option.

### CLI

```bash
# Scan mode (no target)
node src/main.js -w 12

# Hunt mode — one target
node src/main.js -t TLm2haFEW9NXHKqyNgu2sHzggH88oAiryp -w 16

# Hunt mode — multiple targets from file
node src/main.js --targets-file targets.txt -w 8

# Save every generated wallet to DB (slow)
node src/main.js --save-all -w 4
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-w, --workers <n>` | Worker threads | CPU count |
| `-t, --target <addr>` | TRON target (repeatable) | — |
| `--targets-file <path>` | One address per line | — |
| `--save-all` | Save all wallets to DB | off |
| `-h, --help` | Show help | — |

---

## Performance estimates

| Setup | Speed | vs v4 |
|---|---|---|
| v4 (8 cores) | ~1–2 M/s | 1× |
| **v5 Phase-0 (8 cores)** | **~1.5–3 M/s** | **~1.5×** |
| Phase-1 (native keccak) | ~3–5 M/s | ~2.5× |
| Phase-2 CUDA (RTX 3050 Ti) | ~100–200 M/s | ~100× |

---

## Roadmap

- **Phase 0 (done):** native sha256, hunt-mode byte compare, BATCH=2048
- **Phase 1:** replace `@noble/hashes` keccak with native C binding
- **Phase 2:** CUDA kernel — xoshiro++ → secp256k1 → keccak → byte compare, all on GPU

---

## Notes

- Generated wallets have **no mnemonic** — raw random private keys only.
- These cover a different address space than BIP39/BIP44 wallets.
- `wallet-hunter.db` stores results (SQLite, WAL mode).
