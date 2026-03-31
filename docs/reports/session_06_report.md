# Session 06 — MITM Implementation: Gate Test Results
**Date:** 2026-03-29
**Goal:** Implement Phase 2 MITM decryption per approved plan

---

## Work Completed

### New test project: `tests/Sentinel.Crypto.Tests/`

Created `Sentinel.Crypto.Tests` (added to `Sentinel.slnx`). Four tests covering:

| Test | Result |
|------|--------|
| `HandshakeKey_DR654_ProducesExpectedP0` | **FAIL (gate)** |
| `StaticGameKey_EncryptDecrypt_Roundtrip` | PASS |
| `StaticGameKey_EncryptThenDecryptWithCiphertext_Roundtrip` | PASS |
| `StaticGameKey_StreamingChunks_MatchSinglePass` | PASS |

---

## Gate Test: FAILED — Wrong Initial Handshake Key

**Test:** Initialize BouncyCastle `BlowfishEngine` with `"DR654dt34trg4UI6"`, read P[0] after key schedule, assert it equals `0xdb298a75` (Frida-observed from Conquer.exe).

**Result:**

```
Key tested : "DR654dt34trg4UI6"
Actual P[0]: 0xa9e8435b
Expected   : 0xdb298a75
```

The key used in gProxy (5xxx era) does **not** match the CO 7xxx client's initial BF cipher.

**Implication:** `ProxySession.PerformHandshakeAsync` uses `"DR654dt34trg4UI6"` as the default key for the initial handshake cipher instances. This key is wrong — the server's handshake response will be decrypted incorrectly, making it impossible to extract `ClientIvec` and `ServerIvec`.

---

## Positive Findings

`BlowfishCfb64Cipher` itself is correct:
- Encrypt + decrypt roundtrip works for arbitrary data
- Streaming chunks (non-8-byte-aligned splits) produce identical output to single-pass encrypt
- The static game key `"x97ra5i8D6uZz"` is ready to use — no cipher code changes needed

---

## BouncyCastle Internal Layout (for reference)

Field dump from `BlowfishEngine` v2.6.2 after `Init` with `"DR654dt34trg4UI6"`:

| Field | Type | Length | [0] value |
|-------|------|--------|-----------|
| S0 | UInt32[] | 256 | 0x73122d5d |
| S1 | UInt32[] | 256 | 0xa0e7c3c9 |
| S2 | UInt32[] | 256 | 0x3a4b4298 |
| S3 | UInt32[] | 256 | 0xe01054c3 |
| **P** | **UInt32[]** | **18** | **0xa9e8435b** |
| KP (static, initial Pi) | UInt32[] | 18 | 0x243f6a88 |

Note: BouncyCastle 2.x uses `UInt32[]` (not `int[]`) for all BF arrays. The gate test reflection now correctly uses `uint[]`.

---

## Next Required Step: Find the Real Handshake Key

The handshake BF key is NOT `"DR654dt34trg4UI6"`. It must be found before proceeding.

### Option A — Ghidra static search (preferred first attempt)

Search Conquer.exe `.rdata` / `.data` for any ASCII string or byte sequence that — when run through the BF key schedule — produces P[0] = 0xdb298a75.

More practically: find `BF_set_key` in the binary (it's the key schedule entry, called once per cipher context initialization). Trace back from `DoReceiveShakeHand` to find what key is passed to it.

Known call graph:
```
DoReceiveShakeHand (0x00feeb6c)
  → calls recv()
  → calls FUN_01187e21 (VIRTUALIZED — handshake parser)
  → calls FUN_0117317a (VIRTUALIZED — handshake reply builder)
  → somewhere in this path: BF_set_key is called with the initial key
```

The BF `set_key` function is at an unknown address but its caller must be near the cipher initialization for the handshake context. Look for xrefs to `FUN_01249c60` (the "unknown BF function" from session 05 that calls `BF_encrypt` directly) — this may be the key schedule.

Alternatively, search `.data` / `.rdata` for the byte sequence that produces the known initial P-array entry. The key itself may be a printable ASCII string (like `"DR654dt34trg4UI6"` was in 5xxx).

### Option B — Frida dynamic capture (fallback, definitive)

Set a breakpoint at `BF_set_key` (find its address — it processes the key byte-by-byte into the P-array). The first call to it within `DoReceiveShakeHand`'s call chain will have the handshake key as the first argument.

Alternatively: after the game starts, dump the memory at the handshake cipher context struct. The `workingKey` field in `BlowfishEngine` stores the raw key bytes — the same field would exist in OpenSSL's `BF_KEY` struct.

### Option C — Brute / candidate list

Test known CO keys from community sources:
- `"DR654dt34trg4UI6"` (gProxy 5xxx) — **confirmed WRONG**
- `"x97ra5i8D6uZz"` (game traffic key) — different role, likely wrong for handshake
- `"TQServer"`, `"TQClient"` — protocol strings, unlikely as keys
- Any key visible in `.rdata` near the handshake function area

---

## Status

| Step | Status |
|------|--------|
| Create `Sentinel.Crypto.Tests` project | DONE |
| Gate test: P[0] validation | DONE — **GATE FAILS** |
| Cipher correctness tests | DONE — all 3 PASS |
| Bug 1 fix (handshake direction) | NOT STARTED — blocked |
| Bug 2 fix (static game key) | NOT STARTED — blocked |
| Step 5 (plaintext logging) | NOT STARTED — blocked |
| Step 6 (appsettings MITM flag) | NOT STARTED — blocked |

**Blocked on:** real initial handshake key for CO 7xxx.
