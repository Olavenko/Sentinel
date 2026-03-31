# Session 07 — S-Box Investigation Framework & Nuclear Chain-Table Cipher
**Date:** 2026-03-30
**Goal:** Investigate S-box layouts for CO 7xxx modified Blowfish; implement nuclear fallback that decrypts handshake traffic without S-box knowledge

---

## Context

Session 06 confirmed:
- The handshake cipher uses P-array `FridaP[0..15]` injected directly from Frida memory
- Zero S-boxes produce `BF_encrypt(0,0) = c1 97 e1 12 f4 b5 e8 21` — wrong
- Actual game output is `bc 8a 80 e5 bf b0 14 1d` (consistent 8-byte delta `7d 1d 61 f7 4b 05 fc 3c`)
- Two S-box-like memory regions were identified: ECX+0x0CC (512 bytes) and ECX+0x2D4 (489 bytes)
- 512 BF_encrypt chain pairs were captured (starting from IV=zeros), confirming the real BF_encrypt output

This session implements a two-track approach:
1. **S-box hypothesis framework** — tests multiple interpretations of the SBOX memory regions once the full dump is provided
2. **Nuclear chain-table cipher** — bypasses S-box discovery entirely using the known BF_encrypt pairs

---

## Work Completed

### 1. `BlowfishCfb64Cipher` — S-box support added

Two additions to `src/Sentinel.Crypto/BlowfishCfb64Cipher.cs`:

#### `SetRawState` method (new)

```csharp
public void SetRawState(
    ReadOnlySpan<uint> p14,
    ReadOnlySpan<uint> s0, ReadOnlySpan<uint> s1,
    ReadOnlySpan<uint> s2, ReadOnlySpan<uint> s3)
```

- Accepts the full cipher state: 16 P-array entries + four S-box arrays
- S-boxes may be any power-of-2 length (32, 64, 128, 256, …); mask is derived automatically
- All four S-boxes must be the same length
- Replaces the zero-S-box path when real S-box data is available

#### `EncryptIvBlock` raw mode — updated

```csharp
// Full path (S-boxes present):
var mask = (uint)(s0.Length - 1);
for (var i = 1; i <= 13; i += 2)
{
    xr ^= BfF(xl, s0, s1, s2, s3, mask) ^ _rawP[i];
    xl ^= BfF(xr, s0, s1, s2, s3, mask) ^ _rawP[i + 1];
}

// Zero-S-box fallback (F=0):
for (var i = 1; i <= 13; i += 2)
{
    xr ^= _rawP[i];
    xl ^= _rawP[i + 1];
}
```

The F-function uses a bitmask for S-box indexing, supporting any power-of-2 S-box size:

```csharp
private static uint BfF(uint x, uint[] s0, uint[] s1, uint[] s2, uint[] s3, uint mask) =>
    ((s0[(x >> 24) & mask] + s1[(x >> 16) & mask]) ^ s2[(x >> 8) & mask]) + s3[x & mask];
```

`SetRawKeySchedule` behaviour is unchanged — it still resets the S-box fields to null (zero-S-box mode).

---

### 2. `BlowfishSboxInvestigationTests.cs` — new test file

#### Nuclear chain-table tests (4 tests — all PASS)

`ChainTableCfb64Cipher` (in the test file) is a self-contained CFB64 cipher that replaces the BF_encrypt computation with a `Dictionary<ulong, ulong>` lookup. Identical state machine to OpenSSL `BF_cfb64_encrypt`. If an IV is not in the table it throws with the missing key's hex value, indicating exactly which Frida pair to capture next.

The table is pre-populated from two sources:

| Input (IV) | Output (keystream) | Source |
|---|---|---|
| `0000000000000000` | `bc8a80e5bfb0141d` | Frida chain capture |
| `bc8a80e5bfb0141d` | `694d6035a12e9daf` | Frida chain capture |
| `694d6035a12e9daf` | `ec3699e9846441a2` | Frida chain capture |
| `ec3699e9846441a2` | `6acf349c4aa71eac` | Frida chain capture |
| `db09701df591fa9b` | `38ef9f8691d4c8f4` | Derived from Capture #1 (decrypt) |
| `4c667e70cca6b2aa` | `96cbb7d3e9067970` | Derived from Capture #3 (encrypt) |

Derivations:
- **Capture #1 decrypt:** IV after block 0 = first 8 ciphertext bytes (`db09701df591fa9b`). Keystream[8..15] = plaintext[8..14] XOR ciphertext[8..14] + ivec[7] probe = `38ef9f8691d4c8f4`.
- **Capture #3 encrypt:** IV after block 0 = first 8 ciphertext bytes (`4c667e70cca6b2aa`). Keystream[8..15] = ciphertext[8..15] XOR plaintext[8..15] = `96cbb7d3e9067970`.

Nuclear tests:

| Test | Result |
|------|--------|
| `BfEncryptTable_ZeroIv_EntryIsCorrect` | **PASS** |
| `BfEncryptTable_ChainIsConsistent` | **PASS** |
| `ChainTable_Decrypt_Capture1_OutputMatches` | **PASS** |
| `ChainTable_Decrypt_Capture1_IVAfterMatches` | **PASS** |
| `ChainTable_Encrypt_Capture3_OutputMatches` | **PASS** |
| `ChainTable_EncryptThenDecrypt_Roundtrip` | **PASS** |

#### S-box hypothesis tests (6 tests — SKIP pending Frida dump)

Five layout hypotheses ready to activate once the full SBOX region dump is pasted into `SboxA_Raw` / `SboxB_Raw`:

| Hypothesis | Layout | Index bits |
|------------|--------|-----------|
| A  | 4×32 from SBOX_A, big-endian uint32 | 5-bit (mask=31) |
| A2 | 4×32 from SBOX_A, little-endian uint32 (x86 native) | 5-bit (mask=31) |
| B  | 4×64: S0/S1 from SBOX_A, S2/S3 from SBOX_B | 6-bit (mask=63) |
| C  | Single 128-entry table, shared by all four S-box slots | 7-bit (mask=127) |
| D  | 4×32 interleaved: S0[0],S1[0],S2[0],S3[0],S0[1],… from SBOX_A | 5-bit (mask=31) |
| E  | 4×32 from SBOX_A tail (skip first 128 bytes — header/metadata hypothesis) | 5-bit (mask=31) |

Each hypothesis test calls `RunBfEncryptZeroIvTest` which:
1. Builds a `BlowfishCfb64Cipher` with the candidate S-boxes via `SetRawState`
2. Encrypts 8 zero bytes with IV=zeros (plaintext=0 → output = BF_encrypt(0,0) verbatim)
3. Asserts output equals `bc 8a 80 e5 bf b0 14 1d`
4. Prints actual/expected/XOR delta on failure

To activate: paste full 512-byte dump of ECX+0x0CC into `SboxA_Raw` and 489-byte dump of ECX+0x2D4 into `SboxB_Raw`, then remove the `Skip` attributes.

---

## Test Results — Full Suite

```
Failed:  8   (pre-existing — all zero-S-box known-answer failures, gate test)
Passed: 12   (cipher correctness, roundtrip, streaming, 6 new nuclear tests)
Skipped: 6   (S-box hypothesis tests — pending full Frida dump)
Total:  26
```

All 8 failures are unchanged from session 06. No regressions introduced.

---

## Files Modified

| File | Change |
|------|--------|
| `src/Sentinel.Crypto/BlowfishCfb64Cipher.cs` | Added `SetRawState`, `BfF`, updated `EncryptIvBlock` raw path, cleared S-box fields in `Dispose` |
| `tests/Sentinel.Crypto.Tests/BlowfishSboxInvestigationTests.cs` | **New** — nuclear chain-table cipher + 6 S-box hypothesis tests |

---

## Architectural Note — `ChainTableCfb64Cipher` vs `BlowfishCfb64Cipher`

`ChainTableCfb64Cipher` lives in the test project intentionally. It is a temporary research tool — not a production cipher. Once the real S-boxes are confirmed (hypothesis tests pass), `BlowfishCfb64Cipher.SetRawState` with the real S-box values becomes the canonical path and the chain-table cipher is no longer needed.

For live MITM before S-boxes are confirmed: the chain table can be extended to cover any sequence of IVs the handshake produces. Each Frida `BF_cfb64_encrypt` hook call adds one entry.

---

## Status

| Step | Status |
|------|--------|
| Gate test: P[0] validation (key `R3Xx97ra5i8D6uZz`) | DONE — **GATE FAILS** (CO uses modified BF) |
| Cipher correctness tests | DONE — PASS |
| Known-answer tests (Capture #1, #3) | DONE — **FAIL** (zero S-boxes wrong) |
| Nuclear chain-table cipher | **DONE — all 4 known captures PASS** |
| `BlowfishCfb64Cipher.SetRawState` with real S-boxes | DONE — implemented, awaiting S-box data |
| S-box hypothesis tests A–E | DONE — **SKIP** (paste Frida dump to activate) |
| Bug 1 fix (handshake direction) | NOT STARTED — blocked |
| Bug 2 fix (static game key) | NOT STARTED — blocked |
| Step 5 (plaintext logging) | NOT STARTED — blocked |

---

## Next Required Step: Provide Full S-Box Dump

Run the Frida SBOX capture script against Conquer.exe and paste output into `BlowfishSboxInvestigationTests.cs`:

```javascript
// Frida script — dump S-box regions from BF cipher object
// After hooking BF_cfb64_encrypt, ECX = cipher object pointer
var sboxA = ptr(ecx).add(0xCC).readByteArray(512);   // → SboxA_Raw
var sboxB = ptr(ecx).add(0x2D4).readByteArray(489);  // → SboxB_Raw
console.log(hexdump(sboxA)); console.log(hexdump(sboxB));
```

Known first bytes from prior session:
- `SboxA_Raw` (`ECX+0x0CC`): `f6 d0 ec 86 ba cc 88 fa 4e 68 84 8e f2 24 e0 22 …`
- `SboxB_Raw` (`ECX+0x2D4`): `9d 90 83 8a d1 8c e7 f6 25 28 eb 82 99 64 8f 2e …`

Once the full dumps are pasted, run:

```
dotnet test --filter "SboxHypothesis"
```

If any hypothesis passes, `BF_encrypt(0,0)` will match and the S-boxes are confirmed. Then update `BlowfishCfb64Cipher` with the real S-box values — all known-answer tests will pass and live MITM decryption of the handshake becomes possible.
