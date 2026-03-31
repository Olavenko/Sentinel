# Session 05 — DX9 RE Address Mapping
**Date:** 2026-03-29
**Binary:** Conquer_DX9 (Env_DX9\Conquer.exe)
**Tool:** Ghidra + GhidraMCP

---

## Step 0 — Binary Verification

Confirmed DX9 binary. Segments:

| Segment  | Range                     | Notes                                  |
|----------|---------------------------|----------------------------------------|
| .text    | 0x00401000 – 0x014b9bff   | Main code (~10.5 MB)                   |
| .rdata   | 0x014ba000 – 0x019923ff   | Read-only data (strings, vtables)      |
| .data    | 0x01993000 – 0x01a27ac7   | Mutable data                           |
| **.vlizer** | **0x01b3d000 – 0x01ef2fff** | **Code virtualization layer (VMProtect-style)** |

**Critical finding:** The `.vlizer` segment is present. Several key functions are **fully virtualized** — their `.text` stub does nothing but jump into the virtualization VM. Ghidra cannot statically decompile these functions.

---

## Step 1 — String Search Results

| String                                          | Address      | Notes                                            |
|-------------------------------------------------|--------------|--------------------------------------------------|
| `"GameServerIP:%s port:%d"`                     | 0x016de488   | No DATA xrefs found (possibly accessed indirectly) |
| `"BF_cfb64_encrypt"`                            | *(not found)*| String not present — OpenSSL statically inlined  |
| `"blowfish"`                                    | 0x01726c60   | EVP alias registration: maps "blowfish" → BF-CBC |
| `"CMyClientSocket::DoReceive CheckMsg Failed"`  | 0x016dc1e8   | Xref → FUN_00fee7cd (DoReceive)                  |
| `"DoReceiveShakeHand recv return 0"`            | 0x016dc244   | Xref → FUN_00feeb6c                              |
| `"DoReceiveShakeHand recv return -1"`           | 0x016dc268   | Xref → FUN_00feeb6c                              |
| `"DoReceive1 recv return 0 break"`              | 0x016dc168   | Xref → FUN_00fee7cd                              |
| `"DoReceive2 recv return 0 break"`              | 0x016dc1a8   | Xref → FUN_00fee7cd                              |
| `"CMyNetwork::FuncRecvSend DoReceive %d"`       | 0x016bbca4   | Referenced at 0x00e42f7e (DATA ref)              |
| `"CMyNetwork::FuncRecvSend SS_SHAKEHAND Failed"`| 0x016bbccc   | Same function area                               |
| `"crypto\bio\bf_buff.c"`                        | 0x0174a020   | OpenSSL Blowfish BIO buffer — confirms static OpenSSL |

---

## Findings — Address Table

| Address    | Function Name (Ghidra) | Purpose                                     | Virtualized? |
|------------|------------------------|---------------------------------------------|-------------|
| 0x012410f0 | FUN_012410f0           | **BF_cfb64_encrypt** (OpenSSL core)         | No          |
| 0x0124a5d0 | FUN_0124a5d0           | **BF_encrypt** (OpenSSL core)               | No          |
| 0x01170dce | FUN_01170dce           | **BF CFB64 decrypt wrapper** (`encrypt=0`)  | No          |
| 0x01172de1 | FUN_01172de1           | **BF CFB64 encrypt wrapper** (`encrypt=1`)  | No          |
| 0x00fee7cd | FUN_00fee7cd           | **CMyClientSocket::DoReceive**              | No          |
| 0x00feeb6c | FUN_00feeb6c           | **DoReceiveShakeHand**                      | No          |
| 0x00feed21 | FUN_00feed21           | **DoSendMsg** (sends with encryption)       | No          |
| 0x01187e21 | FUN_01187e21           | **Handshake parser** (parses server reply)  | **YES**     |
| 0x0117317a | FUN_0117317a           | **Build handshake reply** (to server)       | **YES**     |
| 0x00fef18a | FUN_00fef18a           | **Custom CO XOR cipher** (pre-BF mode)      | No          |
| 0x01269f40 | FUN_01269f40           | OpenSSL EVP cipher table registration       | No          |
| 0x01249c60 | FUN_01249c60           | Unknown BF function (calls BF_encrypt directly) | No      |

---

## Function Details

### BF_cfb64_encrypt — 0x012410f0
Decompilation confirmed standard OpenSSL CFB-64 logic:
- Processes input in 8-byte blocks (64-bit Blowfish block size)
- Calls `FUN_0124a5d0` (BF_encrypt) when the 8-byte IV buffer is exhausted
- Two modes: `encrypt=1` (feedback from plaintext) / `encrypt=0` (feedback from ciphertext)
- Called by two wrappers: decrypt at `0x01170dce`, encrypt at `0x01172de1`

### BF CFB64 Decrypt Wrapper — 0x01170dce
```c
FUN_012410f0(param_2, param_3, param_4,
             param_1 + 0x10,       // BF_KEY
             (int)param_1 + 0xd,   // IV buffer
             param_1 + 1,          // num (CFB position)
             0);                   // encrypt=0 (DECRYPT)
```

### BF CFB64 Encrypt Wrapper — 0x01172de1
```c
FUN_012410f0(param_2, param_3, param_4,
             param_1 + 0x10,       // BF_KEY
             (int)param_1 + 0x15,  // IV buffer (different offset — TX vs RX)
             param_1 + 2,          // num (CFB position)
             1);                   // encrypt=1 (ENCRYPT)
```

### CMyClientSocket::DoReceive — 0x00fee7cd
Three connection modes, selected by `param_1[0x702]`:
- **Mode 1 (unencrypted):** raw forward
- **Mode 2 (Blowfish):** decrypt via `FUN_01170dce`, verify MAC via `FUN_0117849f`
- **Mode 3 (pre-Blowfish):** forward without decryption
- On `*(param_1+0x1c0e) != 0` → delegates to `DoReceiveShakeHand`

### DoReceiveShakeHand — 0x00feeb6c
1. Calls `recv()` into 2 KB stack buffer
2. Passes received data to `FUN_01187e21` (**VIRTUALIZED** — cannot decompile)
3. Calls `FUN_0117317a` to build reply (**VIRTUALIZED**)
4. Wraps reply in message type `0x404` and queues it

### DoSendMsg — 0x00feed21
Mirror of DoReceive for outbound data:
- Mode 1/3: uses custom CO XOR cipher (`FUN_00fef18a`)
- Mode 2: uses BF CFB64 encrypt wrapper (`FUN_01172de1`) then appends MAC

### Custom CO XOR Cipher — 0x00fef18a
Used during initial connection (before Blowfish key is established). Algorithm:
```
for each byte b at offset i:
    b ^= key1_table[key1_idx + 8]
    b ^= key2_table[key2_idx + 0x108]
    advance key1_idx (wraps at 0xFF), advance key2_idx
    b = rotl4(b) ^ 0xAB          // bit-rotate nibbles and XOR
```
This matches the known CO 5xxx protocol cipher from gProxy.

### Virtualized Functions (WARNING)
Both critical handshake functions dispatch into `.vlizer`:

| Address    | Purpose                  | VM entry point |
|------------|--------------------------|----------------|
| 0x01187e21 | Handshake parser         | 0x01e5e6e7     |
| 0x0117317a | Build handshake reply    | 0x01e50d56     |

These **cannot be statically decompiled** by Ghidra. Dynamic analysis (x32dbg + network capture) is required to understand the DH key exchange flow.

---

## Cross-References

### BF_cfb64_encrypt (0x012410f0) callers:
| Caller address | Function         | Mode         |
|----------------|-----------------|--------------|
| 0x01170e05     | FUN_01170dce    | Decrypt (0)  |
| 0x01172e1a     | FUN_01172de1    | Encrypt (1)  |

### BF_encrypt (0x0124a5d0) callers:
| Caller address | Function         | Purpose                      |
|----------------|-----------------|------------------------------|
| 0x01241188     | FUN_012410f0    | Within BF_cfb64_encrypt      |
| 0x0124126a     | FUN_012410f0    | Within BF_cfb64_encrypt      |
| 0x01249d59     | FUN_01249c60    | Unknown BF mode (ECB/CBC?)   |
| 0x01249e37     | FUN_01249c60    | Unknown BF mode              |
| 0x012b14a2     | FUN_012b13a0    | Unknown BF usage             |
| 0x012b1345     | FUN_012b12e0    | Unknown BF usage             |

### DoReceive (0x00fee7cd) callers:
| Caller address | Notes                               |
|----------------|-------------------------------------|
| 0x00e42ec6     | Likely CMyNetwork::FuncRecvSend     |

### DoReceiveShakeHand (0x00feeb6c) callers:
| Caller address | Notes                               |
|----------------|-------------------------------------|
| 0x00fee808     | Within FUN_00fee7cd (DoReceive)     |

---

## Comparison with DX8

| DX8 Address  | Function                     | DX9 Address  | Delta       | Notes                               |
|-------------|------------------------------|--------------|-------------|-------------------------------------|
| 0x01170264  | BF CFB64 decrypt wrapper     | 0x01170dce   | +0x0B6A     | Confirmed match                     |
| 0x0124a740  | BF_encrypt (OpenSSL)         | 0x0124a5d0   | -0x0170     | Confirmed match                     |
| 0x0124a320  | BF_decrypt (OpenSSL)         | *not found*  | —           | May be inlined or absent in DX9     |
| 0x01240de0  | BF_cfb64_encrypt (OpenSSL)   | 0x012410f0   | +0x0310     | Confirmed match                     |
| 0x00fee3a1  | DoReceiveShakeHand           | 0x00feeb6c   | +0x07CB     | Confirmed match                     |
| 0x01172610  | Build handshake reply        | 0x0117317a   | +0x016A     | **VIRTUALIZED in DX9**              |
| 0x00fee002  | CMyClientSocket::DoReceive   | 0x00fee7cd   | +0x07CB     | Confirmed match                     |
| 0x00fede9d  | Game Server connect          | *not found*  | —           | Estimated ~0x00fee668 (same +0x07CB delta) |

**Key DX8 → DX9 change:** The two most sensitive handshake functions (`FUN_0117317a`, `FUN_01187e21`) have been moved into the VMProtect virtualization layer. This means the DH key exchange and handshake reply logic **cannot be statically reversed** — this is likely an anti-cheat/anti-bot measure added in 7xxx era servers.

---

## Next Steps

1. **Dynamic analysis required for handshake functions.** Set breakpoints at:
   - `0x00feeb6c` (DoReceiveShakeHand entry) — observe recv'd server data
   - `0x01187e21` (virtualized handshake parser) — dump input/output
   - `0x0117317a` (virtualized reply builder) — dump output buffer
   - `0x00feeb6c + offset to FUN_0041d9cc call` — capture the 0x404 message being queued

2. **Capture live DH handshake.** Run Sentinel transparent proxy against target server to capture raw bytes of the handshake exchange (Type 0x404 packets). Compare structure against gProxy `Handshake.h` / `HandshakeReply.h`.

3. **Test the known DH parameters.** From gProxy: known Blowfish key `"DR654dt34trg4UI6"` and known DH parameters. Implement `BlowfishCfb64Cipher` and `DiffieHellman` in `Sentinel.Crypto` using `FUN_012410f0` as the confirmed algorithm reference.

4. **Identify `FUN_01249c60`.** This function calls `BF_encrypt` directly (not via CFB64). It may be BF_ecb_encrypt, BF_cbc_encrypt, or BF key setup — worth examining to understand if CO uses multiple BF modes.

5. **Find Game Server connect function.** Estimate: `~0x00fee668` (applying `+0x07CB` delta from DX8's `0x00fede9d`). Confirm by searching for xrefs to the `"GameServerIP:%s port:%d"` string (0x016de488).

6. **Implement `ICipher` and `IKeyExchange`.** With the confirmed algorithm (BF-CFB64), implement:
   - `Sentinel.Crypto/BlowfishCfb64Cipher.cs` — wraps `BouncyCastle` BF-CFB
   - `Sentinel.Crypto/DiffieHellman.cs` — from gProxy parameters, test against live capture
