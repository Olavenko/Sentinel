# Session 04 Report — 2026-03-29

## Summary

This session performed deep reverse engineering of the 7xxx game client binary via Ghidra MCP to understand the actual crypto protocol. The DH MITM implemented in session 03 caused a deadlock because the 7xxx protocol is fundamentally different from the 5xxx gProxy reference: the **client sends first**, not the server. The session mapped out the complete network architecture, identified two distinct cipher systems (TQ XOR for login, Blowfish CFB64 for game server), and traced the CMsgEncryptCode key derivation algorithm. Critical crypto initialization functions remain behind Themida virtualization.

---

## 1. Problem Statement

After enabling DH MITM on the GameServer endpoint, the proxy deadlocked. `PerformHandshakeAsync` in `ProxySession.cs:141` called `ReadHandshakeDataAsync(serverStream, ct)` first, waiting for a server-initiated DH handshake that never arrives in the 7xxx protocol. The client sends a 276-byte plaintext transfer token first (type `0x0A02`), and the server responds after validation.

**Root cause:** The 5xxx gProxy protocol (server sends DH handshake first) does not match the 7xxx protocol (client sends first).

**Fix applied:** Set `EnableMitm: false` on GameServer endpoint in `appsettings.json` to restore transparent forwarding.

---

## 2. Protocol Flow Discovery

### 2.1 Login Server Flow

```
Client ──connect──▶ Login Server
Client ◀──CMsgEncryptCode(seed)── Server    // Server sends first
Client: key = srand(seed) + 16x rand()      // MSVC LCG derivation
Client ──CMsgConnect(encrypted)──▶ Server
Client ◀──CMsgConnectEx(encrypted)── Server  // Contains game server IP/port
```

### 2.2 Game Server Flow

```
Client ──connect──▶ Game Server
Client ──TransferToken(276B, type 0x0A02, PLAINTEXT)──▶ Server
Client ◀──ServerResponse(331-363B, ENCRYPTED)── Server
... bidirectional encrypted traffic ...
```

### 2.3 Key Difference from 5xxx

| Aspect | 5xxx (gProxy) | 7xxx (this server) |
|--------|--------------|-------------------|
| Who sends first | Server (DH handshake) | Client (transfer token) |
| Key exchange | Diffie-Hellman | CMsgEncryptCode seed |
| Login cipher | Blowfish CFB64 | TQ XOR cipher (type 1/3) |
| Game cipher | Blowfish CFB64 | Blowfish CFB64 (type 2) |
| Default key | `"DR654dt34trg4UI6"` | **Unknown** (not in binary) |

---

## 3. Ghidra RE Findings

### 3.1 CMsgEncryptCode Handler — `FUN_010910a6`

The login server's key derivation is fully decompiled and understood:

```c
// FUN_010910a6 — CMsgEncryptCode handler
srand(*(uint*)(msg_buffer + 4));           // Seed from server packet
for (int i = 0; i < 16; i++) {
    DAT_019871e8[i] = (char)rand();        // MSVC LCG: state = state * 214013 + 2531011
}
FUN_004397de(seed);                        // Get game singleton
FUN_0110c868(seed);                        // Store seed at singleton + 0x5338
```

- **Key buffer:** `DAT_019871e8` (16 bytes)
- **Only one WRITE xref** to this buffer — read access is via computed addresses or virtualized code
- **String ref:** `"Login Receive 1 : CMsgEncryptCode"` at `0x016e6fac`
- **RTTI:** `.?AVCMsgEncryptCode@@` at `0x019e791c`

### 3.2 Network Architecture — CMyClientSocket

Decompiled from `FUN_00fee002` (`myclientsocket.cpp`), the receive function uses a **connection type** field at `this[0x702]` to select the cipher:

| Type | Cipher | Used For | Decrypt Function |
|------|--------|----------|-----------------|
| 1 | TQ XOR cipher | Login (and type 3) | `FUN_00fee9bf` |
| 2 | Blowfish CFB64 | Game Server | `FUN_01170264` |
| 3 | TQ XOR cipher | Variant of type 1 | `FUN_00fee9bf` |

### 3.3 TQ XOR Cipher — `FUN_00fee9bf`

Simple proprietary cipher for login connections (types 1/3):

```c
for (int i = 0; i < length; i++) {
    data[i] ^= key_table_1[counter1 + 8];     // 256-byte key table
    data[i] ^= key_table_2[counter2 + 0x108];  // 256-byte key table
    counter1++;
    if (counter1 > 0xFF) {
        counter1 = 0;
        counter2++;
        if (counter2 > 0xFF) counter2 = 0;
    }
    data[i] = ((data[i] << 4) | (data[i] >> 4)) ^ 0xAB;  // nibble swap + XOR
}
```

### 3.4 Blowfish CFB64 Decrypt Wrapper — `FUN_01170264`

Wrapper for game server (type 2) connections. Calls `FUN_01240de0` (BF_cfb64_encrypt):

```c
// Cipher object layout:
// +0x00: [4B] flag/pointer (must be non-zero)
// +0x04: [4B] num (CFB64 position counter)
// +0x0C: [1B] initialized flag
// +0x0D: [8B] IV (initialization vector)
// +0x40: [4168B] BF_KEY schedule (18 P-array + 4x256 S-box entries)
```

### 3.5 Confirmed OpenSSL BF Functions

| Address | Function | Confirmed By |
|---------|----------|-------------|
| `0x0124a740` | `BF_encrypt` | Called from BF_cfb64, BF_cbc, BF_ecb, and key schedule |
| `0x0124a320` | `BF_decrypt` | Called from BF_cbc and BF_ecb decrypt paths |
| `0x01240de0` | `BF_cfb64_encrypt` | Matches OpenSSL CFB64 exactly — encrypt + decrypt modes |
| `0x01249dd0` | `BF_cbc_encrypt` | CBC mode, uses BF_encrypt/BF_decrypt |
| `0x012b0fd0` | `BF_ecb_encrypt` | Single block ECB mode |
| `0x012b1090` | BF OFB/CFB variant | Another streaming mode implementation |

### 3.6 CCipher Class (RTTI-traced)

| Component | Address |
|-----------|---------|
| RTTI type_info | `0x019eb5f4` (`.?AVCCipher@@`) |
| Vtable | `0x01703390` |
| Constructor 1 | `FUN_011f17ad` |
| Constructor 2 | `FUN_011f1820` |
| Init function | `FUN_01e43ae0` → **Themida virtualized** |

Constructor callers (all exception unwind handlers):

- `0x01355907`, `0x014814a4`, `0x01483cd4` — destructors in catch blocks
- No direct construction call sites visible — construction is inlined or virtualized

### 3.7 Game Server Connection Path

```
FUN_00fede9d — "GameServerIP:%s port:%d"
  └─▶ FUN_00e4bcee(type=2, ip, port, 0xf) — connection setup
       └─▶ FUN_00f88081(LAB_00e4290b, this) — spawns connection thread
            └─▶ _beginthreadex(LAB_00e4290b, ...) — thread start
```

### 3.8 DoReceiveShakeHand — `FUN_00fee3a1`

Handles the handshake phase of a new connection:

```
1. recv() up to 0x800 bytes (server's handshake data)
2. FUN_011872b7(data, length)  → VIRTUALIZED (Themida)
   └─▶ FUN_01e2890d → FUN_01c80fba  (obfuscated with LOCK/UNLOCK)
3. FUN_01172610(reply_buf, 0x800)  → VIRTUALIZED (Themida)
   └─▶ FUN_01e20c31 → FUN_01c70fba  (obfuscated with LOCK/UNLOCK)
4. Build reply message and enqueue for sending
5. Clear shakehand flag at this + 0x1c0e
```

### 3.9 Checksum Discovery

In type 2 DoReceive, after decrypting the packet body:

- **`FUN_00815380()`** returns `8` — the checksum is 8 bytes appended to each packet
- **`FUN_01177935()`** returns `"TQServer"` — the expected checksum value

So type 2 packets have format: `[2B size][payload][8B "TQServer" checksum]`

### 3.10 Source Path & File References

From exception strings:

- `e:\cqclient\gzsu2kc5\0\cqclient\cqclient\3drole\network\msgconnect.cpp`
- `e:\cqclient\gzsu2kc5\0\cqclient\cqclient\3drole\core\myclientsocket.cpp`
- `e:\cqclient\gzsu2kc5\0\cqclient\cqclient\3drole\core\mynetwork.cpp`

---

## 4. Themida Virtualization Barrier

The following critical functions are protected by Themida code virtualization (LOCK/UNLOCK anti-analysis patterns), preventing static decompilation:

| Function | Purpose | Calls |
|----------|---------|-------|
| `FUN_01e2890d` | Process received handshake | `FUN_01c80fba` |
| `FUN_01e20c31` | Build handshake reply | `FUN_01c70fba` |
| `FUN_01e43ae0` | CCipher initialization | `FUN_01c70fba` |
| `FUN_01e2f1ea` | CCipher vtable method | `FUN_01c82fba` |

All of these ultimately call `FUN_01c7xxxx` functions which contain:

- Heavy LOCK/UNLOCK instruction sequences
- Anti-analysis jump tables
- Global state manipulation via `DAT_01b7cf04`
- Relocation of function pointer tables (0x369 = 873 entries)

**These functions contain the key derivation and cipher initialization logic that we cannot extract statically.**

---

## 5. Key Findings Summary

### Confirmed

1. 7xxx protocol is **client-sends-first** (not server-sends-first like 5xxx)
2. Game server Pkt#1 (C→S, 276B, type `0x0A02`) is **plaintext** transfer token
3. CMsgEncryptCode key derivation: `srand(seed)` + 16x `(char)rand()` using MSVC LCG
4. Login uses **TQ XOR cipher** (connection type 1/3), game uses **Blowfish CFB64** (type 2)
5. Type 2 packets have an **8-byte `"TQServer"` checksum** appended after payload
6. `"DR654dt34trg4UI6"` is **NOT in the 7xxx binary** as a string
7. OpenSSL Blowfish is statically linked (BF_encrypt at `0x0124a740`)

### Unsolved — Critical Blocker

- **The initial Blowfish key for game server connections is unknown**
- The key setup code is behind Themida virtualization
- All 12+ candidate keys tested empirically failed to decrypt game server Pkt#2
- The CCipher constructors and init functions are virtualized

---

## 6. Failed Key Candidates

| Key | Source | Result |
|-----|--------|--------|
| `"DR654dt34trg4UI6"` | gProxy default | No decrypt |
| `"TQServer"` | Checksum string | No decrypt |
| `"gzsu2kc5"` | Source path component | No decrypt |
| All-zeros (16B) | Common default | No decrypt |
| srand/rand from login seed | CMsgEncryptCode derivation | No decrypt |
| 30 dynamic 4-byte offsets from GameServer Pkt#1 as seeds | Brute force | No decrypt |

---

## 7. Recommended Next Steps

### Option A: Dynamic Analysis (Recommended)

Since static analysis is blocked by Themida, use dynamic analysis:

1. **x64dbg/x32dbg** — Set breakpoint on `BF_set_key` equivalent or on `FUN_0124a740` (BF_encrypt). The first call after game server connect will be key schedule init. Read the key from the stack/registers.
2. **Frida hook** — Hook `FUN_01170264` (BF decrypt wrapper) and dump the cipher object at offset +0x0D (IV) and +0x40 (key schedule) after the first successful decrypt.
3. **API Monitor** — Hook `recv`/`send` on the game server socket to capture plaintext before encryption.

### Option B: Passive Proxy Without Decryption

Implement the corrected protocol flow (client-sends-first) in `ProxySession.cs` without attempting to decrypt. This restores proxy functionality and allows traffic capture for offline analysis:

1. Forward client's transfer token to server (transparent)
2. Forward server response to client (transparent)
3. Forward all subsequent traffic (transparent, log ciphertext)

### Option C: Known-Plaintext Attack

If the `"TQServer"` checksum (8 bytes) is always at a predictable offset, and the CFB64 cipher is reset per-packet, we could derive key material from known plaintext. However, CFB64 is a streaming cipher (not reset per-packet), making this approach unreliable.

---

## 8. Files Modified This Session

| File | Change |
|------|--------|
| `src/Sentinel.CLI/appsettings.json` | `EnableMitm: false` on GameServer (fix deadlock) |

No code was written this session — the focus was entirely on reverse engineering.

---

## 9. Address Reference Table

Quick reference for future Ghidra sessions:

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x010910a6` | CMsgEncryptCode handler | Key derivation — fully decompiled |
| `0x019871e8` | Key buffer (16B) | Written by CMsgEncryptCode handler |
| `0x00fee002` | CMyClientSocket::DoReceive | Main receive loop with cipher dispatch |
| `0x00fee3a1` | DoReceiveShakeHand | Handshake receiver |
| `0x00fee9bf` | TQ XOR cipher | Login encryption (types 1/3) |
| `0x01170264` | BF CFB64 decrypt wrapper | Game server decryption (type 2) |
| `0x01240de0` | BF_cfb64_encrypt | OpenSSL Blowfish CFB64 |
| `0x0124a740` | BF_encrypt | OpenSSL Blowfish core encrypt |
| `0x0124a320` | BF_decrypt | OpenSSL Blowfish core decrypt |
| `0x011872b7` | Process handshake | Virtualized (Themida) |
| `0x01172610` | Build handshake reply | Virtualized (Themida) |
| `0x011f17ad` | CCipher constructor 1 | Virtualized init |
| `0x011f1820` | CCipher constructor 2 | Virtualized init |
| `0x01703390` | CCipher vtable | RTTI at `0x019eb5f4` |
| `0x00fede9d` | Game server connect | Logs "GameServerIP:%s port:%d" |
| `0x00e4bcee` | Connection setup | Spawns thread, type=2 for game |
| `0x00815380` | Checksum size | Returns 8 |
| `0x01177935` | Checksum value | Returns "TQServer" |
| `0x00f29b95` | CMsgConnectEx handler | Login response processing |
