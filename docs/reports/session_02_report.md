# Session 02 Report — 2026-03-28

## Summary

This session focused on Phase 2 reverse engineering: setting up GhidraMCP, analysing the CO client binary, analysing a CO DLL, and performing statistical packet-capture analysis across four dedicated gameplay sessions. The session ended with a clear blocker and a decision to implement DH MITM in Phase 3 before continuing Phase 2 analysis.

---

## 1. GhidraMCP Setup

### What It Is

GhidraMCP is a bridge that exposes Ghidra's analysis capabilities as an MCP (Model Context Protocol) server. This allows Claude Code to call Ghidra tools directly — decompile functions, list imports/exports, rename symbols, search strings — without leaving the editor.

### How It Works

```
Claude Code (MCP client)
    │  JSON-RPC over stdio
    ▼
GhidraMCP MCP server process (Python)
    │  HTTP REST
    ▼
GhidraMCP Ghidra plugin (Java)
    │  Ghidra internal API
    ▼
Loaded binary (Conquer.exe, TqNDProtect.dll, …)
```

### Connection Details

| Component | Detail |
|-----------|--------|
| Ghidra plugin | Installed in Ghidra's `Extensions/` folder, auto-loaded on startup |
| Plugin HTTP port | `localhost:8080` (default) |
| MCP server | Python script that wraps the HTTP API as MCP tools |
| Claude connection | `.claude/settings.local.json` → `mcpServers.ghidra` entry pointing to the Python MCP server |

### Available Tools (used this session)

`list_imports`, `list_exports`, `list_functions`, `list_strings`, `list_segments`, `decompile_function`, `search_functions_by_name`, `list_classes`, `list_namespaces`, `get_function_xrefs`

---

## 2. Conquer.exe Analysis

### Key Finding: Code Virtualizer

The CO client binary is protected by **Code Virtualizer** (by Oreans). This is a code virtualisation obfuscator — it replaces native x86 instructions with a custom bytecode that runs inside a software VM embedded in the binary. It is **not** an encryption library; it is an anti-reverse-engineering tool applied to the client's most sensitive routines.

### Evidence

- `.vlizer` section present in the PE binary — the unmistakable signature of Code Virtualizer
- Ghidra decompilation of protected functions produces unreadable output (VM dispatch loops, not real logic)
- Strings such as `"Virtual Machine"` and Code Virtualizer marker bytes visible in the binary

### Impact on RE

| Region | Status |
|--------|--------|
| Unprotected functions (startup, config, UI) | Decompilable normally |
| Virtualised functions (crypto, network handshake, packet dispatch) | Decompilation blocked — output is the VM interpreter, not the original code |

The networking and encryption code is almost certainly inside the virtualised region. This is why Ghidra-only RE of the handshake is impractical without devirtualisation tooling (Oreans deprotector, manual VM analysis, or dynamic tracing).

---

## 3. TqNDProtect.dll Analysis

### What It Is

`TqNDProtect.dll` is the CO client's **anti-cheat DLL**, not an encryption or networking library.

### Evidence from Ghidra

| Finding | Detail |
|---------|--------|
| Exported functions | `NdProtect_Init`, `NdProtect_Check`, `NdProtect_Heartbeat`, `NdProtect_Report` |
| Import list | `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `OpenProcess`, `ReadProcessMemory` |
| Strings | References to cheat tool names, debug-flag detection strings, driver integrity checks |
| No cipher constants | No Blowfish S-box, no DH/BigNum imports, no `CryptAcquireContext` |

### Conclusion

TqNDProtect.dll performs process scanning (looking for known cheat processes), memory integrity checks, and heartbeat reporting back to the server. It is completely separate from the encryption/networking stack and is not relevant to Phase 3.

---

## 4. Packet Capture Analysis

### Capture Setup

Four dedicated game sessions were recorded after login, each focused on a single activity:

| Session | File size | Activity |
|---------|-----------|----------|
| `session_b3df7ba3...` | 31 798 B | Login + idle |
| `session_41e69b80...` | 37 240 B | Walk only |
| `session_b65aceaa...` | 78 146 B | Attack only |
| `session_9934b968...` | 28 350 B | Chat only |

Binary file format (per entry):
```
8 bytes  — Windows FILETIME timestamp (100 ns intervals since 1601-01-01)
1 byte   — direction: 0 = C→S, 1 = S→C
4 bytes  — payload length (little-endian uint32)
N bytes  — raw payload
```

---

### 4.1 Encryption: Blowfish CFB64

Confirmed from gProxy reference source (`GameCryptography.cpp`, `Blowfish.cpp`):

- Algorithm: **Blowfish** in **CFB64 mode** (`BF_cfb64_encrypt` from OpenSSL)
- Separate cipher state per direction (C→S and S→C run independent streams)
- Each stream is **continuous** — the cipher state carries across packet boundaries; you cannot decrypt packet N without having processed packets 0…N−1

Verification from captures: after the first plaintext C→S packet, **every** subsequent packet has `inner_len ≠ outer_len` (the decrypted length field doesn't match the outer container length), confirming active encryption. Trial decryption with the hardcoded key confirmed failure (all [BAD]).

---

### 4.2 Key Exchange: Diffie-Hellman (session-unique key)

Confirmed from gProxy reference source (`DiffieHellman.cpp`, `GameCryptography.cpp`):

- The **hardcoded key `"DR654dt34trg4UI6"`** is only the *initial* Blowfish key, used before the DH exchange completes.
- After the DH exchange, both sides call `CompleteDH()`, which replaces the key with the DH shared secret and sets per-direction IVs.
- The DH shared secret is **unique per session** — it depends on the ephemeral keypairs generated at connection time.
- Trial decryption with the hardcoded key across all four sessions failed completely, confirming the server uses DH and the key has already been replaced by the time our captures begin.

---

### 4.3 Handshake Packet Structure

The very first packet in every game server session is:

```
Direction : C→S
Size      : 276 bytes
Type      : 0x0A02 (2562 decimal)
Encryption: PLAINTEXT (inner_len == outer_len confirmed in all 4 sessions)
```

#### Byte Map

```
Offset   Size  Status    Notes
───────────────────────────────────────────────────────────────────
  0– 3      4  FIXED     CO header: sz=276 (0x0114), type=0x0A02
  4– 7      4  VARIABLE  Session token / random nonce (from auth server)
  8–11      4  FIXED     0x15 6d 5d e2 — server stamp / build identifier
 12–15      4  VARIABLE  Session-specific
 16–23      8  FIXED     0x11 01 00 00 = 273; 0x07 b8 4e b1 (server param)
 24–27      4  VARIABLE  Session-specific
 28–31      4  FIXED     0xbb c9 b4 09
 32–33      2  VARIABLE
 34–35      2  FIXED     0x5b cb
 36–43      8  VARIABLE
 44–50      7  FIXED     87 22 74 74 97 fe 5f  ("tt" at bytes 46–47)
 51–56      6  VARIABLE  (partial)
 57–79     23  FIXED     Includes 0x5e 5e 5e ("===") pattern
 80–119    40  VARIABLE  40-byte session-specific region
120–275   156  FIXED     Identical across ALL sessions — DH prime P
                         (hardcoded in CO client binary)
```

The **156-byte fixed block** (`0x76 6e 49 91 e0 73 93 fc … 02 df d6 a0`) is the DH prime P — it never changes across sessions because it is a constant embedded in the client binary. The 68 variable bytes scattered through offsets 4–119 carry the session token received from the auth server.

---

### 4.4 Auth Server Seed Packet

The auth server sends an **8-byte S→C packet** as the very first message:

```
Bytes 0–3: c5 48 69 12  — FIXED across all auth sessions (server identifier?)
Bytes 4–7: xx xx xx xx  — VARIABLE per session (TQ cipher seed)
```

This is the TQ stream cipher initialisation seed. The auth server uses a different cipher (TQ cipher, not Blowfish) for the login/account phase. The variable 4-byte seed is used by the client to initialise the TQ running-key cipher for the auth connection.

---

### 4.5 Packet Size Fingerprint Table

All type IDs in encrypted packets are meaningless (random-looking). Outer payload **size** is the only reliable cross-session identifier.

#### C→S Size Distribution

| Size | idle | walk | attack | chat | Classification |
|-----:|:----:|:----:|:------:|:----:|----------------|
| 14   | ×2   | ×2   | ×2     | ×2   | Fixed login pair |
| 16   | ×1   | ×1   | ×1     | ×1   | Login step |
| 17   | ×2   | ×2   | ×2     | ×2   | Fixed login pair |
| 18   | ×3   | ×3   | ×3     | ×3   | Fixed login triple |
| 19   | ×1   | ×1   | ×2     | ×1   | Login step |
| **20** | **×34** | **×14** | **×22** | **×10** | **HEARTBEAT** |
| 28   | ×2   | ×1   | ×1     | ×1   | Login/ack |
| 30   | –    | ×27  | ×14    | ×2   | **Movement** |
| 31   | –    | ×24  | ×11    | ×1   | **Movement variant** |
| 35   | ×7   | ×7   | ×7     | ×7   | Fixed login block (×7 always) |
| 37   | –    | –    | –      | ×1   | **Chat message (short)** |
| 40   | ×6   | ×3   | ×4     | ×2   | Login/session data |
| 42   | –    | –    | ×20    | –    | **Attack command** |
| 43   | –    | –    | ×15    | –    | **Attack variant / skill** |
| 44   | ×1   | ×1   | ×1     | ×1   | Login step |
| 45   | ×1   | ×1   | ×1     | ×1   | Login step |
| 56   | –    | ×33  | ×43    | ×11  | **Action packet** (move + action) |
| 60   | ×1   | ×1   | ×1     | ×1   | Login step |
| 70   | ×1   | ×1   | ×1     | ×1   | Login step |
| 76   | –    | ×1   | ×1     | ×1   | Rare action |
| 94   | –    | –    | –      | ×1   | **Chat message (long)** |
| 104  | –    | –    | –      | ×1   | **Chat (extended / whisper?)** |
| 276  | ×1   | ×1   | ×1     | ×1   | **DH auth / transfer token (PLAINTEXT)** |
| 357  | ×1   | ×1   | ×1     | ×1   | **Login credential packet** |
| 564  | ×1   | ×1   | ×1     | ×1   | **Character selection / world entry** |

#### S→C Size Distribution (selected)

| Size | idle | walk | attack | chat | Classification |
|-----:|:----:|:----:|:------:|:----:|----------------|
| **20** | **×37** | **×16** | **×23** | **×12** | **HEARTBEAT / ACK** |
| 26   | ×20  | ×2   | **×112** | ×4  | **Hit/miss event** (burst in combat) |
| 27   | ×1   | ×28  | ×23    | ×3   | **Position update** |
| 28   | ×2   | ×26  | ×14    | ×3   | **Entity state** |
| 33   | ×35  | ×19  | ×21    | ×23  | **Periodic server push** (NPC/clock) |
| 47   | ×11  | ×33  | ×43    | ×11  | **Entity position update** |
| **48** | ×2   | ×2   | **×44** | ×2  | **Combat result** (HP/damage) |
| 57   | –    | –    | ×23    | –    | **Combat event** (death / skill effect) |
| 64   | ×1   | ×1   | ×1     | ×1   | Login ack |
| 72   | ×2   | ×2   | ×3     | ×2   | Login info pair |
| 82   | ×2   | ×2   | ×5     | ×2   | Session info |
| 128  | –    | –    | ×10    | –    | **AoE / effect packet** |
| 166  | –    | –    | ×23    | –    | **Extended combat info** |
| 184  | –    | –    | ×15    | –    | **Large combat event** (loot / AoE) |
| 524  | ×1   | ×1   | ×2     | ×1   | **Server config block** |
| 664  | –    | –    | ×3     | –    | **Bulk drop / loot table** |
| 3xxx–5xxx | ×1 | ×1 | ×1 | ×1 | **Map / world state on login** |

---

### 4.6 Movement Packets

| Type | Direction | Sizes | Evidence |
|------|-----------|-------|----------|
| Walk / run command | C→S | **30, 31** | Present in walk (×27, ×24) and attack (×14, ×11), absent in idle. Two sizes suggest two modes (walk vs run, or different direction encodings). |
| Action / combined | C→S | **56** | High frequency in walk (×33) and attack (×43), also in chat (×11). Possibly an action-update packet sent alongside movement. |
| Position update | S→C | **27, 28** | Spikes strongly in walk (×28, ×26) and attack (×23, ×14). Server confirming or broadcasting entity positions. |
| Walk-triggered world data | S→C | 106, 132, 147, 254, 323, 346, 353, 406, 466, 893, 1870, 3338, 3593 | Appear exclusively in walk session — zone/NPC data loaded as the character moves. |

---

### 4.7 Combat Packets

| Type | Direction | Size | Count (attack session) | Evidence |
|------|-----------|-----:|:----------------------:|----------|
| Attack command | C→S | **42** | ×20 | Attack-only |
| Attack variant / skill | C→S | **43** | ×15 | Attack-only |
| Hit / miss event | S→C | **26** | **×112** | Most frequent combat packet; fires on every attack exchange |
| Combat result (HP/damage) | S→C | **48** | ×44 | 22× more common in attack than idle |
| Kill / skill effect | S→C | **57** | ×23 | Attack-only |
| Extended combat info | S→C | **166** | ×23 | Attack-only |
| Large combat event | S→C | **184** | ×15 | Attack-only — likely loot drop or AoE result |
| AoE effect | S→C | 128 | ×10 | Attack-only |
| Mob drop / loot table | S→C | 664 | ×3 | Attack-only |

The S→C **sz=26 (×112)** is the single strongest combat signature — it fires at least once per attack interaction and is the highest-frequency packet in the entire attack session.

---

### 4.8 Chat Packets

| Type | Direction | Size | Evidence |
|------|-----------|-----:|----------|
| Short chat message | C→S | **37** | Chat-only (×1) |
| Long chat message | C→S | **94** | Chat-only (×1); 57 bytes longer than sz=37 — likely a longer message body |
| Extended chat (whisper / trade?) | C→S | **104** | Chat-only (×1) |
| Chat response (short) | S→C | 38, 46 | Chat-only |
| Chat broadcast | S→C | 160, 203, 204, 331, 363, 525, 772, 811 | Variable size — message length-dependent |
| Large chat event (NPC dialog?) | S→C | 1147, 1561, 1693, 3380, 5676 | Chat-only large packets |

---

### 4.9 Heartbeat Packets

```
C→S  sz=20  — rate ∝ session length (34 in 31 KB idle session, 10 in 28 KB chat session)
S→C  sz=20  — same rate, server responds in kind
```

These are the only size-20 packets and appear in every session at a stable rate. Almost certainly a keepalive/ping pair (CO clients typically send a heartbeat every ~5 seconds).

---

### 4.10 Login Sequence Packets

The following packets appear **exactly once per session, always**:

```
C→S  276 bytes  — DH auth / transfer token (PLAINTEXT, type 0x0A02)
C→S  357 bytes  — Login credentials (encrypted)
C→S  564 bytes  — Character selection or world-entry confirmation
C→S  16, 44, 45, 60, 70 bytes  — Individual login steps (×1 each)
C→S  35 bytes ×7  — Fixed block of 7 login-sequence packets (character data?)
S→C  64 bytes   — Login acknowledgement
S→C  524 bytes  — Server configuration block
S→C  72 bytes ×2 — Server info pair
S→C  3000–5500 bytes ×1 — Initial map / world state dump (size varies by map)
```

---

## 5. What Is Still Missing from Phase 2

| Missing Item | Notes |
|---|---|
| `tools/Sentinel.PacketViewer/` | Not built |
| Pattern matcher (5xxx IDs in 7xxx traffic) | Not built |
| Ghidra RE of cipher / handshake code | Blocked by Code Virtualizer |
| Capture scenarios: pickup, NPC, map change, equip, death | Not collected |
| `PROTOCOL.md` | Not written |
| Verified packet type IDs (bytes[2:4] of decrypted packets) | Blocked by encryption |
| Field offset maps for any packet type | Blocked by encryption |

---

## 6. Blocker: DH MITM Required

**The fundamental blocker for all further Phase 2 analysis:**

All game server packets after pkt#0 are Blowfish CFB64 encrypted with a session-unique DH-derived key. The hardcoded key `"DR654dt34trg4UI6"` does not decrypt the traffic. Every packet type ID, every field offset, every structured analysis requires plaintext.

To get plaintext, Sentinel must perform a **DH Man-in-the-Middle**:

```
Current (transparent):
  CO Client ──plain pkt#0──▶ Sentinel ──forward──▶ Real Server
  CO Client ◀──encrypted──── Sentinel ◀──forward──── Real Server
  (Sentinel sees only ciphertext)

Required (MITM):
  CO Client ◀── Sentinel's fake DH pubkey ── Sentinel ──── Real Server's real DH pubkey
               ↑                                           ↑
         SharedSecret_A                            SharedSecret_B
         (Client ↔ Sentinel)                       (Sentinel ↔ Server)

  CO Client ──encrypt(A)──▶ Sentinel ──decrypt(A)──▶ PLAINTEXT ──encrypt(B)──▶ Real Server
  CO Client ◀──encrypt(A)── Sentinel ◀──decrypt(B)── PLAINTEXT ◀──encrypt(B)── Real Server
```

Sentinel maintains two separate Blowfish states (one per direction per side = four total), decrypts inbound, logs plaintext, re-encrypts outbound. The CO client and server are unaware of the intercept.

---

## 7. Decision

**Skip to Phase 3 early: implement DH MITM in `Sentinel.Network`.**

This is the single change that unblocks:
- All remaining Phase 2 analysis (type IDs, field offsets, `PROTOCOL.md`)
- Phase 3 proper (real-time decrypted packet logging)
- Phase 4 (typed packet deserialization)

The DH MITM goes into `ProxySession` and `Sentinel.Crypto` — clean additions within the existing architecture, no structural changes required.

---

## Appendix: Key Reference Values

| Item | Value |
|------|-------|
| Initial Blowfish key (gProxy 5xxx) | `"DR654dt34trg4UI6"` |
| Blowfish mode | CFB64 (`BF_cfb64_encrypt`), segment size = 64 bits |
| Initial IV (before DH) | 8 zero bytes per direction |
| DH prime P (pkt#0 bytes 120–275) | `766e4991e07393fc11f571a0746d15ed603406f21511a376de4e53fba8153a0d2df81509c23f78b602a4414f11110cca0bfe68f8f4caf0885b102ba863ed9d49078e1afdbea0fbf28284f9eb0f0223aabcb861836e57bb36b305b6c27662149b1c4c4b0b541110b4d7893cd5a219ab7e1a7f402a57243c4fd89805616c075b44b0f7bfa9163d06f4a45222ba73adcf0c14793feb9497856b02dfd6a0` |
| Game login packet type | `0x0A02` (2562) |
| Auth server initial packet | 8 bytes S→C, first 4 fixed `c5 48 69 12`, last 4 = TQ seed |
| CO game server ports (this private server) | Auth: 9958, Game: 5815 (remote); 9959, 5816 (Sentinel listen) |
