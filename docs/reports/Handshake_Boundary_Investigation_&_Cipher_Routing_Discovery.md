# Phase 3 — Session Report: Handshake Boundary Investigation & Cipher Routing Discovery

**Date:** 2026-04-05
**Status:** PAUSED — Key discovery made, new direction identified
**Session Duration:** ~4 hours
**Tools Used:** Frida v20 (handshake boundary script), Claude Code + GhydraMCP (Ghidra analysis), CipherVerify standalone test

---

> ## ⚠ CORRECTION (2026-06-27) — read before the body
>
> This report's central routing discovery is **correct**: port 80 = dual-table cipher, port 19000 = a *separate* mode-2 cipher (mode selector `this+0x1c08 = 2`), with `TQClient`/`TQServer` 8-byte trailers and ctx layout key@`+0x40` / ivec@`+0x15`. **But the port-19000 cipher is NOT Blowfish.** Every "Blowfish CFB64" reference below is superseded by:
>
> **Port 19000 = TQ-customized CAST5 (CAST-128) CFB64** — RFC-2144 CAST5 S-box *values* + CAST5 f1/f2/f3 round structure, key-dependent rotations, 12/16-round flag, with a **−1 S-box index offset** (so stock CAST5 / OpenSSL `cast5-cfb` will not decrypt it). Proven by standalone out-of-game reproduction of three live packets across both directions/keys, including a `SENTINELPROBE123` known-plaintext capture.
>
> **Corrected function addresses** — the addresses in the tables below are wrong: `0x012410f0` was a float-math dead end, and `0x01170dce` / `0x01172de1` are not the cipher. Use instead:
> - CFB64 driver: `FUN_01254810` @ `0x01254810`
> - CAST5 block:  `FUN_01266300` @ `0x01266300`
> - S-boxes:      base `0x0171E034` (read from `0x0171E030` for the −1 offset)
>
> The `P[0]=0xdb298a75`-style constants cited as "Blowfish P-array" entries were actually CAST5 subkeys. The body below is preserved verbatim as the original 2026-04-05 investigation record (provenance), including the Blowfish misidentification it concluded with. Canonical finding: `ROADMAP.md`.

---

## Executive Summary

This session started with investigating why the FindSplit brute-force tool couldn't find the handshake/gameplay boundary. It ended with a **critical architectural discovery**: the Game connection (port 19000) does NOT use the gameplay cipher at all — it uses **Blowfish CFB64** exclusively. The gameplay cipher (dual-table XOR + nibble-swap) is only used on the **Auth connection** (port 80).

This fundamentally changes the MITM proxy strategy.

---

## Key Discoveries (in order of importance)

### Discovery 1: Two Different Ciphers on Two Different Connections

| Connection        | Port  | Cipher Used                                    | Key Type                       |
|-------------------|-------|------------------------------------------------|--------------------------------|
| Auth (GameAuth)   | 80    | Gameplay cipher (dual-table XOR + nibble-swap) | Static tables (hardcoded)      |
| Game (GameServer) | 19000 | Blowfish CFB64                                 | Session key from DH handshake  |

**Evidence:** Frida v20 script hooked both `FUN_00fef18a` (gameplay cipher) and `FUN_00feeb6c` (DoReceiveShakeHand). After the handshake completed on the Game connection, **zero** gameplay cipher calls were observed — even after waiting. All gameplay cipher activity happened BEFORE the handshake, on the Auth connection.

### Discovery 2: Static Tables Are Confirmed (Again)

Three independent verification methods all confirm the gameplay cipher tables are static:

1. **Frida cross-session validation:** 3 sessions, 24/24 table matches
2. **CipherVerify standalone test:** 16/16 PASS — C# implementation matches Frida output exactly across all 3 sessions
3. **Encrypted byte comparison:** Identical plaintext at identical counter positions produces identical ciphertext across sessions

Claude Code's earlier conclusion that tables were "session-specific" was **incorrect** — it was an inference from failed decryption, not from actual evidence.

### Discovery 3: The Game Connection Uses Blowfish (mode=2)

From Ghidra analysis, the mode selector field at `this + 0x1c08` determines which cipher is used:

- **mode 1 or 3:** Gameplay cipher (`FUN_00fef18a`)
- **mode 2:** Blowfish CFB64 wrappers (`FUN_01170dce` / `FUN_01172de1`)

Frida confirmed the Game connection handshake operates in **mode=2** throughout.

### Discovery 4: Handshake Is 2 Calls, Not 3

The `DoReceiveShakeHand` function (`FUN_00feeb6c`) was called exactly **2 times** on the Game connection:

- Call #9: `hsFlag=1` on enter, `hsFlag=1` on leave (handshake continues)
- Call #10: `hsFlag=1` on enter, `hsFlag=0` on leave (handshake complete)

The previous Stage 6 report assumed 3 message exchanges. The actual count from the proxy log is:

- C→S 276 bytes (login/DH init)
- S→C 331 bytes (DH response)
- C→S 177 bytes (DH reply)

But `DoReceiveShakeHand` is only called twice because the first C→S message is sent via `FUN_00ff7183` (PRE_HS_SEND) before the handshake recv loop starts.

### Discovery 5: Complete Auth Connection Flow

The Auth connection gameplay cipher flow (from Frida v20):

# 0  CIPHER recv ctx  len=2    (0,0)→(2,0)      S→C first gameplay packet (0800 = size header)

# 1  CIPHER recv ctx  len=6    (2,0)→(8,0)      S→C continuation

# 2  CIPHER send ctx  len=472  (0,0)→(216,1)    C→S login data (counters reset per packet)

# 3  CIPHER recv ctx  len=2    (8,0)→(10,0)     S→C

# 4  CIPHER recv ctx  len=10   (10,0)→(20,0)    S→C

# 5  CIPHER recv ctx  len=2    (20,0)→(22,0)    S→C

# 6  CIPHER recv ctx  len=322  (22,0)→(88,1)    S→C

# 7  PRE_HS_SEND — encrypts first 12 bytes of login packet for Game server

# 8  CIPHER send ctx  len=12   (0,0)→(12,0)     C→S (the 12-byte encrypted header)

--- Auth connection ends, Game connection starts ---

# 9  HANDSHAKE ENTER mode=2

# 10 HANDSHAKE LEAVE  mode=2, hsFlag=0 (done)

--- No more gameplay cipher calls after this ---

Two separate cipher contexts are used:

- `ctx=0x211bdc8` (or `0x2169248` in session 2) — recv direction (S→C), cumulative counters
- `ctx=0x211bbc0` (or `0x2169040` in session 2) — send direction (C→S), reset to (0,0) per packet

---

## Ghidra Analysis Summary (GhydraMCP on correct Env_DX9\Conquer.exe)

### Key Functions

| Address        | Function       | Role                                                           |
|----------------|----------------|----------------------------------------------------------------|
| `0x00fee7cd`   | `FUN_00fee7cd` | Primary receive loop — dispatches based on mode and hsFlag     |
| `0x00feeb6c`   | `FUN_00feeb6c` | DoReceiveShakeHand — handshake recv handler                    |
| `0x00feed21`   | `FUN_00feed21` | Primary send path — encrypts based on mode                     |
| `0x00fef18a`   | `FUN_00fef18a` | Gameplay cipher (dual-table XOR + nibble-swap)                 |
| `0x00ff7183`   | `FUN_00ff7183` | Pre-handshake send — encrypts first 12 bytes, sets preSendFlag |
| `0x012410f0`   | `FUN_012410f0` | Blowfish CFB64 primitive (OpenSSL-style)                       |
| `0x01170dce`   | `FUN_01170dce` | Blowfish recv/decrypt wrapper (enc=0)                          |
| `0x01172de1`   | `FUN_01172de1` | Blowfish send/encrypt wrapper (enc=1)                          |

### State Machine Fields (on socket object)

| Offset          | Type   | Purpose                                                     |
|-----------------|--------|-------------------------------------------------------------|
| `this + 0x1c08` | int32  | Mode selector: 1/3 = gameplay cipher, 2 = Blowfish          |
| `this + 0x1c0d` | byte   | Pre-send flag (set by PRE_HS_SEND, cleared before handshake)|
| `this + 0x1c0e` | byte   | Handshake flag (1 = in handshake, 0 = normal recv)          |
| `this + 0x1c14` | object | Handshake context (passed to virtualized DH functions)      |
| `this + 0x1cd8` | object | Gameplay cipher context (tableA, tableB, counters)          |

### Blowfish CFB64 Context Layout

ctx + 0x00: initialized flag
ctx + 0x04: stream position counter (recv)
ctx + 0x08: stream position counter (send)
ctx + 0x0d: IV buffer (recv, 8 bytes)
ctx + 0x15: IV buffer (send, 8 bytes)
ctx + 0x40: BF_KEY schedule (passed as param_1 + 0x10)

### Virtualized (Code Virtualizer) Functions

| Address        | Called From    | Purpose                                    |
|----------------|----------------|--------------------------------------------|
| `FUN_01e5e6e7` | `FUN_01187e21` | Handshake parser (DH parameter extraction) |
| `FUN_01e50d56` | `FUN_0117317a` | Handshake reply builder                    |

`.vlizer` section: `0x01b3d000 - 0x01ef2fff` (RWX)

### Mode 2 Protocol Details

- Send: packet body encrypted with Blowfish, then encrypted "TQClient" (8 bytes) appended
- Recv: packet decrypted with Blowfish, last 8 bytes checked = "TQServer" (after decryption)

---

## What Was Ruled Out

1. **Tables are NOT session-specific** — confirmed static across 3 sessions with 3 methods
2. **Counter carry-over does NOT explain the decryption failure** — tested counter (88,1) and nearby values on Game connection S→C data, all produced garbage
3. **The Game connection does NOT use the gameplay cipher** — zero cipher calls observed after handshake

---

## Revised Architecture Understanding

┌─────────────────────────────────────────────────────────────┐
│                    CONNECTION FLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. AUTH CONNECTION (port 80)                               │
│     ├── Cipher: Gameplay (static dual-table XOR)            │
│     ├── S→C: recv counters cumulative from (0,0)            │
│     ├── C→S: send counters reset to (0,0) per packet        │
│     ├── Traffic: login exchange, server list, etc.          │
│     └── Connection closes after auth completes              │
│                                                             │
│  2. GAME CONNECTION (port 19000)                            │
│     ├── Phase A: Login packet (first 12 bytes encrypted     │
│     │            with gameplay cipher via PRE_HS_SEND)      │
│     ├── Phase B: DH Handshake (2x DoReceiveShakeHand)       │
│     │            Blowfish CFB64 key exchange (mode=2)       │
│     │            Virtualized DH code in .vlizer section     │
│     ├── Phase C: Gameplay traffic                           │
│     │            ALL encrypted with Blowfish CFB64 (mode=2) │
│     │            NOT the gameplay cipher                    │
│     └── "TQServer"/"TQClient" 8-byte trailers on packets    │
│                                                             │
└─────────────────────────────────────────────────────────────┘

---

## Impact on Sentinel MITM Proxy

### What works now

- Auth connection decryption: fully working with static tables
- TCP proxy relay: working end-to-end
- Handshake pass-through: working

### What needs to change

- Game connection decryption requires **Blowfish CFB64 key**, not gameplay cipher tables
- To get the Blowfish key, we need ONE of:
  1. **Frida hook on BF_cfb64_encrypt** (FUN_012410f0) — capture key + IV from live session (recommended next step)
  2. **Full MITM handshake** — intercept DH exchange, derive own keys (harder but gives full control)
  3. **Devirtualize the .vlizer code** — reverse the DH key derivation (hardest, not recommended)

### Stage 6 Report Corrections Needed

| Item            | Stage 6 Said                         | Actual                                                               |
|-----------------|--------------------------------------|----------------------------------------------------------------------|
| Tables          | Static, not from handshake           | ✅ Correct                                                           |
| Game cipher     | Gameplay cipher after handshake      | ❌ Wrong — Blowfish CFB64                                            |
| Handshake count | 3 messages                           | Partially correct — 3 TCP messages but 2 DoReceiveShakeHand calls    |
| Counter model   | Cumulative recv on game connection   | ❌ Wrong — cumulative on Auth only                                   |

---

## Next Steps (when resuming)

### Immediate: Frida Hook on Blowfish (Recommended)

Write a Frida script to hook `FUN_012410f0` (BF_cfb64_encrypt) and capture:

- The BF_KEY schedule (at param_4, which is `param_1 + 0x10` from the wrapper)
- The IV (param_5)
- The stream position (param_6)
- The direction (param_7: 0=decrypt, 1=encrypt)
- Input/output bytes

This will reveal the Blowfish key without needing to crack the virtualized DH code.

### Follow-up: Implement Blowfish in Proxy

Once we have the key extraction working via Frida, decide between:

- **Option A:** Hook-assisted proxy — Frida extracts key each session, passes to proxy
- **Option B:** Full MITM — proxy intercepts DH, generates own keys (needs DH parameter understanding)

### Files Created This Session

- `F:\Sentinel\tools\CipherVerify\` — Standalone cipher verification (16/16 PASS)
- `F:\Sentinel\tools\CounterCarryTest\` — Counter carry-over test (disproved)
- `F:\Sentinel\tools\frida_v20_handshake_boundary.js` — Handshake boundary detection script (v4)
- `F:\Sentinel\docs\reports\handshake_ghidra_analysis.md` — GhydraMCP analysis report

---

## Raw Frida v20 Output (for reference)

### Session timestamps

- Auth cipher calls: t=1775360526.264 to t=1775360528.120
- Handshake calls: t=1775360528.122 to t=1775360528.378
- Post-handshake cipher calls: NONE

### Cipher context addresses (vary per session)

- Session 1: recv=0x211bdc8, send=0x211bbc0
- Session 2: recv=0x2169248, send=0x2169040
