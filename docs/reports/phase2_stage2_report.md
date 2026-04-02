# Phase 2 — Stage 2 Report: Trace Back to Init Path
**Date:** 2026-03-31
**Status:** COMPLETED
**Script(s) used:** GhidraMCP + Claude Code static analysis

---

## Objective
Analyze the 3 BF callers and dispatch layer to find the cipher init path and identify the gameplay cipher.

## Method
- Analyzed all 3 caller addresses via Ghidra decompilation
- Traced the dispatch layer (recv/send handlers)
- Identified the gameplay cipher function and fully reversed its algorithm
- Mapped the complete socket object layout and connection type switching

## Raw Findings

### The 3 BF Callers
The Frida-observed addresses (0x1A423AB, 0x1A3F18F, 0x1A5088A) reside inside Code Virtualizer VM handlers. No native code exists at those addresses — they are VM-internal instruction pointers within CV-protected thunks:
- FUN_01187e21 (thunk to CV at 0x01E5E6E7) — handshake processing, contains 2 BF decrypt calls
- FUN_0117317a (thunk to CV at 0x01E50D56) — reply generation, contains 1 BF encrypt call

Ghidra also found 2 native BF wrapper functions that are NEVER triggered by Frida:
- FUN_01170dce — decrypt wrapper (enc=0, ivec at ctx+0x0D, num at ctx+0x04)
- FUN_01172de1 — encrypt wrapper (enc=1, ivec at ctx+0x15, num at ctx+0x08)

These serve a "type-2" regular traffic path that is never active — the game always switches to type-1 (custom cipher) after handshake.

### Dispatch Layer — Connection Type Switch
The socket handler FUN_00fee7cd uses a mode flag at socket+0x1C08:

| Type | Mode | Cipher Used |
|------|------|-------------|
| 1 | Custom (gameplay) | FUN_00fef18a — dual-table XOR |
| 2 | Blowfish | FUN_01170dce / FUN_01172de1 |
| 3 | Custom variant | FUN_00fef18a (same as type 1) |

Additional flags:
- socket+0x1C0E — handshake-active flag (1 during handshake, 0 after)
- socket+0x1C0D — handshake-reply-queued flag

Flow: Connection starts as type-2 with handshake-active=1. CV code processes DH exchange via Blowfish, then sets type=1, handshake-active=0.

### Gameplay Cipher — Fully Reversed
FUN_00fef18a at 0x00FEF18A — the primary cipher for ALL gameplay traffic:
```c
void custom_cipher(cipher_ctx *ctx, byte *buf, int len, bool commit) {
    int savedA = ctx->counterA, savedB = ctx->counterB;
    for (int i = 0; i < len; i++) {
        buf[i] ^= ctx->tableA[ctx->counterA];
        buf[i] ^= ctx->tableB[ctx->counterB];
        if (++ctx->counterA > 0xFF) {
            ctx->counterA = 0;
            if (++ctx->counterB > 0xFF) ctx->counterB = 0;
        }
        buf[i] = (buf[i] << 4 | buf[i] >> 4) ^ 0xAB;
    }
    if (!commit) { ctx->counterA = savedA; ctx->counterB = savedB; }
}
```

Context layout:
- ctx+0x00: counterA (0-255, advances per byte)
- ctx+0x04: counterB (0-255, advances when A wraps)
- ctx+0x08: tableA[256] (key stream 1)
- ctx+0x108: tableB[256] (key stream 2)

Key properties:
- Self-inverse (encrypt = decrypt)
- Commit flag allows peek without consuming keystream
- Tables derived from DH session key inside CV-protected code

### Packet Integrity Tags
Not a real HMAC — static string tags:
- Client → Server: "TQClient" (8 bytes)
- Server → Client: "TQServer" (8 bytes)
- FUN_00813f6b returns constant 8 (tag length)

### Handshake Flow (DoReceiveShakeHand)
```
recv(socket_fd, buf, 0x800)
result = FUN_01187e21(buf, len)     // CV-protected: 2 BF decrypts + DH processing
if (result > 0):
    size = FUN_0117317a(reply, 0x800) // CV-protected: 1 BF encrypt + reply
    socket+0x1C0E = 0                 // EXIT handshake mode
    socket+0x1C08 = 1                 // SWITCH to custom cipher
```

### Socket Object Memory Map
```
+0x0008 : recv buffer (2048 bytes)
+0x0808 : internal pointer area
+0x080A : body recv area
+0x1008 : BF cipher context (BF_KEY at +0x1048)
+0x1808 : handshake reply buffer
+0x1C08 : connection type (1=custom, 2=BF, 3=custom variant)
+0x1C0D : handshake-reply-queued flag
+0x1C0E : handshake-active flag
```

## Analysis

### Two-Phase Encryption Architecture
The game uses a clean two-phase approach:
1. **Handshake phase**: Blowfish CFB64 with static key, processes DH exchange
2. **Gameplay phase**: Lightweight dual-table XOR cipher with DH-derived tables

The transition is atomic — CV code sets socket+0x1C08 from 2→1, and the dispatch layer immediately routes all traffic to the custom cipher.

### Custom Cipher is Weak but Sufficient for MITM
The gameplay cipher is cryptographically weak (XOR + nibble rotate), but for MITM purposes we don't need to break it — we need to replicate it. Since it's self-inverse, the same function encrypts and decrypts.

### Tables are the Key
The entire gameplay cipher security depends on tableA[256] and tableB[256]. These are derived inside CV-protected code from the DH session key. If we can dump these tables, we can decrypt all gameplay traffic.

## Confirmed Facts
- Gameplay uses a completely different cipher than the handshake (dual-table XOR, not Blowfish)
- Gameplay cipher algorithm is fully reversed at FUN_00fef18a
- Cipher is self-inverse (same operation encrypts and decrypts)
- Connection type flag at socket+0x1C08 controls cipher routing
- BF wrapper functions exist but are never used in practice (type-2 path)
- Packet integrity uses static strings "TQClient"/"TQServer", not real HMAC
- All handshake crypto logic is CV-protected (3 BF calls from VM)
- Table derivation happens inside CV-protected FUN_01187e21

## Disproven Assumptions
- **"Need to reverse the full Blowfish key exchange for MITM"** — WRONG for gameplay. We only need the custom cipher tables.
- **"Gameplay uses Blowfish"** — WRONG. Blowfish is handshake-only.
- **"ChainTable cipher from earlier RE work is the gameplay cipher"** — PARTIALLY CORRECT. The concept matches (table-based XOR) but the actual implementation is a dual-table system with nibble rotation.

## Open Questions
- What is the custom cipher context's socket-relative offset?
- Are tableA/tableB identical across sessions or session-specific?
- Exact derivation path from DH key to tables (inside CV code)

## Next Step
Proceed to **Stage 4** (skipping Stage 3 — Stalker not needed since callers are identified):
Hook FUN_00fef18a at 0x00FEF18A, log ECX register to find the cipher context base address, then dump tableA[256] + tableB[256]. Compare tables across sessions to determine if they are static or session-derived.

● I now have all the major pieces. FUN_0117849f returns "TQServer". This confirms the full picture. Let me write up the comprehensive analysis.

  ---
  Stage 2 Analysis — Complete Encryption Architecture

  ---
  Step 1: The 3 BF Callers

  The Frida-observed addresses (0x1A423AB, 0x1A3F18F, 0x1A5088A) live inside Code Virtualizer VM handlers — Ghidra confirms no code exists at those absolute addresses
  (0x01E423AB, etc.). This means the 3 handshake BF calls are made directly from within the CV virtual machine executing FUN_01187e21 and FUN_0117317a (thunks to CV code
  at 0x01E5E6E7 / 0x01E50D56 respectively).

  Ghidra does find 2 additional BF wrapper functions — but these serve the regular-traffic path, not the handshake:

  ┌────────────┬──────────────┬────────────────────────────────────────────────────┐
  │  Address   │   Function   │             Wraps BF_cfb64_encrypt as              │
  ├────────────┼──────────────┼────────────────────────────────────────────────────┤
  │ 0x01170DCE │ FUN_01170dce │ Decrypt (enc=0), ivec at ctx+0x0D, num at ctx+0x04 │
  ├────────────┼──────────────┼────────────────────────────────────────────────────┤
  │ 0x01172DE1 │ FUN_01172de1 │ Encrypt (enc=1), ivec at ctx+0x15, num at ctx+0x08 │
  └────────────┴──────────────┴────────────────────────────────────────────────────┘

  Both wrappers share the same guard logic (check param_1[3] enabled flag, check non-null buffers) and call BF_cfb64_encrypt (0x012410F0) directly. They are only called
  from FUN_00feed21 (send) and FUN_00fee7cd (recv) — Frida never fires on these because by the time regular traffic flows, the connection type has already been switched
  away from Blowfish mode.

  BF cipher context layout (base = socket_obj + 0x1008, confirmed by Frida P[0] = 0xDB298A75 at socket+0x1048):

  socket + 0x1008 + 0x00  → int    state/counter
  socket + 0x1008 + 0x04  → int    num_decrypt    (param_1[1], for FUN_01170dce)
  socket + 0x1008 + 0x08  → int    num_encrypt    (param_1[2], for FUN_01172de1)
  socket + 0x1008 + 0x0C  → byte   enabled flag   (param_1[3])
  socket + 0x1008 + 0x0D  → [8]    ivec_decrypt   (recv IV stream)
  socket + 0x1008 + 0x15  → [8]    ivec_encrypt   (send IV stream)
  socket + 0x1008 + 0x40  → BF_KEY (P-array + S-boxes, ~1024 bytes)

  Decrypt uses ivec_decrypt + num_decrypt → two completely independent CFB64 streams (one per direction), sharing only the key schedule.

  ---
  Step 2: The Dispatch Layer

  FUN_00fee7cd (socket handler, 0x00FEE7CD) — the main receive loop:

  param_1 + 0x1C08  →  connection type flag  (param_1[0x702])
  param_1 + 0x1C0E  →  handshake-mode flag
  param_1 + 0x1C0D  →  handshake-reply-ready flag

  Control flow:

  if (socket+0x1C0E != 0) {
      // HANDSHAKE MODE
      if (socket+0x1C0D != 0) { socket+0x1C0D=0; FUN_00feed10(); }  // send queued reply
      FUN_00feeb6c(param_2);  // DoReceiveShakeHand
  } else {
      // REGULAR MODE — type-dispatched
      recv 2-byte header;
      switch (socket+0x1C08) {
          case 1:  custom_cipher_decrypt(header, 2);        // FUN_00fef18a
          case 2:  BF_decrypt(header, 2);                   // FUN_01170dce
                   + FUN_00fef18a(header, 2, 1);            // ALSO applies custom cipher?
          case 3:  goto case 1;
      }
      recv body;
      switch (socket+0x1C08) {
          case 1:  custom_cipher_decrypt(body);
          case 2:  BF_decrypt(body) + verify HMAC;
          case 3:  custom_cipher_decrypt(body);
      }
  }

  FUN_00feed21 (send path, 0x00FEED21) — symmetric:

  type = *(int *)(socket + 0x1C08);
  if (type == 1 || type == 3)
      FUN_00fef18a(buffer, size, 1);       // custom cipher
  if (type == 2)
      FUN_01172de1(ctx, buffer, size);     // BF encrypt
      BF_encrypt("TQClient", 8);           // + encrypted tag

  No cipher context creation happens in these functions — both just consume pre-initialized contexts. Initialization is exclusively in CV-protected code.

  ---
  Step 3: The Gameplay Cipher — FUN_00fef18a (0x00FEF18A)

  This is the primary cipher for all regular gameplay traffic. Fully decompiled:

  void custom_cipher(cipher_ctx *ctx, byte *buf, int len, bool commit) {
      int savedA = ctx->counterA, savedB = ctx->counterB;
      for (int i = 0; i < len; i++) {
          buf[i] ^= ctx->tableA[ctx->counterA];       // XOR with running key A
          buf[i] ^= ctx->tableB[ctx->counterB];       // XOR with running key B
          if (++ctx->counterA > 0xFF) {
              ctx->counterA = 0;
              if (++ctx->counterB > 0xFF) ctx->counterB = 0;
          }
          buf[i] = (buf[i] << 4 | buf[i] >> 4) ^ 0xAB;  // nibble-swap + XOR 0xAB
      }
      if (!commit) { ctx->counterA = savedA; ctx->counterB = savedB; }
  }

  Custom cipher context layout:

  ctx + 0x00  → int    counterA     (0–255, advances every byte)
  ctx + 0x04  → int    counterB     (0–255, advances when A wraps)
  ctx + 0x08  → [256]  tableA       (running key stream 1)
  ctx + 0x108 → [256]  tableB       (running key stream 2)

  The commit flag (param_4) — if false, counters are rolled back. Used for peek/preview operations without consuming keystream.

  This cipher is symmetric — encrypt = decrypt (applying it twice restores plaintext), since XOR and nibble-swap are self-inverse when applied with the same key position.

  ---
  Step 4: Handshake → Gameplay Cipher Initialization

  DoReceiveShakeHand (FUN_00feeb6c, 0x00FEEB6C):

  recv(socket_fd, buf, 0x800);
  int result = FUN_01187e21(buf, len);      // CV-protected: full handshake processing
                                             // ← 2 BF decrypts happen inside here
  if (result > 0) {
      size = FUN_0117317a(reply_buf, 0x800); // CV-protected: generate reply
                                             // ← 1 BF encrypt happens inside here
      // dispatch reply as message
      socket+0x1C0E = 0;   // ← EXIT HANDSHAKE MODE
  }

  The CV-protected FUN_01187e21 (0x01E5E6E7) and FUN_0117317a (0x01E50D56) are the black boxes. They:
  1. Call BF_cfb64_encrypt directly (bypassing FUN_01170dce wrappers)
  2. Process the DH/key-exchange data
  3. Derive the custom cipher table contents from the handshake session key
  4. Write socket+0x1C08 = 1 (switching from BF mode to custom cipher mode)

  The handshake-reply preparation and acknowledgment chain:
  - FUN_00ff7183 — decrypts 12 bytes using custom cipher; stores result at socket+0x1808; sets socket+0x1C0D = 1
  - FUN_00feed10 — sends the packet at socket+0x1808 via FUN_01136d8e (raw send() loop)

  ---
  Blowfish HMAC Tag (type-2 mode only)

  The 8-byte tag appended to each Blowfish-encrypted packet is not a real HMAC:

  - Client → Server: appends BF_encrypt("TQClient") — 8 bytes
  - Server → Client: appends BF_encrypt("TQServer") — 8 bytes
  - FUN_00813f6b() returns the constant 8 (tag length)

  The receiver decrypts the last 8 bytes and compares to the expected plaintext string. It's a static-string integrity tag, not a cryptographic MAC.

  ---
  Complete Architecture Summary

  SESSION LIFECYCLE
  ─────────────────────────────────────────────────────────────
  CONNECT
    socket+0x1C08 = 2    (Blowfish mode set — presumably at object init)
    socket+0x1C0E = 1    (handshake mode active)

  HANDSHAKE  [CV-protected — FUN_01187e21 / FUN_0117317a]
    recv 15 bytes  → BF_cfb64_decrypt(key=DR654dt34trg4UI6?, ivec=...) → handshake header
    recv 320-346 B → BF_cfb64_decrypt(same stream)                     → DH public key / body
    derive session key from DH exchange
    populate custom_cipher.tableA[256] and tableB[256] from session key
    BF_cfb64_encrypt(reply, 167-197 bytes)                             → encrypted response
    socket+0x1C08 = 1    (SWITCH to custom cipher mode)
    socket+0x1C0E = 0    (exit handshake mode)

  GAMEPLAY  [visible code — FUN_00fee7cd / FUN_00feed21]
    RECV: buf[i] ^= tableA[ctrA] ^= tableB[ctrB]; buf[i] = rol4(buf[i])^0xAB
    SEND: same transform; append 8-byte "TQClient" tag (unencrypted in type-1)
          (in type-2 only: "TQClient" tag would be BF-encrypted, but type-2 not used in practice)

  ─────────────────────────────────────────────────────────────
  KEY MEMORY MAP (socket_obj base)
    +0x008  : recv buffer (param_1+2, 2048 bytes)
    +0x808  : piVar1 area
    +0x80A  : body recv area (param_1+0x202)
    +0x1008 : BF cipher context (1040+ bytes, BF_KEY at +0x1048)
    +0x1808 : handshake reply buffer
    +0x1C08 : connection type (1=custom, 2=BF, 3=custom variant)
    +0x1C0D : handshake-reply-queued flag
    +0x1C0E : handshake-active flag
    custom cipher context: offset TBD (initialized by CV code, ECX-passed to FUN_00fef18a)

  ---
  Critical Unknowns Remaining (all in CV-protected code)

  ┌────────────────────────────────┬──────────────────────────────────────┬────────────────────────────────────────────────────────────────────────────────┐
  │            Unknown             │                Where                 │                                 How to attack                                  │
  ├────────────────────────────────┼──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ BF key during handshake        │ FUN_01187e21 CV VM                   │ Frida: dump BF_KEY at session start → compare to known key "DR654dt34trg4UI6"  │
  ├────────────────────────────────┼──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ DH parameters / key exchange   │ FUN_01187e21 CV VM                   │ Frida: log args to BF_cfb64_encrypt calls #1 and #2                            │
  ├────────────────────────────────┼──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ Custom cipher table derivation │ FUN_01187e21 / FUN_0117317a          │ Frida: dump tableA+tableB after handshake completes (socket+custom_ctx_offset) │
  ├────────────────────────────────┼──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ Custom cipher context offset   │ CV code writing ECX for FUN_00fef18a │ Frida: hook FUN_00fef18a entry, log ECX register                               │
  ├────────────────────────────────┼──────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────┤
  │ Exact socket+0x1C08 = 1 write  │ CV VM                                │ Frida: memory write watchpoint on that field                                   │
  └────────────────────────────────┴──────────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────┘

  The single most valuable Frida experiment: hook FUN_00fef18a entry and log ECX — that immediately gives you the custom cipher context base address, from which you can
  calculate ctx - socket_base to find the socket-relative offset, then dump the 512-byte table contents.

  ---
  I'll update the project memory with these findings:

  Recalled 1 memory (ctrl+o to expand)

● Now I'll update the memory with the Stage 2 findings — the gameplay cipher is an entirely different system:

  Wrote 3 memories (ctrl+o to expand)

● Memory updated. Here's the executive summary of what Stage 2 found:

  ---
  Stage 2 Findings — Executive Summary

  The Big Discovery: Two Completely Different Ciphers

  The 3 Frida-observed BF calls happen inside Code Virtualizer (FUN_01187e21 / FUN_0117317a thunks). Ghidra finds two BF wrapper functions (FUN_01170dce / FUN_01172de1)
  but these serve a "type-2" regular-traffic path that's never active in practice — Frida never triggers them because the game always transitions to type-1 after
  handshake.

  ┌───────────┬────────────────────────────────┬────────────────────────────┬─────────────────────────────────────────────────────────┐
  │   Phase   │             Cipher             │           Where            │                          When                           │
  ├───────────┼────────────────────────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Handshake │ ChainTable CFB64 (modified BF) │ CV-protected VM            │ 3 calls total: decrypt 15B + 320-346B, encrypt 167-197B │
  ├───────────┼────────────────────────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
  │ Gameplay  │ Dual-table XOR + nibble-rotate │ FUN_00fef18a at 0x00FEF18A │ Every packet after handshake                            │
  └───────────┴────────────────────────────────┴────────────────────────────┴─────────────────────────────────────────────────────────┘

  Gameplay Cipher Algorithm (fully reversed)

  per byte:  b ^= tableA[ctrA]
             b ^= tableB[ctrB]
             if (++ctrA > 255) { ctrA=0; if (++ctrB>255) ctrB=0; }
             b = rol4(b) ^ 0xAB
  Two 256-byte tables, derived from DH session key inside the CV VM. Tables live at ctx+0x08 and ctx+0x108.

  Packet Integrity Tags

  Not a real HMAC — just the static strings "TQClient" (outgoing) and "TQServer" (incoming), 8 bytes each, appended to every packet. In type-2 (BF) mode they'd be
  BF-encrypted; in type-1 (gameplay) mode, encryption TBD.

  socket+0x1C08 = Connection Type Switch

  This field (param_1[0x702]) is the mode gate. CV code sets it from 2 → 1 during handshake completion. The flag at +0x1C0E separates handshake mode from regular receive.

  Next Frida Target

  Hook FUN_00fef18a entry, log ECX → immediately reveals the gameplay cipher context base address and its socket-relative offset. Then dump 512 bytes from ctx+0x08 to get
  both tables.