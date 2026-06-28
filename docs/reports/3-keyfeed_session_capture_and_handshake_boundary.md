# Keyfeed Session Capture & Handshake-Boundary Wiring Note

> **Date:** 2026-06-27 (live Frida-MCP diagnosis, Conquer.exe Env_DX9, port 19000).
> **Scope:** Findings from validating `tools/frida_v22_keyfeed.js` against three live logins.
> This is a **wiring note for the proxy task** — no proxy code changes are made here.

## TL;DR

The port-19000 game connection routes **two different CAST5-variant CFB64 cipher
contexts** through the same driver `FUN_01254810`:

1. A **static pre-handshake cipher** — a *fixed* key (recurs byte-identically every
   login), seeded from a **zero IV**, used for the brief initial exchange (~3 cipher
   calls: the DH negotiation).
2. The **per-session DH cipher** — a *different* key every login, seeded from a
   non-zero DH-derived IV, used for **all gameplay**.

The keyfeed deliberately captures **only the DH session key**. The proxy's read-only
gameplay decrypt must therefore **begin after the static→DH switch**, passing the
initial handshake bytes through unchanged.

## Evidence — three live logins

The static context's schedule hash is **constant** across logins; the DH session's
changes every time. (The static context's *address* moves per connection, proving it
is a fixed key reloaded into a fresh allocation, not a fixed buffer.)

| Login                  | Static ctx hash | Static ctx ptr           | DH session hash | DH session ptr |
| ---------------------- | --------------- | ------------------------ | --------------- | -------------- |
| user manual run        | `7663ddf9`      | (n/a)                    | `63e5eff2`      | (n/a)          |
| MCP login 1            | `7663ddf9`      | `0x174ae57c`             | `1ec017ec`      | `0x2218c7c`    |
| MCP relog (noisy)      | `7663ddf9`      | `0x1792e57c`             | `36aa8dae`      | `0x2218c7c`    |
| MCP relog (clean)      | `7663ddf9`      | `0x1792e57c`             | `b3ad6971`      | `0x2218c7c`    |

The static schedule is the fixed constant (132-byte CAST5 schedule, K[32]=`00000000`,
16-round):

```
758a29db1d0000000cff833c020000004845ec0d02000000e073c2f80b000000
1295a93800000000c8cf7ffc010000008000114e14000000633fc1f810000000
92e02385120000008760498f120000003b97bc9f140000007b9a962209000000
faff92b801000000c79ed1f618000000dd3ac5f6020000006ef9665a04000000
00000000
```

## The switch point (clean trace)

Attaching **before** login, the first cipher calls of a fresh session are:

| call | dir  | schedule   | ivec               | num | len | note                          |
| ---- | ---- | ---------- | ------------------ | --- | --- | ----------------------------- |
| i=0  | recv | `7663ddf9` | `0000000000000000` | 0   | 15  | static, zero-IV stream start  |
| i=1  | recv | `7663ddf9` | `6a1932c082dfea50` | 7   | 328 | static, DH data (mid-stream)  |
| i=2  | send | `7663ddf9` | `0000000000000000` | 0   | 174 | static, zero-IV stream start  |
| i=3  | send | `b3ad6971` | `95e20adab324b5fe` | 0   | 52  | **DH session — first use**    |
| i=5  | recv | `b3ad6971` | `90fea563c9bc49a5` | 0   | 2   | **DH session — recv start**   |

The static handshake exchange is the first **3 cipher calls** (recv ~15 B, recv ~328 B
[the DH payload], send ~174 B) — these sizes vary slightly per login. The DH session
key activates at **i=3** and stays for the rest of the connection.

## Wiring implications for the proxy (port 19000, `EnableGameplayDecrypt`)

1. **Start decrypting only after the static→DH switch.** The initial handshake bytes
   are encrypted under the static key (and are the DH negotiation itself, not gameplay).
   This matches the existing `EnableGameplayDecrypt=true` + `CipherActiveFromStart=false`
   design ("pass handshake through, decrypt after").
2. **Seed from the keyfeed's stream-start state.** The keyfeed gives the DH session
   `schedule_hex` plus the per-direction **num=0** initial ivec (`send_ivec_hex` /
   `recv_ivec_hex`). Seed `Cast5VariantCfb64Cipher` with `SetRawState` + `SetIv` +
   `SetNum(0)` per direction and decrypt from the first post-handshake byte.
3. **Boundary detection is still an open design point.** The proxy needs to know *where*
   on the wire the static→DH switch occurs. Options to decide in the wiring task:
   - count the handshake bytes (the static exchange is a small fixed-shape sequence);
   - detect the DH-complete / first-gameplay packet via protocol framing;
   - **(recommended)** extend the keyfeed to also emit the cumulative byte offset of the
     first DH-session call per direction, so the proxy has an exact switch offset.
   See also `Handshake_Boundary_Investigation_&_Cipher_Routing_Discovery.md`.
4. **The static key is recoverable if ever needed** (it is the fixed constant above,
   zero IV) — but gameplay decrypt does **not** require it. Out of scope for now.

## Why the keyfeed guard is correct

`frida_v22_keyfeed.js` writes a direction's ivec only on a **clean stream start:
`num == 0` AND a non-zero ivec**. Verified live: this rejects all three static-context
calls (its num=0 calls have a zero IV; its non-zero-IV call is mid-stream at num=7) and
captures only the DH session's true start — so a zero-ivec/static key file is never
written, even momentarily. End-to-end confirmed: the captured `b3ad6971` schedule + ivec
decrypts live S→C packets to readable plaintext ending in the `TQServer` marker.
