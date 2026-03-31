# Session 08 — Chat-GPT Report — Runtime IV Validation & Direction-Mapping Pivot
**Date:** 2026-03-30  
**Goal:** Validate whether handshake IVs are truly used by the live CFB64 stream, extend Frida capture to session-specific chains, and determine the correct next direction for RE.

---

## Context

Previous work had already established:

- The game cipher is **not standard Blowfish**; it is a custom 64-bit block cipher used in **CFB64** mode
- The runtime key schedule / BF state is **stable across sessions**
- `BF_cfb64_encrypt` is hooked successfully and can be used to generate deterministic chain output
- A zero-start chain had already been captured successfully:
  - `0000000000000000 -> bc8a80e5bfb0141d`
  - `bc8a80e5bfb0141d -> 694d6035a12e9daf`
- Initial hypothesis: the cipher context contained:
  - `ServerIvec` at `cipher_ctx + 0x0d`
  - `ClientIvec` at `cipher_ctx + 0x15`
- Open question: are those IVs actually the same IV/state used by live calls to `BF_cfb64_encrypt`?

This session was focused on answering that question with runtime evidence.

---

## Work Completed

### 1. Frida v11 — Handshake IV dump + 128KB chain capture

A new Frida script was built on top of the working v10 script with two major additions:

#### A. Hook `DoReceiveShakeHand` at `0x00feeb6c`

After each handshake call returned, the script attempted to inspect candidate runtime objects and dump:

- `server_ivec`
- `client_ivec`
- `dec_num`
- `enc_num`
- candidate `p0`

Two candidates were inspected:
- `ecx`
- `arg0`

This immediately showed that:

- `arg0` was either zeroed or invalid
- `ecx` consistently exposed non-zero IV-like values

#### B. Extend chain generation from 4KB → 128KB

The working `BF_cfb64_encrypt` hook path was preserved and expanded to generate:

- `131072` bytes total
- `16384` chain entries
- output format:
  - `HEX_INPUT -> HEX_OUTPUT`

This successfully produced a large zero-start chain suitable for offline lookup and testing.

---

### 2. Multi-session validation — handshake IVs are session-specific

The updated script was run across **five separate game launches / login sessions**.

Observed `server_ivec` / `client_ivec` pairs:

| Run | Server IV | Client IV |
|-----|-----------|-----------|
| 1 | `61ed2572c8cbcd54` | `e4b29df7e6a3c5f4` |
| 2 | `4585ce1c82e97874` | `391ce5b8eb752252` |
| 3 | `4585cea5f68110f1` | `1433e89ee7d6e752` |
| 4 | `1d813a3f45ed9221` | `731da8dc59e87af7` |
| 5 | `b8ba86c5ed063c8f` | `97d5982b94192f73` |

This established conclusively:

- IVs are **not zero**
- IVs are **not fixed**
- IVs are **session-specific**

This invalidated the earlier assumption that the zero-start chain alone would be sufficient for live session traffic.

---

### 3. Frida v12 — Generate 3 chains per session

After confirming session-specific IVs, the script was upgraded again to produce:

1. `ZERO` chain  
2. `SERVER_IV` chain  
3. `CLIENT_IV` chain  

#### Confirmed runtime example

Captured handshake IVs:

- `server_ivec = 2eeb6d440578f21d`
- `client_ivec = b911420958480b64`

Generated chains:

- `ZERO start IV=0000000000000000`
- `SERVER_IV start IV=2eeb6d440578f21d`
- `CLIENT_IV start IV=b911420958480b64`

Example outputs:

##### ZERO
- `0000000000000000 -> bc8a80e5bfb0141d`
- `bc8a80e5bfb0141d -> 694d6035a12e9daf`
- `694d6035a12e9daf -> ec3699e9846441a2`

##### SERVER_IV
- `2eeb6d440578f21d -> 5fbf91c6d964db9c`
- `5fbf91c6d964db9c -> e8f95c2f81f8b1c5`
- `e8f95c2f81f8b1c5 -> 5ec07ed9bc163137`

##### CLIENT_IV
- `b911420958480b64 -> e91ed830ff205422`
- `e91ed830ff205422 -> ea0f65a9cbf96b8b`
- `ea0f65a9cbf96b8b -> 13e1279a1770a71b`

All three chains completed successfully.

#### Line counts

Each chain produced:

- `16384` transition lines
- plus `START`
- plus `END`

Total per chain:
- `16386` lines

This confirmed there was no truncation or mid-stream failure.

---

### 4. Frida v13 — Direction mapping test against live `BF_cfb64_encrypt`

At this point the main remaining question was:

- Does `ServerIvec` correspond to inbound traffic?
- Does `ClientIvec` correspond to outbound traffic?
- Or vice versa?

A focused runtime script was then created to monitor actual calls to `BF_cfb64_encrypt` and log:

- `enc`
- `len`
- `num_before`
- `ivec_now`
- whether `ivec_now` matched:
  - `ServerIvec`
  - `ClientIvec`
  - or neither

#### Runtime evidence

Handshake capture:

- `server_ivec = 9d2b3e2885dc978e`
- `client_ivec = 09e6bb8f516cfe43`

But live BF calls showed:

##### Call #0
- `enc=0`
- `ivec_now=0000000000000000`
- `match=NEITHER`

##### Call #1
- `enc=0`
- `ivec_now=aa16820eee490d39`
- `match=NEITHER`

##### Call #2
- `enc=1`
- `ivec_now=0000000000000000`
- `match=NEITHER`

This was the critical finding of the session.

---

## Key Discovery

### Handshake IV fields are **not** the live IV/state used directly by `BF_cfb64_encrypt`

This session disproved the working assumption that the values read from:

- `cipher_ctx + 0x0d`
- `cipher_ctx + 0x15`

could be mapped directly to the actual live `ivec` buffers passed into `BF_cfb64_encrypt`.

Although those fields:

- are non-zero
- vary by session
- look like real handshake-derived values

they do **not** match the `ivec` actually observed in live encryption/decryption calls.

That means one of the following is true:

1. They are handshake-only values or staging fields
2. They are copied / transformed into another runtime stream state later
3. The assumed runtime object layout is only partially correct
4. The actual encrypt/decrypt stream contexts live elsewhere

Most importantly, this means:

- `SERVER_IV` / `CLIENT_IV` chains are valid as captured transformations from those values
- but they cannot yet be assumed to represent the exact live `BF_cfb64_encrypt` stream state used on real packets

---

## Resulting Strategic Pivot

Before this session, the next logical step seemed to be:

- map `ServerIvec` → direction
- map `ClientIvec` → direction

After v13, that is **no longer the correct next step**.

The real next step is now:

### Locate the actual live stream state used by `BF_cfb64_encrypt`

The most promising runtime indicators are now:

- `ivecPtr`
- `numPtr`
- `bfKeyPtr`
- possibly return address / caller
- per-direction pointer stability across repeated calls

The investigation must move away from handshake field interpretation and toward direct runtime tracking at the `BF_cfb64_encrypt` call site.

---

## Files / Scripts Produced During Session

| Item | Purpose |
|------|---------|
| `hook_blowfish_v11.js` | Handshake IV dump + 128KB zero-start chain |
| `hook_blowfish_v12.js` | Generate `ZERO`, `SERVER_IV`, and `CLIENT_IV` chains |
| `hook_blowfish_v13.js` | Runtime direction-mapping probe for live BF calls |

---

## Status

| Step | Status |
|------|--------|
| Confirm non-zero handshake IVs | DONE |
| Confirm handshake IVs vary by session | DONE |
| Generate 128KB zero-start chain | DONE |
| Generate per-session `SERVER_IV` chain | DONE |
| Generate per-session `CLIENT_IV` chain | DONE |
| Directly map handshake IVs to live BF direction | **FAILED / disproven by runtime evidence** |
| Verify live `BF_cfb64_encrypt` uses handshake IV fields directly | **FAILED / disproven** |
| Identify actual live encrypt/decrypt stream state | NOT STARTED |
| Map true runtime stream state to inbound/outbound directions | NOT STARTED |

---

## Final Assessment

This session was a major clarification step.

### What was confirmed
- The cipher state is stable enough to reproduce deterministic chains
- Handshake-derived IV-like values exist and are session-specific
- Large per-session chain capture works
- Live BF hooks are reliable and expose real runtime state

### What was disproven
- The handshake IV fields are **not** the same as the live `ivec` buffers used by `BF_cfb64_encrypt`
- Therefore, simple direction mapping via handshake field comparison is incorrect

### Why this matters
This prevents a false conclusion and redirects the RE effort to the correct target:

> the actual runtime stream context passed into `BF_cfb64_encrypt`, not the earlier handshake storage fields.

That is the real path forward for building a correct live decryptor / MITM implementation.

---

## Next Required Step

Create a new Frida probe focused exclusively on live `BF_cfb64_encrypt` runtime state:

- group calls by `enc`
- log `ivecPtr`
- log `numPtr`
- log caller / return address if useful
- determine whether each direction uses a stable dedicated stream buffer
- identify where the true live IV/state is initialized and updated

Once that is mapped, the correct inbound/outbound stream handling can finally be implemented with confidence.