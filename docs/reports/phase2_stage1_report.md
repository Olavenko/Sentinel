# Phase 2 — Stage 1 Report: Runtime Observation of BF_cfb64_encrypt
**Date:** 2026-03-31
**Status:** COMPLETED
**Script(s) used:** `frida_v14_stage1.js`

---

## Objective
Observe all calls to `BF_cfb64_encrypt` during login and gameplay to identify callers, stability patterns, and usage frequency.

## Method
- Wrote Frida hook on `BF_cfb64_encrypt` at `0x012410f0`
- Filtered calls by P[0] == `0xdb298a75` (our target cipher context)
- Logged: caller address, backtrace (6 frames), ctx pointer, ivec, num, len, enc, input/output preview
- Ran across **4 sessions** (Session A–D):
  - Session A: Login only (quick detach)
  - Session B: Login + brief gameplay
  - Session C: Login + extended gameplay (~2 minutes, killed mobs, talked to NPCs)
  - Session D: Login + extended gameplay (same as C, different login)
- Collected caller statistics and backtrace analysis

## Raw Findings

### Call Pattern (identical across all 4 sessions)

| Call # | enc | len (range) | num_before | ivec_before | Caller Offset |
|--------|-----|-------------|------------|-------------|---------------|
| 0 | 0 (decrypt) | 15 | 0 | `0000000000000000` | `Conquer.exe+1a423ab` |
| 1 | 0 (decrypt) | 320–346 | 7 | session-specific | `Conquer.exe+1a3f18f` |
| 2 | 1 (encrypt) | 167–197 | 0 | `0000000000000000` | `Conquer.exe+1a5088a` |

Total calls per session: **exactly 3** (no additional calls during gameplay)

### Backtrace (identical across all sessions)

**Calls #0 and #1 (decrypt):**