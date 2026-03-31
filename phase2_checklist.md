# Sentinel — Phase 2: Crypto RE Master Plan
**Created:** 2026-03-31
**Status:** IN PROGRESS
**Goal:** Fully understand the encryption system and extract the key with zero guesswork.

---

## Checklist

### Stage 1: Runtime Observation (BF_cfb64_encrypt only)
| # | Step | Status | Report |
|---|------|--------|--------|
| 1.1 | Write Frida script: hook `BF_cfb64_encrypt`, log caller, return addr, ctx ptr, ivec ptr + dump, num, len, enc, **backtrace** | ⬜ | — |
| 1.2 | Run script on **Session A** — capture full login + early gameplay | ⬜ | — |
| 1.3 | Run script on **Session B** — same steps | ⬜ | — |
| 1.4 | Run script on **Session C** — same steps | ⬜ | — |
| 1.5 | Compare 3 sessions: identify what is **stable** vs **session-specific** (ctx ptr, ivec, num, caller, backtrace) | ⬜ | — |
| 1.6 | Identify the **primary caller(s)** that invoke `BF_cfb64_encrypt` | ⬜ | — |
| 1.7 | Write Stage 1 Report | ⬜ | `phase2_stage1_report.md` |

**Stage 1 Decision Gate:**
- ✅ If stable caller(s) found → proceed to Stage 2
- ❌ If callers are randomized/virtualized → escalate to Stage 3 (Stalker)

---

### Stage 2: Trace Back to Init Path
| # | Step | Status | Report |
|---|------|--------|--------|
| 2.1 | Analyze primary caller address(es) in **Ghidra** via GhidraMCP + Claude Code | ⬜ | — |
| 2.2 | Identify the function that **creates or allocates** the cipher context | ⬜ | — |
| 2.3 | Identify the function that **fills** the context (key schedule / P-array / S-boxes) | ⬜ | — |
| 2.4 | Determine: is there a **separate** handshake ctx vs game ctx? | ⬜ | — |
| 2.5 | Hook the init function — log the **input key material** before expansion | ⬜ | — |
| 2.6 | Write Stage 2 Report | ⬜ | `phase2_stage2_report.md` |

**Stage 2 Decision Gate:**
- ✅ If init function + key input found → proceed to Stage 4
- ❌ If init path is obfuscated/virtualized → escalate to Stage 3

---

### Stage 3: Stalker on DoReceiveShakeHand (only if needed)
| # | Step | Status | Report |
|---|------|--------|--------|
| 3.1 | Write Frida Stalker script — **call-level only**, limited window around handshake | ⬜ | — |
| 3.2 | Run and capture call targets + execution order | ⬜ | — |
| 3.3 | Cross-reference call targets with Ghidra | ⬜ | — |
| 3.4 | Identify init/derivation functions missed in Stage 2 | ⬜ | — |
| 3.5 | Write Stage 3 Report | ⬜ | `phase2_stage3_report.md` |

---

### Stage 4: Key Source Hypothesis Testing
| # | Step | Status | Report |
|---|------|--------|--------|
| 4.1 | Test Hypothesis A: key is **static** (compare ctx P-array across 3 sessions) | ⬜ | — |
| 4.2 | Test Hypothesis B: key is **DH-derived** (check if DH output feeds into key schedule) | ⬜ | — |
| 4.3 | Test Hypothesis C: DH is handshake-only, game cipher has **independent key** | ⬜ | — |
| 4.4 | Conclusive determination of key source | ⬜ | — |
| 4.5 | Write Stage 4 Report | ⬜ | `phase2_stage4_report.md` |

---

### Stage 5: Key Extraction
| # | Step | Status | Report |
|---|------|--------|--------|
| 5.1 | Extract **raw key** if init function is hookable | ⬜ | — |
| 5.2 | If raw key not accessible: dump **expanded context** (P-array + S-boxes) | ⬜ | — |
| 5.3 | Validate extracted key/context: encrypt known plaintext and compare with real capture | ⬜ | — |
| 5.4 | Write Stage 5 Report | ⬜ | `phase2_stage5_report.md` |

---

### Stage 6: MITM Integration Design
| # | Step | Status | Report |
|---|------|--------|--------|
| 6.1 | Determine key delivery method: static value / Frida injection / DLL hook | ⬜ | — |
| 6.2 | Determine IV/stream state acquisition per session | ⬜ | — |
| 6.3 | Design proxy decrypt/re-encrypt pipeline | ⬜ | — |
| 6.4 | Write Stage 6 Report (final architecture) | ⬜ | `phase2_stage6_report.md` |

---

## Report Template

All reports go to: `F:\Sentinel\docs\reports\`

```markdown
# Phase 2 — Stage [N] Report: [Title]
**Date:** YYYY-MM-DD
**Status:** COMPLETED / PARTIAL / BLOCKED
**Script(s) used:** [filename(s)]

---

## Objective
[What this stage was trying to answer — one or two sentences max]

## Method
[What was done — tools, hooks, scripts, Ghidra analysis, etc.]

## Raw Findings
[Data tables, addresses, hex dumps — the evidence]

## Analysis
[What the findings mean — patterns, conclusions, surprises]

## Confirmed Facts
- [Fact 1 — proven by evidence]
- [Fact 2 — proven by evidence]

## Disproven Assumptions
- [Assumption that was wrong — and why]

## Open Questions
- [What is still unknown after this stage]

## Next Step
[Exactly what to do next based on these results]
```

---

## Key Addresses Reference
| Symbol | Address | Module | Offset |
|--------|---------|--------|--------|
| `BF_cfb64_encrypt` | `0x012410f0` | Conquer.exe | `0xE410f0` |
| `DoReceiveShakeHand` | `0x00feeb6c` | Conquer.exe | `0xBEEB6C` |
| Cipher context | `socket_obj + 0x1008 + 0x40` | Conquer.exe | — |
| Known P[0] | `0xdb298a75` | — | — |
| Static session key | `x97ra5i8D6uZz` | — | — |
| Handshake key | `R3Xx97ra5i8D6uZz` | — | — |

## Known Facts (from previous sessions)
1. Cipher is custom 64-bit block cipher in CFB64 mode
2. Key schedule / BF state is **stable across sessions** (P[0] always = `0xdb298a75`)
3. Handshake IVs are **session-specific** (change every login)
4. Handshake IV fields (`cipher_ctx + 0x0d`, `+0x15`) are **NOT** the live ivec used by `BF_cfb64_encrypt`
5. Both `BF_cfb64_encrypt` and `DoReceiveShakeHand` are inside `Conquer.exe`
6. Handshake functions are Themida/Code Virtualizer protected
7. Blowfish functions are hookable via Frida
8. `ndac.dll` (anti-cheat) is loaded but not currently detecting Frida
