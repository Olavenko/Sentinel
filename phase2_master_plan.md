## Phase 2 Plan — Runtime Crypto Path Discovery and Extraction

### Objective
Identify the real runtime encryption path used by the client, determine where the active cipher context is created and initialized, validate whether the game cipher key is static or derived, and extract either the raw key material or a reusable expanded context for MITM integration.

> **CORRECTION (2026-06-27):** Where this plan refers to `BF_cfb64_encrypt` / Blowfish as the port-19000 game cipher, the actual cipher is a **TQ-customized CAST5 (CAST-128) CFB64** (RFC-2144 CAST5 S-boxes + round structure with a −1 S-box index offset → not stock CAST5). Real functions: CFB64 driver `FUN_01254810` @ `0x01254810`, CAST5 block `FUN_01266300` @ `0x01266300`, S-boxes base `0x0171E034` (from `0x0171E030`). See `ROADMAP.md` for the canonical finding.

---

## Stage 1 — Confirm the Runtime Encryption Boundary

### Goal
Start from the one confirmed crypto use site and collect clean evidence before making any assumptions about initialization or key derivation.

### Actions
1. Hook `BF_cfb64_encrypt` only.
2. For each call, record:
   - caller address
   - return address
   - short backtrace
   - ctx pointer
   - ivec pointer + dump
   - num pointer/value
   - input length
   - output length
3. Capture data across at least 3 separate sessions.
4. Compare the sessions to determine:
   - whether the caller is stable
   - whether the ctx pointer is stable or recreated
   - whether only IV/state changes across sessions
   - whether the game traffic path appears isolated from handshake logic

### Success Criteria
- At least one stable caller or call chain is identified.
- The real runtime cipher context used by game traffic is observed.
- A comparison baseline across sessions is established.

### Decision Gate
- If the caller chain is stable and readable, continue to Stage 2.
- If the caller chain is noisy, inconsistent, or clearly hidden behind protection layers, still do a minimal Stage 2 pass, then escalate to Stage 3 only if needed.

---

## Stage 2 — Walk Backward to the Initialization Path

### Goal
Determine how the active cipher context is prepared before it reaches `BF_cfb64_encrypt`.

### Actions
1. Start from the stable caller or shortest stable call chain found in Stage 1.
2. Identify where the active ctx comes from:
   - allocation
   - copy from template
   - staged initialization
   - setup spread across multiple routines
3. Track how the ctx memory is written before first use.
4. Separate the following if both exist:
   - handshake-related context
   - game-traffic context
5. Identify one of the following:
   - a clear init function
   - an init path
   - an init cluster of closely related routines

### Success Criteria
- The preparation path for the active ctx is understood well enough to explain how it becomes usable by `BF_cfb64_encrypt`.
- The path is classified as one of:
   - direct key setup
   - context copy/template load
   - multi-step runtime build

### Decision Gate
- If a usable init path is found, continue to Stage 4.
- If the path disappears into protection or virtualization too early, move to Stage 3.

---

## Stage 3 — Targeted Handshake Tracing Only If Required

### Goal
Use runtime tracing only as a rescue step when Stages 1 and 2 are not enough.

### Actions
1. Apply tracing around `DoReceiveShakeHand` only if the init path cannot be resolved from Stages 1 and 2.
2. Start with call-level tracing only.
3. Limit tracing to a short execution window.
4. Record only:
   - call targets
   - order of execution
   - transitions into suspicious or repeated routines
   - movement toward ctx creation or setup
5. Expand tracing only on targets that already look relevant.

### Rules
- No full instruction-level tracing from the start.
- No full memory read/write logging.
- No broad tracing windows without a specific target.

### Success Criteria
- A short list of handshake-executed routines relevant to ctx setup or key flow is obtained.
- The missing link between runtime use and initialization becomes visible.

---

## Stage 4 — Test the Key Origin Hypotheses

### Goal
Resolve where the game cipher key material actually comes from.

### Hypotheses
1. The game cipher key is static.
2. The game cipher key is derived from DH or another session exchange.
3. DH is used only for handshake/session negotiation, while the game cipher uses a separate static or semi-static key path.

### Actions
1. Compare ctx behavior across sessions.
2. Compare IV/state behavior across sessions.
3. Compare any init inputs or setup buffers found in Stage 2 or Stage 3.
4. Check whether DH-related values directly influence the game cipher ctx.
5. Separate correlation from proof:
   - session IV change alone does not prove dynamic key derivation
   - repeated ctx structure strongly suggests static or reused key material

### Success Criteria
One hypothesis is selected based on runtime evidence, not assumption.

---

## Stage 5 — Extract a Reusable Artifact

### Goal
Capture the minimum artifact needed to reproduce or relay the game encryption path.

### Extraction Priority
1. Raw key material
2. Full init path plus inputs
3. Expanded cipher context
4. Stable reusable template plus runtime state handling

### Actions
1. If a key setup routine or equivalent input point is found:
   - hook it
   - dump key material before expansion if possible
2. If raw key capture is not practical:
   - dump the expanded ctx after initialization completes
3. Preserve all state required for correct replay:
   - ctx content
   - ivec behavior
   - num progression
   - direction-specific handling if applicable

### Validation
Validation must confirm both:
1. output correctness
2. state progression correctness

### Success Criteria
At least one reusable artifact is captured and verified against real traffic behavior.

---

## Stage 6 — Prepare MITM Integration Strategy

### Goal
Decide how the proxy will obtain and use the encryption material in real operation.

### Questions to Resolve
1. Is the key static and recoverable once?
2. Must the material be collected every session?
3. Will MITM rely on:
   - one-time extraction
   - runtime Frida injection
   - in-process helper / DLL injection
   - context relay from the client process

### Actions
1. Choose the simplest viable production path based on Stage 4 and Stage 5 results.
2. Prefer designs that avoid repeated heavy tracing.
3. Keep extraction separate from proxy logic unless session-derived material forces tighter coupling.

### Success Criteria
A realistic acquisition model exists for production use, not just lab success.

---

## Evidence Classification

### Confirmed
Use this section only for facts proven directly by runtime observation.

### Strongly Suspected
Use this section for results that are highly consistent but not yet fully proven.

### Working Hypothesis
Use this section for active assumptions that guide the next step but must not be treated as settled.

---

## Execution Rules

1. Start from confirmed runtime use, not from protected handshake code.
2. Do not assume `BF_set_key` exists as a neat visible function.
3. Accept that initialization may be distributed across multiple routines.
4. Use tracing only as escalation, never as the default first move.
5. Prefer stable runtime evidence over static naming or guessed semantics.
6. Do not mark addresses, keys, or contexts as final facts unless verified by runtime data.

---

## Expected Deliverables

1. A runtime call map centered on `BF_cfb64_encrypt`
2. A documented ctx preparation path
3. A resolved key-origin conclusion
4. A validated reusable crypto artifact
5. A practical MITM acquisition strategy