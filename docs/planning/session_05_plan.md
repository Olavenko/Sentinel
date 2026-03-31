# Session 05 Plan — Dynamic Analysis with x32dbg

## Objective

Extract the Blowfish key used for Game Server encryption (connection type 2) by setting breakpoints on known crypto functions and reading the key from memory at runtime. Static analysis in Ghidra is blocked by Themida virtualization on CCipher init functions.

---

## Context for AI Assistant

You are helping Mohamed perform dynamic analysis on a Conquer Online 7xxx patch client using x32dbg. This is part of the Sentinel project — a C#/.NET proxy for CO protocol research.

### What we know from Session 04 (Ghidra RE):

- Client is **32-bit** — use `x32dbg.exe` (not x64dbg.exe)
- Game Server uses **Blowfish CFB64** encryption (connection type 2)
- Login Server uses **TQ XOR cipher** (connection types 1/3) — NOT relevant here
- The client connects to Login Server first, then Game Server
- On Game Server connect: client sends 276-byte plaintext transfer token FIRST (type 0x0A02), then server responds with encrypted data
- The Blowfish key setup is behind Themida virtualization — cannot be extracted statically
- Type 2 packets end with 8-byte checksum: `"TQServer"`

### Key addresses from Ghidra (confirmed):

| Address      | Function                  | Purpose                                    |
|-------------|---------------------------|--------------------------------------------|
| `0x01170264` | BF CFB64 decrypt wrapper  | Called when decrypting Game Server packets  |
| `0x0124a740` | BF_encrypt (OpenSSL)      | Core Blowfish encrypt block                |
| `0x0124a320` | BF_decrypt (OpenSSL)      | Core Blowfish decrypt block                |
| `0x01240de0` | BF_cfb64_encrypt (OpenSSL)| CFB64 mode — called by the wrapper         |
| `0x00fee3a1` | DoReceiveShakeHand        | Handles handshake after Game Server connect |
| `0x011872b7` | Process handshake (VIRTUALIZED) | Themida-protected handshake processing |
| `0x01172610` | Build handshake reply (VIRTUALIZED) | Themida-protected reply builder    |
| `0x00fee002` | CMyClientSocket::DoReceive | Main receive loop with cipher dispatch    |
| `0x00fede9d` | Game Server connect       | Logs "GameServerIP:%s port:%d"             |

### Cipher object layout (from Ghidra decompilation of 0x01170264):

```
+0x00: [4B] flag/pointer (must be non-zero)
+0x04: [4B] num (CFB64 position counter)
+0x0C: [1B] initialized flag
+0x0D: [8B] IV (initialization vector)
+0x40: [4168B] BF_KEY schedule (18 P-array entries × 4B + 4 × 256 S-box entries × 4B)
```

### Validation method:

If we extract the correct key, decrypting the first Game Server→Client packet with Blowfish CFB64 using that key+IV should produce data ending with the 8-byte ASCII string `"TQServer"`.

---

## Step-by-Step Plan

### CRITICAL — Anti-Debug & Timing Strategy

**Anti-Debug:** The client uses Themida which includes anti-debug protection. The client WILL detect x32dbg and crash/close unless we hide the debugger.

**Solution — ScyllaHide plugin (MUST be set up before opening the client):**
1. Download ScyllaHide from: https://github.com/x64dbg/ScyllaHide/releases
2. Extract and copy the plugin files to x32dbg's `plugins/` folder (specifically `ScyllaHideX86.dll`)
3. Restart x32dbg
4. Go to: Plugins → ScyllaHide → Options
5. Select profile: **"Themida x86"** (pre-configured for Themida protection)
6. If no Themida profile exists, check ALL boxes in the options
7. Click OK/Apply

**Timing Strategy:** When a breakpoint triggers, the client FREEZES completely. The game server has a timeout (~10-30 seconds) and will disconnect the frozen client. This is expected and normal.

**DO NOT try to collect everything in one attempt.** Use multiple login attempts:
- **Attempt 1:** Just confirm breakpoints trigger. Copy register values. Let it disconnect.
- **Attempt 2:** When breakpoint hits, quickly read register values (ECX, ESP). Copy-paste the output. Done.
- **Attempt 3:** Dump cipher object memory (dump command). Copy-paste the output. Done.
- **Attempt 4:** Dump specific offsets (IV, P-array). Copy-paste the output. Done.

Each attempt = login again, trigger breakpoint, grab ONE piece of data, move on.

### Step 1 — Set up ScyllaHide and launch client

1. Confirm ScyllaHide plugin is installed (Plugins menu should show "ScyllaHide")
2. Configure ScyllaHide with Themida profile (see above)
3. Open `x32dbg.exe` (NOT x64dbg — client is 32-bit)
4. File → Open → select the CO client executable (.exe)
5. The debugger will break at the system entry point
6. **BEFORE pressing F9:** Confirm ScyllaHide is active (check Plugins → ScyllaHide → it should show the profile is applied)
7. Press F9 (Run) — may need to press F9 multiple times as Themida has multiple initial breakpoints
8. The client window should appear and show the login screen
9. **Checkpoint:** Client is running and showing login screen without crashing

> **If client still crashes:** Report the exact error message or behavior. We may need to adjust ScyllaHide settings or try a different approach (Frida, which attaches differently and is harder to detect).

### Step 2 — Set breakpoints

In the x32dbg command bar (bottom of the window), enter these commands one by one:

```
bp 0x00fee3a1
bp 0x01170264
bp 0x0124a740
```

Breakpoint summary:
- `0x00fee3a1` → DoReceiveShakeHand (will hit during Game Server handshake)
- `0x01170264` → BF CFB64 decrypt wrapper (will hit on first encrypted packet)
- `0x0124a740` → BF_encrypt core (will hit during key schedule setup AND during encrypt/decrypt)

After setting them, go to Breakpoints tab to confirm all 3 are listed and enabled.

**Checkpoint:** 3 breakpoints set and visible in the Breakpoints tab.

### Step 3 — Login and trigger Game Server connection

1. Press F9 (Run) to resume execution
2. Switch to the client window
3. Log in with your credentials on the private server
4. Select your character and enter the game
5. The debugger should break (pause) when the Game Server connection starts

**Checkpoint:** Debugger paused at one of the breakpoints.

### Step 4 — Identify which breakpoint hit

Check the current address (shown at top of disassembly view):

- **If `0x00fee3a1` (DoReceiveShakeHand):**
  - Good — this is the handshake phase
  - Press F9 to continue — we want to get past the handshake to where the cipher is initialized
  - Keep pressing F9 until you hit `0x01170264` or `0x0124a740`

- **If `0x0124a740` (BF_encrypt):**
  - This could be key schedule setup (what we want) OR regular encryption
  - Check the call stack (View → Call Stack or Ctrl+K)
  - Look for who called this function — if it's from a `BF_set_key`-like function, this is key setup
  - Record: the return address, and the values of ESP, EAX, ECX, EDX

- **If `0x01170264` (BF CFB64 decrypt wrapper):**
  - This is the decrypt function — the cipher object is already initialized
  - The cipher object pointer should be accessible from the function parameters
  - Go to Step 5

### Step 5 — Extract cipher object data

When paused at `0x01170264` (BF CFB64 decrypt wrapper):

1. **Find the cipher object pointer:**
   - Look at the stack (ESP register). In a `thiscall`, the `this` pointer is in ECX
   - Or check the first argument on the stack: `[ESP+4]` or `[ESP+8]`
   - The cipher object pointer is whichever parameter points to a large struct

2. **Dump the cipher object:**
   - Once you have the pointer (let's call it `ADDR`), in the command bar:
   ```
   dump ADDR
   ```
   - This shows the memory in the dump window

3. **Read the IV (8 bytes at offset +0x0D):**
   ```
   dump ADDR+0x0D
   ```
   - Copy these 8 bytes

4. **Read the key schedule (at offset +0x40):**
   ```
   dump ADDR+0x40
   ```
   - The first 72 bytes (18 × 4 bytes) are the P-array
   - Copy at least the first 72 bytes

5. **Record EVERYTHING:**
   - Copy-paste the register window
   - Copy-paste the stack window
   - Copy-paste the dump window showing ADDR+0x00 through ADDR+0x50
   - Copy the hex values of: ECX, ESP, [ESP], [ESP+4], [ESP+8], [ESP+C]

**Checkpoint:** You have copy-pastes/hex dumps of the cipher object memory.

### Step 6 — Try to catch the raw key (before expansion)

The key schedule at +0x40 is the EXPANDED key (after BF_set_key processing). To find the ORIGINAL key (before expansion), we need to catch BF_set_key in action.

1. Remove the breakpoint on BF_encrypt (it will hit too many times):
   ```
   bc 0x0124a740
   ```

2. Set a **hardware write breakpoint** on the P-array start (first 4 bytes of key schedule):
   ```
   bph ADDR+0x40, w, 4
   ```
   (Replace ADDR with the actual cipher object address from Step 5)

3. Press F9 to run — if BF_set_key is called again (e.g., on reconnect or new session), the breakpoint will trigger when the P-array is being written

4. If it triggers, check the call stack — the caller should have the raw key as a parameter on the stack

> **Note:** This step may not trigger if the key was already set before we attached. In that case, we work with the expanded key schedule from Step 5 — it's still usable for decryption.

### Step 7 — Capture a test packet for validation

While still debugging (or after collecting key data):

1. Set a breakpoint on DoReceive to capture the first encrypted packet:
   ```
   bp 0x00fee002
   ```

2. When it hits, look at the buffer being passed to the decrypt function
3. Record the raw encrypted bytes (before decryption)
4. Also record the decrypted output (step through the decrypt call with F8 and check the buffer after)

5. **Validation:** If the decrypted data ends with `54 51 53 65 72 76 65 72` (ASCII "TQServer"), the key is correct!

### Step 8 — Document findings

After completing the analysis, create a session report including:

1. Whether anti-debug was encountered and how it was handled
2. Which breakpoints triggered and in what order
3. The cipher object address and its contents (hex dump)
4. The IV bytes (8 bytes from offset +0x0D)
5. The P-array (72 bytes from offset +0x40)
6. The raw key if captured (from Step 6)
7. The test packet (encrypted + decrypted) for validation
8. Any unexpected findings or deviations from the plan

---

## Troubleshooting

### Client crashes on attach / open
- ScyllaHide may not be configured correctly
- Try: Plugins → ScyllaHide → Options → manually check ALL checkboxes
- If still crashing, try the "VMProtect x86" profile instead of Themida
- Last resort: use Frida instead of x32dbg (different attach mechanism, harder to detect)

### Client disconnects after breakpoint hit
- This is EXPECTED — the server times out the frozen client
- This is NOT a failure — just log in again and repeat
- Work in small increments: one piece of data per attempt
- Tip: have the `dump` command ready to paste BEFORE the breakpoint hits

### Breakpoints don't trigger
- ASLR might be enabled — addresses shift on each run
- Check: in x32dbg, go to the Memory Map tab and find the client module base address
- If base is NOT `0x00400000` or `0x01000000`, ASLR is active
- Solution: calculate offset = Ghidra_address - Ghidra_base, then add to actual base
- Example: if Ghidra base was `0x00400000` and actual base is `0x00A00000`:
  - New address = `0x01170264 - 0x00400000 + 0x00A00000` = `0x01770264`

### BF_encrypt breakpoint hits hundreds of times
- This is normal — BF_encrypt is called 521 times just for key schedule setup
- Solution: disable it (`bc 0x0124a740`) and focus on `0x01170264` (decrypt wrapper)

### Can't find cipher object pointer
- Try: at `0x01170264`, step in (F7) a few instructions and watch which register loads the cipher object
- Or: look at the disassembly at `0x01170264` and see which register or stack offset holds the first parameter

---

## Success Criteria

The session is successful if we obtain ANY of:
1. **Best case:** Raw Blowfish key (before expansion) + IV
2. **Good case:** Expanded key schedule (P-array + S-boxes) + IV
3. **Acceptable:** Decrypted Game Server packet proving the key works
4. **Minimum:** Confirmed that breakpoints trigger correctly and we can see the cipher object in memory

Even option 4 is valuable progress — it confirms the addresses are correct and sets up for a follow-up session.

---

## AI Assistant End-of-Session Task

When Mohamed says the session is done or wants to wrap up, ask him:
"Want me to write a session 05 report summarizing what we found? I'll include all addresses, hex dumps, and next steps."

Then produce a report in the same format as session_04_report.md covering:
- What was attempted
- What succeeded / failed
- All captured data (addresses, hex dumps, copy-pastes descriptions)
- Updated understanding of the protocol
- Concrete next steps for session 06
