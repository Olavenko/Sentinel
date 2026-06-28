# Sentinel — Handshake RE Analysis via GhydraMCP
# Run this prompt in Claude Code with GhydraMCP connected to the CORRECT binary: Env_DX9\Conquer.exe

## Context
We are building a MITM proxy for Conquer Online (patch 7xxx+).
The gameplay cipher is fully solved (dual-table XOR + nibble-swap, static tables, verified across 3 sessions).
What we need now is to understand the HANDSHAKE phase that happens before gameplay encryption starts.

## Known Facts
- Binary: Env_DX9\Conquer.exe
- Handshake uses Blowfish CFB64 (function `BF_cfb64_encrypt` at ~0x012410f0)
- Handshake entry point: `DoReceiveShakeHand` at ~0x00feeb6c
- Gameplay cipher function: `FUN_00fef18a` (dual-table XOR + nibble-swap)
- The handshake is exactly 3 messages: S→C, S→C, C→S, then gameplay starts
- Anti-cheat: TqNDProtect.dll / ndac.dll present (Themida protected sections exist)

## Task
Use GhydraMCP tools to analyze the handshake flow. Do these steps IN ORDER:

### Step 1: Locate and list instances
Run `instances_list()` to find the active Ghidra instance, then `instances_use()` to connect.

### Step 2: Find handshake functions
Search for these functions and decompile them:
- `DoReceiveShakeHand` (or search for functions near 0x00feeb6c)
- `BF_cfb64_encrypt` (or search near 0x012410f0)
- Any function that calls `DoReceiveShakeHand` (find xrefs/callers)
- Any function named with "ShakeHand", "Handshake", "DH", "DiffieHellman", "KeyExchange"

### Step 3: Trace the handshake flow
For each function found, decompile it and answer:
1. What parameters does it receive?
2. What crypto operations does it perform?
3. Does it generate or derive any keys/tables?
4. Where does it transition to gameplay mode?

### Step 4: Find the connection between handshake and gameplay cipher
Critical question: How does the game transition from Blowfish handshake to the gameplay cipher?
- Find who calls `FUN_00fef18a` (gameplay cipher) and trace back
- Is there an initialization function that sets up the gameplay cipher context?
- Look for functions that write to the cipher context (the struct containing tableA/tableB)

### Step 5: Analyze the DH key exchange
The handshake packet structure (from Frida captures) is:
```
Server → Client handshake (337 bytes):
  [11]  header
  [4]   TqSize  
  [2+N] NonStaticRandomData
  [2+8] ClientIvec
  [2+8] ServerIvec
  [2+N] Prime + Generator + ServerPublicKey
  [8]   TqServer
```
Find the code that parses this structure and extracts DH parameters.

### Step 6: Summary report
Write a clear summary to F:\Sentinel\docs\reports\handshake_ghidra_analysis.md containing:
- All functions found with addresses and decompiled code
- The complete handshake flow (step by step)
- How the Blowfish key is derived
- How/if the gameplay cipher tables are initialized from handshake data
- The exact transition point from handshake to gameplay
- Any Code Virtualizer protected sections encountered (note them, don't try to decompile)
