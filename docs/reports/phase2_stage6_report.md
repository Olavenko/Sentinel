# Phase 2 — Stage 6 Report: MITM Integration Design
**Date:** 2026-03-31
**Status:** COMPLETED
**Script(s) used:** N/A — architecture design based on Stage 1–5 findings

---

## Objective
Design the complete MITM proxy architecture for Sentinel, defining how each phase of the connection is handled.

## Design Decisions

### Decision 1: Handshake Handling → PASS-THROUGH
The proxy forwards all handshake traffic without modification.

**Rationale:**
- Gameplay cipher tables are static — not derived from handshake/DH exchange
- Handshake is Code Virtualizer protected — complex to replicate
- Pass-through eliminates risk of breaking the connection
- No useful data needs to be extracted from handshake for MITM

### Decision 2: Gameplay Traffic → READ-ONLY (expandable)
The proxy decrypts a COPY of each packet for logging/inspection, then forwards the ORIGINAL encrypted bytes unchanged.

**Rationale:**
- Read-only is sufficient for packet inspection and protocol analysis
- Clean pipeline design allows adding modify+re-encrypt later
- No re-encryption needed = no risk of counter desync
- Future expansion: replace "forward original" with "modify → re-encrypt → forward"

### Decision 3: Handshake Detection → COUNT MESSAGES
The proxy counts message exchanges to detect handshake completion:
1. Server → Client (recv #1)
2. Server → Client (recv #2)
3. Client → Server (send #1)
After these 3 exchanges → switch to GAMEPLAY mode.

**Rationale:**
- Message order is protocol-level constant (verified across 10+ sessions)
- Not dependent on packet sizes (which vary: 320–346 bytes)
- Simple state machine: HANDSHAKE(0) → HANDSHAKE(1) → HANDSHAKE(2) → GAMEPLAY

### Decision 4: Counter Tracking → ASYMMETRIC
| Direction | Counter Model | Proxy Behavior |
|-----------|--------------|----------------|
| Server → Client (recv) | Cumulative | Track (counterA, counterB), advance per byte |
| Client → Server (send) | Reset per packet | Always decrypt from (0, 0) |

**Rationale:**
- Verified by Frida (Stage 5b) across multiple sessions
- recv counters accumulate continuously after handshake
- send counters are externally reset to (0,0) before each packet

---

## Complete Proxy Architecture

### Connection Lifecycle State Machine
```
┌──────────────────────────────────────────────────────┐
│                    NEW CONNECTION                    │
│              state = HANDSHAKE, msg_count = 0        │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                  HANDSHAKE PHASE                     │
│                                                      │
│  on recv from server:                                │
│      forward to client (pass-through)                │
│      msg_count++                                     │
│                                                      │
│  on recv from client:                                │
│      forward to server (pass-through)                │
│      msg_count++                                     │
│                                                      │
│  if msg_count >= 3:                                  │
│      state = GAMEPLAY                                │
│      recv_counterA = 0                               │
│      recv_counterB = 0                               │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                   GAMEPLAY PHASE                     │
│                                                      │
│  on recv from server (encrypted):                    │
│      1. copy = clone(encrypted_bytes)                │
│      2. plaintext = decrypt(copy, recv_cA, recv_cB)  │
│      3. advance recv_cA, recv_cB by len              │
│      4. log(plaintext)                               │
│      5. forward original encrypted_bytes to client   │
│                                                      │
│  on recv from client (encrypted):                    │
│      1. copy = clone(encrypted_bytes)                │
│      2. plaintext = decrypt(copy, 0, 0)              │
│      3. log(plaintext)                               │
│      4. forward original encrypted_bytes to server   │
└──────────────────────────────────────────────────────┘
```

### Cipher Implementation (C#)
```csharp
public class ConquerCipher
{
    private static readonly byte[] TableA = { /* 256 bytes from Stage 4 */ };
    private static readonly byte[] TableB = { /* 256 bytes from Stage 4 */ };

    // Decrypt/Encrypt (self-inverse)
    public static void Transform(byte[] buffer, int offset, int length,
                                  ref int counterA, ref int counterB)
    {
        for (int i = 0; i < length; i++)
        {
            buffer[offset + i] ^= TableA[counterA];
            buffer[offset + i] ^= TableB[counterB];
            if (++counterA > 0xFF)
            {
                counterA = 0;
                if (++counterB > 0xFF) counterB = 0;
            }
            buffer[offset + i] = (byte)(((buffer[offset + i] << 4) |
                                          (buffer[offset + i] >> 4)) ^ 0xAB);
        }
    }

    // Convenience: decrypt server->client (cumulative counters)
    public static byte[] DecryptServerPacket(byte[] encrypted,
                                              ref int counterA, ref int counterB)
    {
        byte[] copy = (byte[])encrypted.Clone();
        Transform(copy, 0, copy.Length, ref counterA, ref counterB);
        return copy;
    }

    // Convenience: decrypt client->server (always from 0,0)
    public static byte[] DecryptClientPacket(byte[] encrypted)
    {
        byte[] copy = (byte[])encrypted.Clone();
        int cA = 0, cB = 0;
        Transform(copy, 0, copy.Length, ref cA, ref cB);
        return copy;
    }
}
```

### Proxy Session State (per connection)
```csharp
public class ProxySession
{
    public SessionState State { get; set; } = SessionState.Handshake;
    public int HandshakeMessageCount { get; set; } = 0;
    public int RecvCounterA { get; set; } = 0;
    public int RecvCounterB { get; set; } = 0;
}

public enum SessionState
{
    Handshake,
    Gameplay
}
```

### Data Flow per Packet (Gameplay Phase)
```
SERVER ──encrypted──► PROXY                              CLIENT
                        │
                        ├─► copy = encrypted.Clone()
                        ├─► plaintext = Decrypt(copy, recvCtrA, recvCtrB)
                        ├─► recvCtrA, recvCtrB += len
                        ├─► Log(plaintext)
                        │
                        └──encrypted──────────────────────► CLIENT
```

---

## Cryptographic Reference

### Gameplay Cipher Algorithm
```
per byte:
    b ^= tableA[counterA]
    b ^= tableB[counterB]
    if (++counterA > 255) { counterA = 0; if (++counterB > 255) counterB = 0; }
    b = nibble_swap(b) ^ 0xAB
```

### Static Tables
- tableA: 256 bytes (extracted Stage 4, verified Stage 5)
- tableB: 256 bytes (extracted Stage 4, verified Stage 5)
- Full hex values stored in: `phase2_stage4_report.md`

### Properties
- Self-inverse: Transform(Transform(x)) = x
- Stateful: counter position matters for recv direction
- Stateless for send: always starts at (0,0)

---

## Future Expansion Path

### Adding Packet Modification
When ready to modify packets, the changes are minimal:
```
Current:   decrypt(copy) → log → forward(original)
Future:    decrypt(copy) → log → modify(copy) → encrypt(copy) → forward(modified)
```

Since the cipher is self-inverse, encrypt = decrypt with same counter position.

For server→client modification:
- Decrypt with current recv counters
- Modify plaintext
- Re-encrypt with SAME counter position (save before, restore, transform again)
- Forward re-encrypted bytes

For client→server modification:
- Decrypt with (0,0)
- Modify plaintext
- Re-encrypt with (0,0)
- Forward re-encrypted bytes

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Counter desync (recv) | Low | Read-only mode — no re-encryption needed |
| Handshake detection fails | Very Low | 3-message pattern verified 10+ sessions |
| Anti-cheat detects proxy | Low | Proxy is TCP-level, no memory injection |
| Tables change in patch | Low | Re-extract via same Frida script |
| Partial packet recv | Medium | Need TCP reassembly before decrypt |

### TCP Reassembly Note
The proxy must handle TCP fragmentation — a single game packet may arrive in multiple TCP segments. The proxy should buffer incoming data and only decrypt complete packets. Packet boundaries can be determined by reading the 2-byte length header (first field after decryption in recv direction).

---

## Summary of All Design Decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Handshake handling | Pass-through | Tables are static, no need to intercept |
| 2 | Gameplay handling | Read-only (expandable) | Sufficient for inspection, safe, expandable |
| 3 | Handshake detection | Count 3 messages | Protocol-level constant, size-independent |
| 4 | Counter tracking | Asymmetric (recv=cumulative, send=reset) | Verified by Frida across multiple sessions |
| 5 | Pipeline design | Clone → decrypt → log → forward original | Zero risk of breaking connection |

---

## Next Step
Proceed to **Phase 3: Implementation** — build the Sentinel proxy with this architecture. Recommended implementation order:
1. TCP proxy relay (forward bytes between client and server)
2. Handshake state machine (count messages, switch to gameplay mode)
3. Cipher implementation (ConquerCipher class with static tables)
4. Gameplay packet decryption + logging
5. Packet parser (interpret decrypted packet structure)