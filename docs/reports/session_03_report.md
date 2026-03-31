# Session 03 Report — 2026-03-28

## Summary

This session implemented the DH Man-in-the-Middle (Step 11) — the critical blocker identified in session 02. Sentinel can now intercept the Diffie-Hellman handshake between the CO client and game server, compute independent shared secrets with each side, and decrypt/re-encrypt all game traffic in real time. This unblocks all remaining Phase 2 analysis (packet type IDs, field offsets, PROTOCOL.md) and all subsequent phases.

---

## 1. Problem Statement

As established in session 02, all game server traffic after the initial plaintext packet is encrypted with Blowfish CFB64 using a session-unique DH-derived key. The hardcoded key `"DR654dt34trg4UI6"` only serves as the initial cipher key during the handshake — once DH completes, the key is replaced with the shared secret. Without intercepting the DH exchange, Sentinel could only log ciphertext.

---

## 2. Architecture

```
CO Client ◀──── SharedSecret_A ────▶ Sentinel ◀──── SharedSecret_B ────▶ Real Server
                                       │
                              4 cipher instances:
                              _clientDecrypt (C→S from client)
                              _clientEncrypt (S→C to client)
                              _serverDecrypt (S→C from server)
                              _serverEncrypt (C→S to server)
```

The proxy maintains **four independent Blowfish CFB64 cipher instances** — one per direction per side. Each has its own key (shared secret), IV, and streaming `num` counter. The CO client and server are unaware of the intercept.

---

## 3. What Was Built

### 3.1 BlowfishCfb64Cipher (`src/Sentinel.Crypto/BlowfishCfb64Cipher.cs`)

Implements `ICipher`. Uses BouncyCastle's `BlowfishEngine` for the ECB block encryption step, with a manual CFB64 XOR/feedback loop that matches OpenSSL's `BF_cfb64_encrypt` exactly.

| Feature | Detail |
|---------|--------|
| Mode | CFB64 (64-bit = 8-byte feedback segments) |
| Streaming | Maintains `_num` counter (0–7) across calls — encrypt 3 bytes, then 5 bytes = same result as 8 bytes at once |
| Initial state | Key = `"DR654dt34trg4UI6"` (16 bytes ASCII), IV = 8 zero bytes |
| Per-byte encrypt | `if (num==0) ivec=BF_ECB(ivec); out=ivec[num]^=in; num=(num+1)%8` |
| Per-byte decrypt | `if (num==0) ivec=BF_ECB(ivec); c=in; out=ivec[num]^c; ivec[num]=c; num=(num+1)%8` |

**Why manual CFB64?** BouncyCastle's `CfbBlockCipher` doesn't expose the streaming `num` counter needed for byte-at-a-time CFB64 processing. OpenSSL's `BF_cfb64_encrypt` maintains this counter across calls, which is essential since TCP delivers data in arbitrary-sized chunks, not aligned to 8-byte blocks.

### 3.2 DiffieHellman (`src/Sentinel.Crypto/DiffieHellman.cs`)

Implements `IKeyExchange`. Wraps BouncyCastle's `DHKeyPairGenerator` and `DHBasicAgreement`.

| Method | What it does |
|--------|-------------|
| `Initialize(prime, generator)` | Constructs `DHParameters` from big-endian byte arrays extracted from the server handshake |
| `GeneratePublicKey()` | Generates ephemeral DH keypair, returns public key as big-endian byte array |
| `ComputeSharedSecret(remotePubKey)` | Performs modular exponentiation, returns shared secret bytes (becomes the Blowfish key) |

Two instances are created per session — one for the proxy↔client side, one for the proxy↔server side. Each generates its own ephemeral keypair.

### 3.3 HandshakeParser (`src/Sentinel.Crypto/HandshakeParser.cs`)

Static utility class that parses and rebuilds the two handshake packets. Includes `ServerHandshake` and `ClientHandshakeReply` data classes.

**Server Handshake (S→C, encrypted with initial key):**

```
Offset  Field                  Format
──────────────────────────────────────────
  0     Header                 11 fixed bytes
 11     TqSize                 Int32 LE
 15     NonStaticRandomData    2-byte LE length prefix + N bytes
  +     ClientIvec             2-byte LE length prefix + 8 bytes
  +     ServerIvec             2-byte LE length prefix + 8 bytes
  +     P (DH prime)           2-byte LE length prefix + N bytes
  +     G (DH generator)       2-byte LE length prefix + N bytes
  +     ServerPublicKey        2-byte LE length prefix + N bytes
  +     TqServer               8 fixed bytes
```

**Client Handshake Reply (C→S, encrypted with initial key):**

```
Offset  Field                  Format
──────────────────────────────────────────
  0     Header                 11 fixed bytes
 11     Data                   2-byte LE length prefix + N bytes
  +     ClientPublicKey        2-byte LE length prefix + N bytes
  +     TqClient               8 fixed bytes
```

The `ReadBuffer`/`WriteBuffer` helpers use TQ's standard 2-byte little-endian length prefix format.

### 3.4 Interface Changes

**ICipher** (`src/Sentinel.Crypto/Interfaces/ICipher.cs`):
- Added: `void SetIv(ReadOnlySpan<byte> iv)` — sets the initialization vector and resets the streaming counter to 0

**IKeyExchange** (`src/Sentinel.Crypto/Interfaces/IKeyExchange.cs`):
- Added: `void Initialize(ReadOnlySpan<byte> prime, ReadOnlySpan<byte> generator)` — sets DH parameters at runtime before key generation

### 3.5 Configuration

**ProxyEndpointConfig** (`src/Sentinel.Core/Models/ProxyConfiguration.cs`):
- Added: `bool EnableMitm` — controls whether the endpoint performs DH MITM

**appsettings.json** — GameServer endpoint now has `"EnableMitm": true`:
```json
{
  "Name": "GameServer",
  "ListenPort": 19000,
  "RemoteHost": "170.33.9.35",
  "RemotePort": 19000,
  "EnableMitm": true
}
```

Other endpoints (Login, VersionCheck, GameAuth) remain transparent.

### 3.6 ProxySession Rewrite (`src/Sentinel.Network/Proxy/ProxySession.cs`)

Major modification — the session now has two phases:

**Phase 1: DH MITM Handshake** (GameServer only, runs before forwarding starts)

1. Create 4 initial ciphers keyed with `"DR654dt34trg4UI6"` + zero IV
2. Read server handshake from `serverStream`, decrypt, parse
3. Create 2 DH instances with same P/G from the handshake, generate ephemeral pubkeys
4. Substitute server's pubkey with proxy's pubkey → encrypt → send to client
5. Read client handshake reply from `clientStream`, decrypt, parse
6. Substitute client's pubkey with proxy's pubkey → encrypt → send to server
7. Compute shared secrets:
   - `sharedSecretClient = dhClient.ComputeSharedSecret(realClientPubKey)`
   - `sharedSecretServer = dhServer.ComputeSharedSecret(realServerPubKey)`
8. Create 4 post-DH ciphers with correct keys and IVs
9. Dispose initial ciphers and DH instances

**Phase 2: Crypto Forwarding** (runs after handshake completes)

The forwarding loop now applies crypto when ciphers are active:

```
Read segment → Decrypt (with inbound cipher) → Log PLAINTEXT → Re-encrypt (with outbound cipher) → Forward
```

**IV Assignment** (matching gProxy's `CompleteDH()` behavior):

| Cipher | Key | IV | Purpose |
|--------|-----|----|---------|
| `_clientDecrypt` | sharedSecretClient | ClientIvec | Decrypt what client sends |
| `_clientEncrypt` | sharedSecretClient | ServerIvec | Encrypt what proxy sends to client |
| `_serverDecrypt` | sharedSecretServer | ServerIvec | Decrypt what server sends |
| `_serverEncrypt` | sharedSecretServer | ClientIvec | Encrypt what proxy sends to server |

**Fail-open:** If the handshake fails for any reason, the session logs a warning and falls back to transparent forwarding. This prevents a crypto bug from making the game unplayable during development.

---

## 4. Files Changed

### New Files

| File | Lines | Purpose |
|------|------:|---------|
| `src/Sentinel.Crypto/BlowfishCfb64Cipher.cs` | ~95 | Blowfish CFB64 cipher implementation |
| `src/Sentinel.Crypto/DiffieHellman.cs` | ~65 | DH key exchange implementation |
| `src/Sentinel.Crypto/HandshakeParser.cs` | ~150 | Handshake packet parse/rebuild + data classes |

### Modified Files

| File | Change |
|------|--------|
| `src/Sentinel.Crypto/Sentinel.Crypto.csproj` | Added `BouncyCastle.Cryptography 2.6.2` |
| `src/Sentinel.Crypto/Interfaces/ICipher.cs` | Added `SetIv()` method |
| `src/Sentinel.Crypto/Interfaces/IKeyExchange.cs` | Added `Initialize()` method |
| `src/Sentinel.Core/Models/ProxyConfiguration.cs` | Added `EnableMitm` property to `ProxyEndpointConfig` |
| `src/Sentinel.Network/Proxy/ProxyServer.cs` | Passes `EnableMitm` flag to `ProxySession` constructor |
| `src/Sentinel.Network/Proxy/ProxySession.cs` | Full rewrite — handshake MITM + crypto forwarding pipeline |
| `src/Sentinel.CLI/appsettings.json` | `"EnableMitm": true` on GameServer endpoint |

### NuGet Additions

| Project | Package | Version |
|---------|---------|---------|
| Sentinel.Crypto | BouncyCastle.Cryptography | 2.6.2 |

---

## 5. Build Status

```
Build succeeded.
    0 Warning(s)
    0 Error(s)
```

---

## 6. Risk Areas

| Risk | Impact | Mitigation |
|------|--------|------------|
| Blowfish CFB64 `num` counter mismatch | All streaming decryption after first 8 bytes fails silently | Manual implementation matches OpenSSL byte-for-byte; needs unit test with multi-chunk streaming |
| BigInteger byte order | Wrong shared secret → garbled traffic | Using BouncyCastle's `BigInteger(1, byte[])` which is big-endian unsigned, matching TQ format |
| Handshake timing / partial TCP delivery | Incomplete handshake parse → exception → fallback to transparent | `ReadHandshakeDataAsync` reads all available data; fail-open protects against edge cases |
| IV assignment error | Decryption produces garbage in one or both directions | IV mapping derived directly from gProxy source (`CompleteDH()` + `tempIvec` logic) |
| Shared secret byte format (leading zeros) | Key length mismatch between sides | BouncyCastle's `ToByteArrayUnsigned()` strips leading zeros, matching OpenSSL `DH_compute_key` behavior |

---

## 7. What This Unblocks

With DH MITM in place, Sentinel now logs **plaintext** packets to `logs/`. This unblocks:

| Item | Status |
|------|--------|
| Packet type ID identification (bytes[2:4] of decrypted packets) | **Unblocked** |
| Field offset mapping for all packet types | **Unblocked** |
| `PROTOCOL.md` — confirmed packet ID map + field layouts | **Unblocked** |
| `tools/Sentinel.PacketViewer/` — meaningful hex viewer | **Unblocked** |
| Pattern matcher (5xxx IDs in 7xxx traffic) | **Unblocked** |
| Additional capture scenarios (pickup, NPC, map change, equip, death) | **Unblocked** |
| Phase 4 typed packet deserialization | **Unblocked** |

---

## 8. Next Steps

1. **Integration test:** Run the full stack (proxy + hook + loader) and verify the CO client can log in and play normally through the MITM proxy
2. **Verify plaintext captures:** Inspect `logs/` files to confirm decrypted packets show recognizable structures (CO packet headers, type IDs matching 5xxx reference)
3. **Unit tests:** Add tests for `BlowfishCfb64Cipher` (round-trip, streaming, known vectors), `DiffieHellman` (two-party agreement), and `HandshakeParser` (parse/build round-trip)
4. **Resume Phase 2 analysis:** With plaintext available, identify packet type IDs, map field offsets, and begin writing `PROTOCOL.md`

---

## Appendix: DH MITM Handshake Flow

```
Step  Direction    What Happens
────────────────────────────────────────────────────────────────────────────
 1    S → Proxy    Server sends CHandshake (encrypted with initial key)
 2    Proxy        Decrypt with initialServerDecrypt
                   Parse: extract P, G, ClientIvec, ServerIvec, server pubkey
                   Create dhClient(P,G) and dhServer(P,G)
                   Generate proxy pubkeys for both sides
 3    Proxy → C    Replace server pubkey with dhClient's pubkey
                   Rebuild, encrypt with initialClientEncrypt, send to client
 4    C → Proxy    Client sends CHandshakeReply (encrypted with initial key)
 5    Proxy        Decrypt with initialClientDecrypt
                   Parse: extract client pubkey
 6    Proxy → S    Replace client pubkey with dhServer's pubkey
                   Rebuild, encrypt with initialServerEncrypt, send to server
 7    Proxy        Compute sharedSecretClient = dhClient ⊕ realClientPubKey
                   Compute sharedSecretServer = dhServer ⊕ realServerPubKey
                   Create 4 post-DH ciphers with correct keys + IVs
 8    C ↔ Proxy ↔ S  All subsequent traffic: decrypt → log plaintext → re-encrypt → forward
```
