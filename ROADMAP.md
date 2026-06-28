# Sentinel — Development Roadmap

A phase-by-phase plan to build a modern .NET 10 / C# 14 Conquer Online proxy targeting patch 7xxx+.

Each phase produces something runnable and testable. Each phase includes learning resources tailored for a junior .NET developer.

**Reference codebase:** The original gProxy (`gProxy-master/`) contains complete protocol documentation for CO patch 5xxx. This serves as our Rosetta Stone — not code to port, but knowledge to compare against.

Last updated: 2026-03-28 (session 3)

---

## Phase 1 — Foundation + Transparent Proxy

### Goal

Build the project scaffold and a fully transparent TCP proxy. The CO client connects through it and plays normally — login, walk, fight, loot, chat — without knowing the proxy exists. Every byte is logged.

### Step 1: Solution Structure — DONE (2026-03-28)

Created the .NET 10 solution with layered architecture:

```
Sentinel/
├── Sentinel.slnx
├── src/
│   ├── Sentinel.Core/          — Interfaces, enums, domain types
│   ├── Sentinel.Crypto/        — Cipher interfaces (placeholder for RE phase)
│   ├── Sentinel.Network/       — TCP proxy, session management, packet logging
│   └── Sentinel.CLI/           — Console app entry point
└── tests/
    └── Sentinel.Network.Tests/ — xUnit test project
```

Dependency graph: `CLI → Network → Core`, `Network → Crypto → Core`, `Tests → Network + Core`

### Step 2: Enums — DONE (2026-03-28)

Copied 6 enum files from gProxy into `Sentinel.Core/Enums/` with `Sentinel.Core.Enums` namespace. Added `PacketDirection` enum for logging.

| File | Values | Backing Type |
|------|--------|-------------|
| `AttackType.cs` | CloseRange, Ranged | int |
| `CharacterClass.cs` | 33 class/tier values | byte |
| `ChatType.cs` | 14 chat channels | ushort |
| `ItemPosition.cs` | 30 equipment slots | byte |
| `MiningDirection.cs` | 8 directions | byte |
| `SpellId.cs` | 63 unique spells (organized by class) | ushort |
| `PacketDirection.cs` | ClientToServer, ServerToClient | byte |

### Step 3: Core Interfaces — DONE (2026-03-28, updated session 2)

| File | Interface | Purpose |
|------|-----------|---------|
| `Core/Interfaces/IProxySession.cs` | `IProxySession` | One client↔server connection — `RunAsync()`, byte counters, packet counters, `EndpointName`, `Disconnected` event |
| `Core/Interfaces/IProxyServer.cs` | `IProxyServer` | Listener — `StartAsync()`, `StopAsync()`, session tracking, lifecycle events |
| `Core/Interfaces/IPacketLogger.cs` | `IPacketLogger` | Log raw bytes with session ID, direction, timestamp |
| `Crypto/Interfaces/ICipher.cs` | `ICipher` | `SetKey()`, `Encrypt()`, `Decrypt()`, `Reset()` on `Span<byte>` |
| `Crypto/Interfaces/IKeyExchange.cs` | `IKeyExchange` | `GeneratePublicKey()`, `ComputeSharedSecret()` |
| `Core/Models/ProxyConfiguration.cs` | `ProxyConfiguration` | Binds from `appsettings.json` — endpoints, log directory, console toggle, `ConsoleVerbosity` |

**Session 2 additions to `IProxySession`:** `PacketsSentToServer`, `PacketsSentToClient` (chunk-level counters), `EndpointName` (e.g. `"GameServer"`) — used by the periodic summary display.

### Step 4: TCP Proxy — DONE (2026-03-28)

| File | Class | What It Does |
|------|-------|-------------|
| `Network/Proxy/ProxySession.cs` | `ProxySession` | Bidirectional forwarding via `PipeReader`. Two concurrent tasks, when one side disconnects the other is cancelled. Logs all data through `IPacketLogger`. |
| `Network/Proxy/ProxyServer.cs` | `ProxyServer` | `TcpListener` per endpoint. On accept: connects to remote, creates session, tracks in `ConcurrentDictionary`. |
| `Network/Proxy/ProxyHost.cs` | `ProxyHost` | Orchestrates auth + game servers. DI-friendly via `IOptions<ProxyConfiguration>`. |

### Step 5: Packet Logger — DONE (2026-03-28, updated session 2)

| File | What It Does |
|------|-------------|
| `Network/Logging/PacketLogger.cs` | Binary file (always): one per session in `logs/` (13-byte header + raw data per entry). Uses `ArrayPool<byte>`, 64KB file buffer, `ConcurrentDictionary` for session files. Console output controlled by `ConsoleVerbosity`. |

**Session 2 — `ConsoleVerbosity` modes:**

| Value | Console Output |
|-------|---------------|
| `"minimal"` (default) | Session start/end only + 2-second periodic summary per active session |
| `"normal"` | One line per packet — direction, size, no hex |
| `"verbose"` | Full hex preview per packet (original behavior, for debugging) |

### Step 6: CLI Entry Point — DONE (2026-03-28, updated session 2)

| File | What It Does |
|------|-------------|
| `CLI/Program.cs` | `Host.CreateApplicationBuilder` for DI + config + logging. Registers `PacketLogger` and `ProxyHost`. Ctrl+C graceful shutdown. |
| `CLI/appsettings.json` | Four real endpoints (Login 26545, VersionCheck 80, GameAuth 16000, GameServer 19000), logs to `logs/`, `ConsoleVerbosity: "minimal"`. |

**Session 2** — Updated `appsettings.json` with real CO private-server IPs and ports (170.33.9.35, 121.207.250.57). Added `ConsoleVerbosity` setting. `ProxyHost` gained a 2-second periodic summary loop for `"minimal"` mode. Diagnostic `POSSIBLE GAME PROTOCOL` and IP-scan warnings demoted from `LogWarning` → `LogDebug` (no longer printed at default log level).

### Step 7: Console Output Cleanup — DONE (2026-03-28 session 2)

Removed hex-dump and warning spam from console output so live traffic is readable.

| File Changed | What Changed |
|---|---|
| `Core/Models/ProxyConfiguration.cs` | Added `ConsoleVerbosity` property |
| `Core/Interfaces/IProxySession.cs` | Added `PacketsSentToServer`, `PacketsSentToClient`, `EndpointName` |
| `Network/Proxy/ProxySession.cs` | Packet counters per segment; diagnostic logs → `LogDebug` |
| `Network/Proxy/ProxyHost.cs` | 2s periodic summary loop (minimal mode) |
| `Network/Logging/PacketLogger.cs` | Console output split across three verbosity levels |
| `CLI/appsettings.json` | `"ConsoleVerbosity": "minimal"` |

Example minimal-mode output every 2 seconds while a session is active:
```
[GameServer] 72386020  ↑42 pkts (3.2 KB)  ↓128 pkts (45.1 KB)
```

### Step 8: SentinelHook.dll — DONE (2026-03-28 session 2)

C++ x86 DLL injected into `Conquer.exe` that hooks `ws2_32.dll!connect()` via MinHook. Rewrites the destination IP of any connection targeting the known game-server IPs to `127.0.0.1`, redirecting traffic through the Sentinel proxy transparently — no CO client configuration required.

| File | What It Does |
|------|-------------|
| `src/Sentinel.Hook/SentinelHook.cpp` | `DllMain` — resolves IPs, calls `InstallHook()`. `HookedConnect()` — scans `sockaddr_in`, rewrites matching IPs to loopback. Logs to `SentinelHook.log` in the game directory. |
| `src/Sentinel.Hook/MinHook.h` | MinHook library (inline x86/x64 hook engine) |
| `src/Sentinel.Hook/CMakeLists.txt` | CMake build config (x86 Release → `SentinelHook.dll`) |
| `src/Sentinel.Hook/build.bat` | One-command build script |

IPs redirected: `170.33.9.35` (game), `121.207.250.57` (auth) → `127.0.0.1` (same port).

### Step 9: Sentinel.Loader — DONE (2026-03-28 session 2)

.NET 10 console app that bridges the two-stage launcher problem: CO requires `Play.exe` to launch `Conquer.exe`, but the hook must be in `Conquer.exe`.

**Strategy:** polling injection — launch `Play.exe` normally, poll every 500ms for a new `Conquer.exe` process, inject as soon as it appears (before the game's network stack initialises).

| File | What It Does |
|------|-------------|
| `src/Sentinel.Loader/Program.cs` | Snapshots existing `Conquer.exe` PIDs → starts `Play.exe` → polls `Process.GetProcessesByName("Conquer")` → calls `Injector.InjectDll()` → waits for exit |
| `src/Sentinel.Loader/Injector.cs` | `InjectDll(hProcess, dllPath)` — `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(LoadLibraryA)` + `WaitForSingleObject`. Returns false if `LoadLibraryA` returns NULL. |
| `src/Sentinel.Loader/NativeMethods.cs` | P/Invoke: `OpenProcess`, `VirtualAllocEx/Free`, `WriteProcessMemory`, `CreateRemoteThread`, `GetModuleHandleA`, `GetProcAddress`, `WaitForSingleObject`, `GetExitCodeThread`, `CloseHandle`, `ResumeThread` |

**Known limitation:** race condition — if `Conquer.exe` makes network connections before the poll cycle finds it, those connections won't be hooked. In practice the game takes several seconds to initialise networking so this is reliable.

**How to run:**
```bash
# Build SentinelHook.dll first
cd src/Sentinel.Hook && build.bat

# Run the loader (as Administrator)
dotnet run --project src/Sentinel.Loader -- "F:\TQ\play.exe" "path\to\SentinelHook.dll"

dotnet run --project src/Sentinel.Loader -- "F:\TQ\Play.exe" "src\Sentinel.Hook\build\SentinelHook.dll"

dotnet run --project src/Sentinel.CLI
```

### Step 10: Integration Test — DONE (2026-03-28 session 2)

CO client connected through the proxy via Hook + Loader. All traffic captured successfully.

- [x] `appsettings.json` updated with real CO server IPs and ports
- [x] Hook DLL redirects client connections to loopback
- [x] Loader handles Play.exe → Conquer.exe two-stage launch
- [x] Console output is readable (minimal verbosity)
- [x] Client logs in and enters game world without disconnection
- [x] Proxy handles client/server disconnect gracefully
- [x] Multiple simultaneous sessions work
- [x] Binary log files captured in `logs/`

**Captures collected (`F:\Sentinel\logs\`):**

| File | Size | Content |
|------|------|---------|
| `session_0e614de1...` | 137 KB | In-game traffic (login + world) |
| `session_72386020...` | 46 KB | Auth/login exchange |
| `session_3495ebce...` | 868 B | Version check / probe |
| `session_36dea030...` | 868 B | Version check / probe |

These captures are the input for Phase 2 reverse engineering.

**How to run (full stack):**
```bash
# Terminal 1 — start the proxy
cd F:\Sentinel
dotnet run --project src/Sentinel.CLI

# Terminal 2 — inject and launch the game
dotnet run --project src/Sentinel.Loader -- "F:\TQ\play.exe"
```

### Learn

**1. System.IO.Pipelines** — high-performance I/O for network apps
- [System.IO.Pipelines in .NET](https://learn.microsoft.com/en-us/dotnet/standard/io/pipelines)
- [David Fowler's TCP Echo sample](https://github.com/davidfowl/TcpEcho)

**2. TCP networking fundamentals** — sockets, streams, byte order
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/) — chapters 1-6

**3. Binary protocol framing** — how CO splits the TCP stream into packets
- [Stephen Cleary — Length-prefix framing](https://blog.stephencleary.com/2009/04/sample-code-length-prefix-message.html)

---

## Phase 2 — Capture, Analysis & Reverse Engineering — IN PROGRESS (blocked)

### Goal

Collect gameplay packet captures, build analysis tooling, and reverse engineer the modern CO client to discover encryption, handshake, and packet structures.

### What to Build

- `tools/Sentinel.PacketViewer/` — hex viewer, diff mode, byte frequency analysis, length distribution, session timeline
- Pattern matcher — search for known 5xxx packet IDs in 7xxx traffic
- Data collection sessions covering: login, idle, walk, attack, pickup, NPC, chat, map change, equip, death

### AI-Assisted RE with Ghidra + GhidraMCP

1. Load modern CO client into Ghidra, run auto-analysis
2. Connect GhidraMCP to Claude Code
3. Ask Claude to find: `recv()`/`send()` handlers, cipher constants (Blowfish S-box, AES S-box, RC5 magic), packet dispatch switch, DH/key exchange calls
4. Verify findings against captured traffic

### Community Resources

| Project | Covers | Look At |
|---------|--------|---------|
| **Comet** | CO emulator 5xxx-6xxx | `src/Comet.Network/` ciphers, `src/Comet.Game/Packets/` |
| **COPS** | Older CO emulator | Packet definitions, cipher code |
| **Canyon** | CO emulator | May have newer patch support |
| **RageZone** | CO dev community | Encryption changes per patch, packet structures |

### Learn

- [Wireshark User's Guide — Chapter 7](https://www.wireshark.org/docs/wsug_html_chunked/ChapterWork.html)
- [Ghidra Beginner course](https://ghidra.re/courses/GhidraClass/)
- [Practical Cryptography for Developers — Symmetric Encryption](https://cryptobook.nakov.com/symmetric-key-ciphers)

### Deliverable

`PROTOCOL.md` — confirmed encryption, handshake diagram, initial packet ID map, field offset notes.

---

### Completed this session (2026-03-28 session 3)

#### GhidraMCP Setup — DONE

Connected GhidraMCP to Claude Code. Bridge: Claude Code (MCP client) → Python MCP server → HTTP REST → Ghidra Java plugin → loaded binary. Plugin runs on `localhost:8080`.

#### Conquer.exe Analysis — DONE (partial, blocked by Code Virtualizer)

- Binary is protected by **Code Virtualizer** (Oreans) — `.vlizer` PE section present
- Networking and crypto routines are inside the virtualised region; Ghidra decompilation of those functions produces VM interpreter code, not original logic
- Unprotected regions (startup, config, UI) decompile normally
- Ghidra-only RE of the handshake is impractical without a devirtualiser

#### TqNDProtect.dll Analysis — DONE

- Confirmed **anti-cheat DLL only** (not encryption/networking)
- Exports: `NdProtect_Init`, `NdProtect_Check`, `NdProtect_Heartbeat`, `NdProtect_Report`
- Imports: `CreateToolhelp32Snapshot`, `Process32First/Next`, `OpenProcess`, `ReadProcessMemory`
- No cipher constants, no DH/BigNum imports — irrelevant to Phase 3

#### Packet Capture Analysis — DONE

Four dedicated gameplay sessions captured and analysed (idle 31 KB, walk 37 KB, attack 78 KB, chat 28 KB).

**Encryption — port 19000 game stream: CORRECTED 2026-06-27**

> ⚠ The original session-2 finding here read "Blowfish CFB64." That was a **misidentification** — CAST5-CFB64 mimics Blowfish-CFB64's 64-bit-block/CFB64 shape (key@ctx+0x40, ivec@ctx+0x15). See the canonical finding below.

- Separate streaming cipher state per direction (running `ivec` + `num`; separate send/recv keys)
- CFB64 stream, 8-byte block, session IV from the handshake

**Canonical finding — port 19000 game cipher (confirmed 2026-06-27):** TQ-customized **CAST5 (CAST-128) in CFB64 mode**. Uses the RFC-2144 CAST5 S-box *values* and CAST5's f1/f2/f3 round structure, key-dependent 5-bit rotations, and 12/16-round flag, driven as a CFB64 stream (8-byte block; per-direction running `ivec` + `num`; separate send/recv keys). **Not stock CAST5** — S-box lookups carry a −1 index offset (TQ customization), so OpenSSL `cast5-cfb` will not decrypt it directly. Implementation: CFB64 driver `FUN_01254810` @ `0x01254810`; CAST5 block `FUN_01266300` @ `0x01266300`; S-boxes at base `0x0171E034` (read from `0x0171E030` for the −1 offset); ctx layout key/schedule@`+0x40`, ivec@`+0x15`, num@`+0x08`. Proven by standalone out-of-game reproduction of three live packets across both directions and both keys, including a `SENTINELPROBE123` known-plaintext capture.

**Key exchange: DH, session-unique**
- Hardcoded key `"DR654dt34trg4UI6"` does NOT decrypt traffic — DH is active
- Trial decryption with the hardcoded key failed on all four sessions

**Handshake packet (pkt#0 C→S, 276 bytes, PLAINTEXT, type 0x0A02)**
- First 4 bytes `14 01 02 0a` fixed in all sessions (CO header)
- 68 variable bytes (session token from auth server)
- 156-byte fixed block at bytes[120:276]: DH prime P hardcoded in CO client binary
- Value: `766e4991e07393fc…02dfd6a0`

**Auth server seed:** 8-byte S→C, bytes[0:4] = `c5 48 69 12` fixed, bytes[4:8] variable (TQ cipher seed)

**Packet size fingerprints (key findings):**

| Packet | Direction | Size(s) | Evidence |
|--------|-----------|---------|----------|
| Heartbeat | both | **20** | All sessions, rate ∝ time |
| Walk command | C→S | **30, 31** | Walk+attack, absent in idle |
| Action/combined | C→S | **56** | Walk×33, attack×43, chat×11 |
| Attack command | C→S | **42, 43** | Attack-only (×20, ×15) |
| Chat (short) | C→S | **37** | Chat-only |
| Chat (long) | C→S | **94** | Chat-only |
| DH auth token | C→S | **276** | ×1 per session, PLAINTEXT |
| Login credentials | C→S | **357** | ×1 per session |
| World entry | C→S | **564** | ×1 per session |
| Hit/miss event | S→C | **26** | Attack×112 — highest-freq combat packet |
| Combat result | S→C | **48** | Attack×44 vs idle×2 |
| Kill/skill effect | S→C | **57** | Attack-only ×23 |
| Entity position | S→C | **47** | Walk×33, attack×43 |
| Server config | S→C | **524** | ×1 per session |

Full tables in `reports/session_02_report.md`.

---

### ⚠ Blocker: DH MITM Required

**All remaining Phase 2 work (type IDs, field offsets, PROTOCOL.md) requires plaintext packets.**

Sentinel must perform a DH man-in-the-middle: intercept the DH handshake, compute two shared secrets (one with the client, one with the server), and maintain four CAST5-variant CFB64 cipher states (see canonical finding above — *not* Blowfish) to decrypt/re-encrypt both directions transparently.

**Decision: implement DH MITM as Step 11 (Phase 3 early) before continuing Phase 2 analysis.**

---

### Remaining (unblocked after Step 11)

- [ ] `tools/Sentinel.PacketViewer/`
- [ ] Pattern matcher (5xxx IDs in 7xxx traffic)
- [ ] Capture scenarios: pickup, NPC, map change, equip, death
- [ ] `PROTOCOL.md`

---

### Step 11: DH MITM Implementation — IN PROGRESS (Phase 3 early, unblocks Phase 2)

Implement Diffie-Hellman man-in-the-middle in `ProxySession` and `Sentinel.Crypto` so Sentinel can decrypt all game server traffic in real time.

**Architecture:**

```
CO Client ◀──────────────────────────── Sentinel ────────────────────────────▶ Real Server
          SharedSecret_A (Client↔Proxy)           SharedSecret_B (Proxy↔Server)
          C5_C2S_A  C5_S2C_A                      C5_C2S_B  C5_S2C_B   (CAST5-variant CFB64, not Blowfish)
```

**What to build:**

| File | What It Does |
|------|-------------|
| `Sentinel.Crypto/DiffieHellman.cs` | Wrap `System.Security.Cryptography.DH` or BouncyCastle `DHParameters`. Parse P/G from the server's handshake packet. Generate ephemeral keypair. Compute shared secret. |
| `Sentinel.Crypto/BlowfishCfb64Cipher.cs` *(misnamed — rename pending)* | Concrete `ICipher` for the port-19000 stream. **NOTE:** the cipher is a **CAST5-variant CFB64, not Blowfish** — this existing class needs renaming (e.g. `Cast5VariantCfb64Cipher`) in a **separate code task** (rebuild + tests). Stock BouncyCastle CAST5 won't work directly because of the −1 S-box offset; a custom transform is required. Stateful streaming. |
| `Sentinel.Crypto/TqKeyExchange.cs` | Concrete `IKeyExchange` — parses `CHandshake` from S→C, rebuilds it with a new pubkey for the client, parses `CHandshakeReply` from C→S, rebuilds it with a new pubkey for the server. Sets per-direction IVs from `ClientIvec` / `ServerIvec` in the handshake. |
| `Sentinel.Network/Proxy/ProxySession.cs` | After handshake completes: decrypt each inbound chunk before logging, re-encrypt before forwarding. Four CAST5-variant CFB64 cipher states total (C→S×2, S→C×2). |

**Handshake packet format (from gProxy reference):**

S→C `CHandshake` (server → client, unencrypted with initial key):
```
ReadBytes(11)   — random header
Read<Int32>     — TQSize
ReadBuffer()    — NonStaticRandomData  (2-byte len prefix)
ReadBuffer()    — ClientIvec           (8 bytes)
ReadBuffer()    — ServerIvec           (8 bytes)
ReadBuffer()    — P (DH prime)
ReadBuffer()    — G (DH generator)
ReadBuffer()    — Server DH pubkey
ReadBytes(8)    — TQServer
```

C→S `CHandshakeReply` (client → server, encrypted with initial key):
```
ReadBytes(11)   — header
ReadBuffer()    — Data
ReadBuffer()    — Client DH pubkey
ReadBytes(8)    — TQClient
```

IV assignment after `CompleteDH()`:
```
Proxy encrypt to client  IV = ClientIvec
Proxy decrypt from client IV = ClientIvec
Proxy encrypt to server  IV = ServerIvec
Proxy decrypt from server IV = ServerIvec
```

**NuGet to add:** `BouncyCastle.Cryptography` to `Sentinel.Crypto`

---

## Phase 3 — Encryption Implementation — NOT STARTED

### Goal

Implement discovered cipher behind `ICipher`. Proxy decrypts in real-time, logs readable packets, re-encrypts before forwarding.

### What to Build

- Concrete `ICipher` for discovered algorithm + `IKeyExchange` for handshake
- `CipherFactory` for config-based cipher selection
- Handshake interceptor — extract session key, initialize per-direction ciphers
- Decrypted packet logger alongside encrypted logs

### Learn

- [BouncyCastle C# API](https://www.bouncycastle.org/csharp/)
- [Span\<T\> and Memory\<T\> usage guidelines](https://learn.microsoft.com/en-us/dotnet/standard/memory-and-spans/memory-t-usage-guidelines)

---

## Phase 4 — Packet Parsing + Game State — NOT STARTED

### Goal

Deserialize decrypted packets into typed C# objects. Build `GameSession` with observable events.

### What to Build

- `IPacket` interface, `PacketRegistry`, `PacketReader`/`PacketWriter`
- Typed packet classes (login, status, entity, movement, combat, items, chat, NPC, map)
- `GameSession` — character stats, entity tracker, inventory, map, NPC dialog
- All state changes fire events for plugins and future UI

### Learn

- [.NET Events and Event-Driven Architecture](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/events/)
- [BinaryPrimitives class](https://learn.microsoft.com/en-us/dotnet/api/system.buffers.binary.binaryprimitives)

---

## Phase 5 — Plugin API + Bot Features — NOT STARTED

### Goal

`IPlugin` interface, `AssemblyLoadContext` loading, first bot (auto-potter or auto-looter).

### What to Build

- `IPlugin` with `OnClientPacketAsync`/`OnServerPacketAsync` interceptors
- `IGameClient` action API (async versions of Jump, Melee, CastSpell, Pickup, NPC, Chat, etc.)
- Plugin discovery from `plugins/` directory with per-plugin config
- First 2-3 bot features to validate the API

### Learn

- [AssemblyLoadContext](https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/understanding-assemblydependencyresolver)
- [Channels in .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/channels)

---

## Phase 6 — Full Bot Suite — NOT STARTED

Combat bots (aimbot, scatter, FatalStrike, auto-hunter, follow-kill), automation (blue mouse, spell macro, meteor spammer, auto-potter, auto-repair, mining), navigation (travel bot, auto-follow, speedhack, gate-hop), management (NFarmer, multi-account, disconnect handler).

### Learn

- [Stateless — state machine library](https://github.com/dotnet-state-machine/stateless)

---

## Phase 7 — UI Layer — NOT STARTED

WPF / MAUI / Avalonia dashboard. MVVM binding to `GameSession` events. Character stats, entity radar, inventory, chat, bot controls, session manager.

---

## NuGet Packages

| Project | Package | Version |
|---------|---------|---------|
| Sentinel.Network | Microsoft.Extensions.Logging.Abstractions | 10.0.5 |
| Sentinel.Network | Microsoft.Extensions.Options | 10.0.5 |
| Sentinel.CLI | Microsoft.Extensions.Hosting | 10.0.5 |
| Sentinel.Network.Tests | Microsoft.NET.Test.Sdk | (template) |
| Sentinel.Network.Tests | xunit | (template) |
| Sentinel.Loader | *(none — plain .NET 10, x86, P/Invoke only)* | — |

## External Dependencies (non-NuGet)

| Component | Dependency | Notes |
|-----------|-----------|-------|
| Sentinel.Hook | MinHook | Bundled in `src/Sentinel.Hook/minhook/` — x86 inline hook engine |
| Sentinel.Hook | MSVC / CMake | Build via `build.bat`; output: `SentinelHook.dll` (x86 Release) |

## File Index

```
src/Sentinel.Core/
├── Enums/
│   ├── AttackType.cs
│   ├── CharacterClass.cs
│   ├── ChatType.cs
│   ├── ItemPosition.cs
│   ├── MiningDirection.cs
│   ├── PacketDirection.cs
│   └── SpellId.cs
├── Interfaces/
│   ├── IPacketLogger.cs
│   ├── IProxyServer.cs
│   └── IProxySession.cs          ← added PacketsSentToServer/Client, EndpointName (session 2)
└── Models/
    └── ProxyConfiguration.cs     ← added ConsoleVerbosity (session 2)

src/Sentinel.Crypto/
└── Interfaces/
    ├── ICipher.cs
    └── IKeyExchange.cs

src/Sentinel.Network/
├── Logging/
│   └── PacketLogger.cs           ← verbosity-aware console output (session 2)
└── Proxy/
    ├── ProxyHost.cs               ← periodic summary loop (session 2)
    ├── ProxyServer.cs
    └── ProxySession.cs            ← packet counters, debug-level diagnostics (session 2)

src/Sentinel.CLI/
├── Program.cs
└── appsettings.json               ← real IPs/ports, ConsoleVerbosity: "minimal" (session 2)

src/Sentinel.Hook/                 ← NEW (session 2) — C++ x86 DLL
├── SentinelHook.cpp
├── MinHook.h
├── CMakeLists.txt
└── build.bat

src/Sentinel.Loader/               ← NEW (session 2) — .NET 10 DLL injector
├── Program.cs
├── Injector.cs
├── NativeMethods.cs
└── Sentinel.Loader.csproj

tests/Sentinel.Network.Tests/
    (empty — ready for tests)

reports/
├── session_02_report.md    ← GhidraMCP setup, Conquer.exe/TqNDProtect findings,
                               full packet capture analysis, DH MITM blocker
```
