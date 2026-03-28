# Sentinel — Development Roadmap

A phase-by-phase plan to build a modern .NET 10 / C# 14 Conquer Online proxy targeting patch 7xxx+.

Each phase produces something runnable and testable. Each phase includes learning resources tailored for a junior .NET developer.

**Reference codebase:** The original gProxy (`gProxy-master/`) contains complete protocol documentation for CO patch 5xxx. This serves as our Rosetta Stone — not code to port, but knowledge to compare against.

Last updated: 2026-03-28

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

### Step 3: Core Interfaces — DONE (2026-03-28)

| File | Interface | Purpose |
|------|-----------|---------|
| `Core/Interfaces/IProxySession.cs` | `IProxySession` | One client↔server connection — `RunAsync()`, byte counters, `Disconnected` event |
| `Core/Interfaces/IProxyServer.cs` | `IProxyServer` | Listener — `StartAsync()`, `StopAsync()`, session tracking, lifecycle events |
| `Core/Interfaces/IPacketLogger.cs` | `IPacketLogger` | Log raw bytes with session ID, direction, timestamp |
| `Crypto/Interfaces/ICipher.cs` | `ICipher` | `SetKey()`, `Encrypt()`, `Decrypt()`, `Reset()` on `Span<byte>` |
| `Crypto/Interfaces/IKeyExchange.cs` | `IKeyExchange` | `GeneratePublicKey()`, `ComputeSharedSecret()` |
| `Core/Models/ProxyConfiguration.cs` | `ProxyConfiguration` | Binds from `appsettings.json` — endpoints, log directory, console toggle |

### Step 4: TCP Proxy — DONE (2026-03-28)

| File | Class | What It Does |
|------|-------|-------------|
| `Network/Proxy/ProxySession.cs` | `ProxySession` | Bidirectional forwarding via `PipeReader`. Two concurrent tasks, when one side disconnects the other is cancelled. Logs all data through `IPacketLogger`. |
| `Network/Proxy/ProxyServer.cs` | `ProxyServer` | `TcpListener` per endpoint. On accept: connects to remote, creates session, tracks in `ConcurrentDictionary`. |
| `Network/Proxy/ProxyHost.cs` | `ProxyHost` | Orchestrates auth + game servers. DI-friendly via `IOptions<ProxyConfiguration>`. |

### Step 5: Packet Logger — DONE (2026-03-28)

| File | What It Does |
|------|-------------|
| `Network/Logging/PacketLogger.cs` | Console: one line per chunk (timestamp, session, direction, size, 32-byte hex preview). Binary file: one per session in `logs/` (13-byte header + raw data per entry). Uses `ArrayPool<byte>`, 64KB file buffer, `ConcurrentDictionary` for session files. |

### Step 6: CLI Entry Point — DONE (2026-03-28)

| File | What It Does |
|------|-------------|
| `CLI/Program.cs` | `Host.CreateApplicationBuilder` for DI + config + logging. Registers `PacketLogger` and `ProxyHost`. Ctrl+C graceful shutdown. |
| `CLI/appsettings.json` | Auth (9959→9958), Game (5816→5815), logs to `logs/`, console hex enabled. |

### Step 7: Integration Test — TODO (next session)

Connect a real CO client through the proxy and verify end-to-end:

- [ ] Update `appsettings.json` with real CO server IP and ports
- [ ] Run `Sentinel.CLI` as administrator
- [ ] Point CO client to `127.0.0.1:9959`
- [ ] Client logs in and enters game world through proxy
- [ ] Walking, fighting, chatting all work without lag or disconnection
- [ ] Proxy handles client disconnect gracefully
- [ ] Proxy handles server disconnect gracefully
- [ ] Multiple sessions can run simultaneously
- [ ] Binary log files appear in `logs/`
- [ ] Console shows live traffic with hex previews
- [ ] Proxy runs 30+ minutes without memory growth

**How to run:**
```bash
cd F:\Sentinel
dotnet run --project src/Sentinel.CLI
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

## Phase 2 — Capture, Analysis & Reverse Engineering — NOT STARTED

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
│   └── IProxySession.cs
└── Models/
    └── ProxyConfiguration.cs

src/Sentinel.Crypto/
└── Interfaces/
    ├── ICipher.cs
    └── IKeyExchange.cs

src/Sentinel.Network/
├── Logging/
│   └── PacketLogger.cs
└── Proxy/
    ├── ProxyHost.cs
    ├── ProxyServer.cs
    └── ProxySession.cs

src/Sentinel.CLI/
├── Program.cs
└── appsettings.json

tests/Sentinel.Network.Tests/
    (empty — ready for tests)
```
