# CLAUDE.md — Sentinel Project Context

> This file provides context for AI assistants (Claude Code, Gemini, etc.) working on this project.

## Project Overview

**Sentinel** is a modern Conquer Online (CO) proxy/bot built with .NET 10 / C# 14. It sits between the CO game client and server, intercepting, logging, and eventually decrypting/parsing all network traffic. The long-term goal is a full-featured bot with a plugin system and optional UI layer.

**Target:** Modern CO private servers (patch 7xxx+, 2026 era).

**Reference codebase:** The original `gProxy` project (`F:\Later\AI Co Path\gProxy-master\`) contains complete protocol documentation for CO patch 5xxx (2010 era). This serves as our Rosetta Stone — not code to port, but knowledge to compare against.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | .NET 10 |
| Language | C# 14 |
| Networking | System.IO.Pipelines, TcpListener, TcpClient, async/await |
| Encryption | ICipher abstraction → BouncyCastle / System.Security.Cryptography (TBD after RE phase) |
| DI | Microsoft.Extensions.DependencyInjection |
| Configuration | Microsoft.Extensions.Options + appsettings.json |
| Logging | Microsoft.Extensions.Logging |
| Testing | xUnit |
| IDE | Visual Studio 2022/2026 |
| RE Tools | Ghidra + GhidraMCP + Claude Code |

## Architecture

```
Sentinel/
├── Sentinel.slnx
├── src/
│   ├── Sentinel.Core/          — Interfaces, enums, domain types (zero dependencies)
│   ├── Sentinel.Crypto/        — ICipher, IKeyExchange interfaces + implementations
│   ├── Sentinel.Network/       — TCP proxy, session management, packet logging
│   ├── Sentinel.GameState/     — Entity tracking, inventory, character state (Phase 4)
│   ├── Sentinel.Plugins/       — Plugin loading, IPlugin interface (Phase 5)
│   └── Sentinel.CLI/           — Console app entry point
├── tests/
│   └── Sentinel.Network.Tests/ — xUnit test project
└── tools/
    └── Sentinel.PacketViewer/  — Hex viewer / analysis tool (Phase 2)
```

### Dependency Graph

```
CLI → Network → Core
       ↓
     Crypto → Core
```

Core has zero external dependencies. Network depends on Core + Crypto. CLI depends on Network. This layering is strict — never add upward dependencies.

## Key Design Decisions

### 1. UI-Agnostic Architecture
The Core, Crypto, Network, and GameState layers have NO dependency on any UI framework. The CLI is a thin presentation layer. A future WPF/MAUI/Avalonia UI would replace CLI without touching any other project.

### 2. ICipher Abstraction
Encryption algorithm is unknown until reverse engineering is complete. All crypto goes behind `ICipher` and `IKeyExchange` interfaces. The proxy doesn't care if it's Blowfish, RC5, AES, or something custom — it calls `Encrypt()`/`Decrypt()` and the implementation handles the rest.

### 3. Observable Game State (Phase 4+)
`GameSession` will hold all game state and emit C# events on changes. Plugins and UI subscribe to events — they never poll or access networking directly.

### 4. Phase-by-Phase Development
Each phase produces something runnable. See ROADMAP.md for the full plan. Do NOT implement features from later phases — keep it incremental.

## Current State

**Phase 1 — Foundation + Transparent Proxy (Steps 1-6 DONE, Step 7 TODO)**

Working transparent TCP proxy that:
- Listens on configurable ports (default: 9959 auth, 5816 game)
- Forwards all bytes bidirectionally without modification
- Logs every chunk: timestamp, direction, size, hex preview to console
- Saves binary log files per session in `logs/` directory
- Handles graceful disconnect from both sides
- Supports multiple simultaneous sessions

**Step 7 (Integration Test)** requires a CO private server to test against.

## Core Interfaces

### IProxySession
One client↔server connection pair. `RunAsync()` does bidirectional forwarding via PipeReader. Tracks bytes transferred. Fires `Disconnected` event with optional exception.

### IProxyServer
TcpListener wrapper. Accepts clients, connects to remote server, creates ProxySession. Tracks active sessions in ConcurrentDictionary.

### IPacketLogger
Logs raw bytes with session ID, direction, timestamp. Binary file format: 13-byte header (8 timestamp + 1 direction + 4 length) + N raw bytes. Console output: one line per chunk with 32-byte hex preview.

### ICipher
`SetKey()`, `Encrypt(Span<byte>)`, `Decrypt(Span<byte>)`, `Reset()`. In-place, zero-allocation. Placeholder until RE phase reveals the actual algorithm.

### IKeyExchange
`GeneratePublicKey()`, `ComputeSharedSecret()`. Placeholder until RE phase reveals the handshake.

## Configuration (appsettings.json)

```json
{
  "Proxy": {
    "AuthEndpoint": {
      "Name": "Auth",
      "ListenPort": 9959,
      "RemoteHost": "SERVER_IP_HERE",
      "RemotePort": 9958
    },
    "GameEndpoint": {
      "Name": "Game",
      "ListenPort": 5816,
      "RemoteHost": "SERVER_IP_HERE",
      "RemotePort": 5815
    },
    "LogDirectory": "logs",
    "LogToConsole": true
  }
}
```

## How to Run

```bash
cd F:\Sentinel
dotnet build
dotnet run --project src/Sentinel.CLI
```

Run as Administrator if needed for port binding. Point CO client to `127.0.0.1:9959` instead of the real server.

## NuGet Packages

| Project | Package | Version |
|---------|---------|---------|
| Sentinel.Network | Microsoft.Extensions.Logging.Abstractions | 10.0.5 |
| Sentinel.Network | Microsoft.Extensions.Options | 10.0.5 |
| Sentinel.CLI | Microsoft.Extensions.Hosting | 10.0.5 |
| Sentinel.Network.Tests | xunit | latest |
| Sentinel.Network.Tests | Microsoft.NET.Test.Sdk | latest |

## Code Conventions

- **Language:** All code, comments, documentation, and variable names in English
- **Style:** Modern C# 14 — file-scoped namespaces, primary constructors where appropriate, pattern matching
- **Async:** async/await everywhere — no blocking calls, no `Task.Result`, no `Task.Wait()`
- **Memory:** Prefer `Span<T>` and `Memory<T>` over `byte[]` where possible. Use `ArrayPool<byte>` for temporary buffers
- **Thread safety:** `ConcurrentDictionary` for shared collections, `Interlocked` for counters
- **Logging:** Structured logging via `ILogger<T>` with message templates (not string interpolation)
- **DI:** Constructor injection. Register via `Microsoft.Extensions.DependencyInjection`
- **Testing:** xUnit. Test names: `MethodName_Scenario_ExpectedResult`
- **No warnings:** Build with zero warnings

## What NOT to Do

- Do NOT add UI framework references to Core, Crypto, Network, or GameState
- Do NOT implement encryption before RE phase confirms the algorithm
- Do NOT copy code from gProxy verbatim — understand it, then rewrite in modern C#
- Do NOT use `Thread.Sleep()`, `Task.Result`, or any blocking calls
- Do NOT add features from later phases prematurely
- Do NOT use `unsafe` code unless absolutely necessary and documented

## Reference: gProxy Protocol Knowledge (5xxx)

The original gProxy at `F:\Later\AI Co Path\gProxy-master\` contains:

| What | Where | Use |
|------|-------|-----|
| Packet IDs + field offsets | `gProxy/gClient.cpp` switch cases | Compare against 7xxx captures |
| Blowfish + DH implementation | `gProxy/GameCryptography.cpp`, `DiffieHellman.cpp` | Reference for ICipher if server uses same crypto |
| Handshake sequence | `gProxy/Handshake.h`, `HandshakeReply.h` | Compare against 7xxx handshake |
| Enums (already copied) | `gProxyAPI/*.cs` | In `Sentinel.Core/Enums/` |
| A* Pathfinding | `gProxyAPI/Algorithms/PathFinder.cs` | Port to `Sentinel.Core/Algorithms/` in Phase 4 |
| Event model | `gProxyAPI/Events.cs` | Redesign as C# events on GameSession |
| GameClient API | `gProxyAPI/GameClient.cs` | Reference for IGameClient interface in Phase 5 |
| Known Blowfish key | `"DR654dt34trg4UI6"` | Test against 7xxx traffic — some private servers still use it |
| Known DH parameters | In `DiffieHellman.cpp` | Test against 7xxx handshake |
