# Sentinel

A modern Conquer Online proxy/bot built with .NET 10 and C# 14. Sentinel sits between the CO game client and server, intercepting and logging all network traffic. The long-term goal is a full-featured bot with decrypted packet parsing, a plugin system, and an optional UI layer.

**Target:** Modern CO private servers (patch 7xxx+, 2026 era).

## Features (Phase 1)

- Transparent TCP proxy — the game client connects through Sentinel without knowing it exists
- Configurable listen/remote ports for auth and game endpoints
- Bidirectional byte forwarding using `System.IO.Pipelines`
- Live console logging with hex previews (timestamp, direction, size, 32-byte hex)
- Binary log files per session saved to `logs/`
- Graceful disconnect handling from both client and server
- Multiple simultaneous sessions

## Architecture

```
Sentinel/
├── Sentinel.slnx
├── src/
│   ├── Sentinel.Core/          — Interfaces, enums, domain types (zero dependencies)
│   ├── Sentinel.Crypto/        — ICipher, IKeyExchange interfaces + implementations
│   ├── Sentinel.Network/       — TCP proxy, session management, packet logging
│   └── Sentinel.CLI/           — Console app entry point
├── tests/
│   └── Sentinel.Network.Tests/ — xUnit test project
└── tools/                      — Analysis tooling (Phase 2+)
```

**Dependency graph:** `CLI → Network → Core`, `Network → Crypto → Core`. Core has zero external dependencies. This layering is strict — no upward dependencies.

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download)

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/Sentinel.git
   cd Sentinel
   ```

2. Update `src/Sentinel.CLI/appsettings.json` with your CO server IP and ports:

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

3. Build and run:

   ```bash
   dotnet build
   dotnet run --project src/Sentinel.CLI
   ```

   Run as Administrator if needed for port binding.

4. Point your CO client to `127.0.0.1:9959` instead of the real server.

## Running Tests

```bash
dotnet test
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | .NET 10 |
| Language | C# 14 |
| Networking | System.IO.Pipelines |
| DI | Microsoft.Extensions.DependencyInjection |
| Configuration | Microsoft.Extensions.Options + appsettings.json |
| Logging | Microsoft.Extensions.Logging |
| Testing | xUnit |

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation + Transparent Proxy | Done |
| 2 | Capture, Analysis & Reverse Engineering | Not Started |
| 3 | Encryption Implementation | Not Started |
| 4 | Packet Parsing + Game State | Not Started |
| 5 | Plugin API + Bot Features | Not Started |
| 6 | Full Bot Suite | Not Started |
| 7 | UI Layer | Not Started |

See [ROADMAP.md](ROADMAP.md) for the full development plan.

## License

All rights reserved.
