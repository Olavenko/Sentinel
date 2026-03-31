# Sentinel Codebase Overview

This document provides a high-level overview of the Sentinel project, its architecture, and the role of each project within the solution.

## Architecture Summary

Sentinel is a proxy-based interception system designed for the TQ (Conquer Online) protocol. It consists of two main parts:
1.  **Redirection (Hook/Loader):** Native components that intercept the client's connection attempts and redirect them to the local proxy.
2.  **Interception (Proxy):** A .NET application that acts as a Man-In-The-Middle (MITM), performing key exchange with both the client and the server to decrypt, log, and potentially modify traffic.

---

## Projects

### 1. Sentinel.Core
**Role:** Shared definitions and interfaces.
- **Dependencies:** None.
- **Key Components:**
    - `IProxyServer` / `IProxySession`: Core abstractions for the proxy logic.
    - `IPacketLogger`: Interface for recording intercepted traffic.
    - `Enums/`: Domain-specific types like `AttackType`, `CharacterClass`, `PacketDirection`, and `SpellId`.

### 2. Sentinel.Network
**Role:** Implementation of the proxy server and session management.
- **Dependencies:** `Sentinel.Core`, `Sentinel.Crypto`.
- **Key Components:**
    - `ProxyServer`: Listens for incoming connections and creates `ProxySession` instances.
    - `ProxySession`: Manages the bidirectional data flow between the client and the server.
        - **MITM Handshake:** Intercepts the TQ Diffie-Hellman handshake to establish shared secrets with both sides.
        - **Relay:** Uses `System.IO.Pipelines` for high-performance data forwarding.
    - `PacketLogger`: Implementation that logs packets to disk/console.

### 3. Sentinel.Crypto
**Role:** Cryptographic primitives and protocol-specific handshake parsing.
- **Dependencies:** `Sentinel.Core`.
- **Key Components:**
    - `BlowfishCfb64Cipher`: Implementation of the Blowfish algorithm in CFB-64 mode, used by the TQ protocol.
    - `DiffieHellman`: Manages key exchange parameters and shared secret computation.
    - `HandshakeParser`: Specifically handles the parsing and rebuilding of the `CHandshake` and `CHandshakeReply` packets used in the TQ protocol.

### 4. Sentinel.Hook (C++)
**Role:** Client-side interception via DLL injection.
- **Platform:** Windows x86 (32-bit).
- **Key Components:**
    - `SentinelHook.cpp`: Uses **MinHook** to hook `ws2_32.dll!connect`.
    - **Logic:** When the game client attempts to connect to a hardcoded server IP, the hook rewrites the destination IP to `127.0.0.1`, forcing the connection through the local Sentinel proxy.

### 5. Sentinel.Loader
**Role:** Injection utility.
- **Dependencies:** None (uses P/Invoke).
- **Key Components:**
    - `Injector.cs`: Handles process discovery and remote thread creation to load `SentinelHook.dll` into the target process (e.g., `Conquer.exe`).

### 6. Sentinel.CLI
**Role:** Main entry point and host.
- **Dependencies:** `Sentinel.Network`, `Sentinel.Core`.
- **Functionality:** 
    - Loads configuration from `appsettings.json`.
    - Configures Dependency Injection (DI) and Logging.
    - Starts the `ProxyServer` to begin listening for redirected connections.

---

## Data Flow

1.  **Startup:** `Sentinel.CLI` starts and begins listening on local ports (e.g., 9958, 5816).
2.  **Injection:** `Sentinel.Loader` injects `SentinelHook.dll` into the game client.
3.  **Redirection:** The game client calls `connect()`. `SentinelHook` intercepts this and changes the destination to `127.0.0.1`.
4.  **Handshake:** 
    - `ProxyServer` accepts the connection and creates a `ProxySession`.
    - `ProxySession` connects to the real server.
    - `ProxySession` performs a MITM DH handshake using `HandshakeParser` and `DiffieHellman`.
5.  **Traffic:** Once keys are established, `ProxySession` uses `BlowfishCfb64Cipher` to decrypt data from one side, logs it via `IPacketLogger`, re-encrypts it for the other side, and forwards it.

## Technical Standards
- **Runtime:** .NET 10.
- **Async:** Fully asynchronous using `Task`, `ValueTask`, and `CancellationToken`.
- **Memory:** Extensive use of `Span<byte>`, `Memory<byte>`, and `ArrayPool<byte>` to minimize allocations.
- **Networking:** `System.IO.Pipelines` for backpressure-aware stream processing.
