# Sentinel - Gemini CLI Context

This file provides foundational mandates and technical context for Gemini CLI when working on the **Sentinel** project.

## Foundational Mandates
- **Precedence:** Instructions in this file take absolute precedence over general workflows.
- **Language & Style:** 
    - All code, comments, and documentation MUST be in English.
    - Use **Modern C# 14** features (file-scoped namespaces, primary constructors, pattern matching).
    - **Async Everything:** Use `async`/`await` exclusively. Never use `.Result`, `.Wait()`, or `Thread.Sleep()`.
    - **Memory Efficiency:** Prefer `Span<T>` and `Memory<T>` over `byte[]`. Use `ArrayPool<byte>` for temporary buffers.
- **Dependency Integrity:** Adhere to the strict layering: `CLI -> Network -> Core` and `Network -> Crypto -> Core`. **Never add upward dependencies.**
- **UI-Agnosticism:** Core, Crypto, Network, and GameState layers must have NO dependencies on any UI framework.
- **No Warnings:** Maintain a codebase with zero build warnings.

## Technical Context
- **Runtime:** .NET 10
- **Language:** C# 14
- **Networking:** `System.IO.Pipelines`, `TcpListener`, `TcpClient`.
- **DI:** `Microsoft.Extensions.DependencyInjection`.
- **Configuration:** `Microsoft.Extensions.Options` + `appsettings.json`.
- **Testing:** xUnit (Naming: `MethodName_Scenario_ExpectedResult`).
- **Native Hooking:** `Sentinel.Hook` (C++/MinHook) and `Sentinel.Loader` (C# Injector) are used for client-side interception.

## Architecture
- **Sentinel.Core:** Interfaces, enums, domain types. Zero external dependencies.
- **Sentinel.Crypto:** `ICipher` and `IKeyExchange` abstractions and implementations.
- **Sentinel.Network:** TCP proxy, session management (`IProxySession`), packet logging (`IPacketLogger`).
- **Sentinel.Hook/Loader:** Native components for hooking the Conquer Online client.
- **Sentinel.CLI:** Thin console presentation layer.

## Development Workflows
- **Build:** `dotnet build`
- **Run CLI:** `dotnet run --project src/Sentinel.CLI`
- **Test:** `dotnet test`
- **Hook Build:** `cd src/Sentinel.Hook && build.bat` (Requires MSVC/CMake)

## Constraints & "What NOT to Do"
- **Do NOT** implement encryption before RE phase confirms the algorithm.
- **Do NOT** copy code from `gProxy` verbatim; rewrite using modern C# idioms.
- **Do NOT** add features from later roadmap phases prematurely.
- **Do NOT** use `unsafe` code unless absolutely necessary and documented.
- **Do NOT** add UI references to non-presentation projects.
