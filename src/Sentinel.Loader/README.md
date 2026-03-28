# Sentinel Loader

Launches Conquer Online (patch 7xxx) with Winsock hooks that redirect all game-server connections to `127.0.0.1`, routing traffic through the Sentinel proxy.

## How It Works

1. **Sentinel.Loader** (C#) creates `Conquer.exe` in a suspended state
2. Injects `SentinelHook.dll` via `CreateRemoteThread` + `LoadLibraryA`
3. Resumes the process — the hook is active before any game code runs

**SentinelHook.dll** (C++/MinHook) hooks `ws2_32.dll!connect()` and rewrites the destination address for known game-server IPs:

| Original IP       | Redirected To |
|-------------------|---------------|
| `170.33.9.35`     | `127.0.0.1`   |
| `121.207.250.57`  | `127.0.0.1`   |

The port is preserved, so Sentinel proxy must listen on the same ports the game expects.

## Prerequisites

- .NET 10 SDK (for the Loader)
- Visual Studio Build Tools with C++ workload (for the Hook DLL)
- Sentinel proxy running on `127.0.0.1` with matching ports

## Building

### Hook DLL (native C++, x86)

From a **Developer Command Prompt for VS**:

```
cd src\Sentinel.Hook
build.bat
```

Output: `src/Sentinel.Hook/build/SentinelHook.dll`

### Loader (C#)

```
dotnet build src/Sentinel.Loader
```

## Usage

1. Start the Sentinel proxy first
2. Copy `SentinelHook.dll` next to the Loader executable, or pass it as the second argument
3. Run:

```
dotnet run --project src/Sentinel.Loader -- "F:\TQ\Env_DX9\Conquer.exe"
```

Or with explicit DLL path:

```
dotnet run --project src/Sentinel.Loader -- "F:\TQ\Env_DX9\Conquer.exe" "path\to\SentinelHook.dll"
```

The Loader will:
- Create Conquer.exe suspended
- Inject the hook DLL
- Resume the process
- Wait for the game to exit

Check `SentinelHook.log` in the game directory for redirect activity.

## Adding More IPs

Edit the `g_redirects` array in `SentinelHook.cpp` and rebuild:

```cpp
static RedirectEntry g_redirects[] = {
    { 0, "170.33.9.35"  },
    { 0, "121.207.250.57" },
    { 0, "1.2.3.4" },        // add new entries here
};
```

## Troubleshooting

- **"CreateProcess failed"** — Run the Loader as Administrator
- **"LoadLibraryA returned NULL"** — Ensure `SentinelHook.dll` is 32-bit and all dependencies (MSVC runtime) are available. The DLL is built with `/MT` (static CRT) to avoid this
- **Game connects but proxy doesn't see traffic** — Verify the proxy is listening on the correct ports; check `SentinelHook.log` for redirect entries
