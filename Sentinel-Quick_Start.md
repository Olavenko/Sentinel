# Sentinel — How to Run (Phase 3)
# ================================
# Open 3 separate terminals, all from F:\Sentinel

# Terminal 1: Start the Proxy
dotnet run --project src/Sentinel.CLI

# Terminal 2: Start the Loader (waits for game process, then injects hook)
dotnet run --project src/Sentinel.Loader -- "F:\TQ\Play.exe" "src\Sentinel.Hook\build\SentinelHook.dll"

# Terminal 3 (or manually): Launch the game
# Open Play.exe from F:\TQ\ normally

# Order matters:
# 1. Proxy FIRST (must be listening before game connects)
# 2. Loader SECOND (waits for game process)
# 3. Game LAST (Loader injects hook, hook redirects traffic to proxy)