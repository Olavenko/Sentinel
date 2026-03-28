using System.Diagnostics;
using System.Runtime.InteropServices;
using static Sentinel.Loader.NativeMethods;

namespace Sentinel.Loader;

internal static class Program
{
    private const string DefaultHookDll = "SentinelHook.dll";
    private const string LauncherName = "play.exe";
    private const string GameProcessName = "Conquer";
    private const int PollIntervalMs = 500;
    private const int MaxWaitSeconds = 120;

    static int Main(string[] args)
    {
        string? launcherPath = args.Length > 0 ? args[0] : null;
        string? hookDll = args.Length > 1 ? args[1] : null;

        if (string.IsNullOrEmpty(launcherPath))
            launcherPath = FindLauncher();

        if (string.IsNullOrEmpty(launcherPath) || !File.Exists(launcherPath))
        {
            Console.Error.WriteLine("Usage: Sentinel.Loader <path\\to\\play.exe> [path\\to\\SentinelHook.dll]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  Launches Play.exe (the CO launcher), waits for it to spawn Conquer.exe,");
            Console.Error.WriteLine("  then injects SentinelHook.dll to redirect game-server connections to 127.0.0.1.");
            return 1;
        }

        string hookDllPath = ResolveHookDllPath(hookDll);
        if (!File.Exists(hookDllPath))
        {
            Console.Error.WriteLine($"Hook DLL not found: {hookDllPath}");
            Console.Error.WriteLine("Build SentinelHook.dll first (see src/Sentinel.Hook/build.bat).");
            return 1;
        }

        hookDllPath = Path.GetFullPath(hookDllPath);
        string launcherDir = Path.GetDirectoryName(Path.GetFullPath(launcherPath))!;

        Console.WriteLine("[Sentinel Loader]");
        Console.WriteLine($"  Launcher: {launcherPath}");
        Console.WriteLine($"  Hook DLL: {hookDllPath}");
        Console.WriteLine();

        // Snapshot existing Conquer.exe PIDs so we can detect the new one
        var existingPids = new HashSet<int>(
            Process.GetProcessesByName(GameProcessName).Select(p => p.Id));

        if (existingPids.Count > 0)
            Console.WriteLine($"  Note: {existingPids.Count} existing Conquer.exe process(es) will be ignored.");

        // Step 1: Launch Play.exe normally
        Console.WriteLine("[1] Launching Play.exe...");

        var psi = new ProcessStartInfo
        {
            FileName = launcherPath,
            WorkingDirectory = launcherDir,
            UseShellExecute = true,
        };

        Process? launcher;
        try
        {
            launcher = Process.Start(psi);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  Failed to start launcher: {ex.Message}");
            Console.Error.WriteLine("  Try running as Administrator.");
            return 1;
        }

        if (launcher is null)
        {
            Console.Error.WriteLine("  Process.Start returned null.");
            return 1;
        }

        Console.WriteLine($"  Launcher PID: {launcher.Id}");
        Console.WriteLine();

        // Step 2: Poll for Conquer.exe
        Console.WriteLine($"[2] Waiting for Conquer.exe to appear (polling every {PollIntervalMs}ms, timeout {MaxWaitSeconds}s)...");

        Process? gameProcess = null;
        var sw = Stopwatch.StartNew();

        while (sw.Elapsed.TotalSeconds < MaxWaitSeconds)
        {
            Thread.Sleep(PollIntervalMs);

            foreach (var proc in Process.GetProcessesByName(GameProcessName))
            {
                if (!existingPids.Contains(proc.Id))
                {
                    gameProcess = proc;
                    break;
                }

                proc.Dispose();
            }

            if (gameProcess is not null)
                break;

            // Animate a simple progress indicator
            double elapsed = sw.Elapsed.TotalSeconds;
            Console.Write($"\r  Waiting... {elapsed:F0}s");
        }

        Console.WriteLine(); // clear the progress line

        if (gameProcess is null)
        {
            Console.Error.WriteLine($"  Conquer.exe did not appear within {MaxWaitSeconds} seconds.");
            Console.Error.WriteLine("  Make sure the launcher is working and actually starts the game.");
            return 1;
        }

        Console.WriteLine($"  Found Conquer.exe — PID: {gameProcess.Id}");
        Console.WriteLine();

        // Step 3: Inject hook DLL into Conquer.exe
        Console.WriteLine("[3] Injecting SentinelHook.dll into Conquer.exe...");

        nint hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)gameProcess.Id);
        if (hProcess == 0)
        {
            Console.Error.WriteLine($"  OpenProcess failed (0x{Marshal.GetLastWin32Error():X8})");
            Console.Error.WriteLine("  Try running as Administrator.");
            return 1;
        }

        try
        {
            if (!Injector.InjectDll(hProcess, hookDllPath))
            {
                Console.Error.WriteLine("  Injection failed.");
                return 1;
            }
        }
        finally
        {
            CloseHandle(hProcess);
        }

        Console.WriteLine("  Injected successfully.");
        Console.WriteLine();
        Console.WriteLine("Conquer.exe is running with Sentinel hook active.");
        Console.WriteLine("All game-server connections will be redirected to 127.0.0.1.");
        Console.WriteLine($"Check SentinelHook.log in the game directory for redirect logs.");
        Console.WriteLine();
        Console.WriteLine("Waiting for Conquer.exe to exit (Ctrl+C to detach)...");

        try
        {
            gameProcess.WaitForExit();
            Console.WriteLine("Conquer.exe has exited.");
        }
        catch (InvalidOperationException)
        {
            Console.WriteLine("Conquer.exe process is no longer accessible.");
        }

        gameProcess.Dispose();
        return 0;
    }

    private static string? FindLauncher()
    {
        string[] candidates =
        [
            @"F:\TQ\play.exe",
            @".\play.exe",
            @"..\play.exe",
        ];

        foreach (string path in candidates)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    private static string ResolveHookDllPath(string? hookDll)
    {
        if (!string.IsNullOrEmpty(hookDll))
            return hookDll;

        string[] candidates =
        [
            DefaultHookDll,
            Path.Combine(AppContext.BaseDirectory, DefaultHookDll),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Sentinel.Hook", "build", DefaultHookDll),
        ];

        foreach (string path in candidates)
        {
            if (File.Exists(path))
                return path;
        }

        return DefaultHookDll;
    }
}
