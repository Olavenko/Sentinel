using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Models;

namespace Sentinel.Network.Keys;

/// <summary>
/// Proxy-only supervisor for the per-PID CAST5 Frida keyfeed. When enabled (Auto-spawn on, and at
/// least one endpoint decrypting CAST5 gameplay), the operator only starts the proxy: this class
/// reconciles live game processes against running Frida children on a periodic tick, spawning one
/// child per game client (<c>frida -p &lt;pid&gt; -l &lt;script&gt; --runtime=v8 -q -t inf</c>) so each
/// Conquer.exe writes its own <c>game-session-&lt;pid&gt;.key.json</c>.
/// <para>
/// Lifecycle rules:
/// <list type="bullet">
/// <item>A key file is deleted ONLY when its game process exits (the reap step). A bare Frida-child
/// crash with the game still alive is respawned and the live key is preserved.</item>
/// <item>Rapid (sub-<c>HealthyUptimeSeconds</c>) crashes for one PID are backed off exponentially
/// and, past <c>MaxRapidRespawns</c>, the PID is circuit-broken (no further respawns) so a wedged
/// target can't spin.</item>
/// <item>On shutdown every child is killed but NO key file is deleted — proxy shutdown is not a
/// game exit, so live keys persist for the next run.</item>
/// </list>
/// Fully async (a <see cref="PeriodicTimer"/> loop, no blocking) and observation-only at the cipher
/// boundary — it merely launches the script the proxy already relies on.
/// </para>
/// </summary>
public sealed class KeyfeedSupervisor : IDisposable
{
    private const int BaseBackoffSeconds = 2;
    private const int MaxBackoffSeconds = 30;
    private const int MinPollIntervalMs = 250;

    private readonly KeyfeedConfig _config;
    private readonly string _keysDirectory;
    private readonly ILogger<KeyfeedSupervisor> _logger;

    private readonly string _processBaseName; // "Conquer" — no extension, for GetProcessesByName
    private readonly string _scriptPath;      // resolved absolute
    private readonly string _outputDir;       // resolved absolute

    // Supervised state, keyed by the GAME process PID. Touched only under _gate (the reconcile tick
    // and Dispose serialize through it); the per-child stdout pump serializes on its own log lock.
    private readonly Dictionary<int, Child> _children = new();
    private readonly object _gate = new();
    private bool _disposed;

    public KeyfeedSupervisor(KeyfeedConfig config, string keysDirectory, ILogger<KeyfeedSupervisor> logger)
    {
        _config = config;
        _keysDirectory = keysDirectory;
        _logger = logger;

        var processName = string.IsNullOrWhiteSpace(config.ProcessName) ? "Conquer.exe" : config.ProcessName;
        _processBaseName = Path.GetFileNameWithoutExtension(processName);
        _scriptPath = Path.GetFullPath(
            string.IsNullOrWhiteSpace(config.ScriptPath) ? "tools/frida_v22_keyfeed.js" : config.ScriptPath);
        _outputDir = Path.GetFullPath(
            string.IsNullOrWhiteSpace(config.OutputLogPath) ? "logs/keyfeed" : config.OutputLogPath);
    }

    /// <summary>
    /// Run the reconcile loop until cancellation. Validates the script once up front (an absent
    /// script would make every spawn fail), then reconciles immediately and on each tick.
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        if (!File.Exists(_scriptPath))
        {
            _logger.LogError(
                "Keyfeed AutoSpawn is ON but the Frida script was not found at '{Script}'. The " +
                "supervisor is inert — fix Proxy:Keyfeed:ScriptPath. No game clients will be auto-attached.",
                _scriptPath);
            return;
        }

        try { Directory.CreateDirectory(_outputDir); }
        catch (Exception ex) { _logger.LogWarning(ex, "Could not create keyfeed log directory {Dir}", _outputDir); }

        var interval = TimeSpan.FromMilliseconds(Math.Max(MinPollIntervalMs, _config.PollIntervalMs));
        _logger.LogInformation(
            "Keyfeed supervisor started: scanning for '{Process}' every {Interval}ms (frida='{Frida}', " +
            "script='{Script}'). Key files are deleted ONLY when a game process exits.",
            _processBaseName, (int)interval.TotalMilliseconds, _config.FridaPath, _scriptPath);

        using var timer = new PeriodicTimer(interval);
        try
        {
            TickSafely();
            while (await timer.WaitForNextTickAsync(ct))
                TickSafely();
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown — children are killed in Dispose.
        }
    }

    /// <summary>
    /// Run one reconcile tick, containing any unexpected throw so a single bad tick (e.g. an
    /// <see cref="Process.HasExited"/> that throws under load) can never terminate the supervisor
    /// loop or surface as an unobserved fault at host shutdown.
    /// </summary>
    private void TickSafely()
    {
        try
        {
            Reconcile();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Keyfeed supervisor reconcile tick failed; continuing on the next tick");
        }
    }

    private void Reconcile()
    {
        lock (_gate)
        {
            if (_disposed) return;

            var live = GetLiveGamePids();
            if (live is null) return; // enumeration failed: never reap/delete on an unknown snapshot
            var now = DateTimeOffset.UtcNow;

            // 1. Reap supervised PIDs whose game process is gone. This — and ONLY this — deletes the
            //    key file.
            foreach (var pid in _children.Keys.ToList())
            {
                if (live.Contains(pid)) continue;
                ReapGameExited(pid);
            }

            // 2. Ensure every live game PID has a running Frida child, honoring backoff + circuit-break.
            foreach (var pid in live)
            {
                if (!_children.TryGetValue(pid, out var c))
                {
                    c = new Child(pid);
                    _children[pid] = c;
                }

                if (c.CircuitBroken) continue;

                if (c.Process is { } proc)
                {
                    if (!proc.HasExited) continue; // healthy: still feeding keys
                    // Child died while the game is still alive — account for it, then maybe respawn.
                    // The key file is left untouched.
                    AccountForChildExit(c, now);
                    if (c.CircuitBroken) continue;
                }

                if (now < c.NextEligibleUtc) continue; // inside the backoff window
                SpawnChild(c, now);
            }
        }
    }

    /// <summary>Game process for <paramref name="pid"/> is gone: kill its child and delete its key.</summary>
    private void ReapGameExited(int pid)
    {
        if (!_children.Remove(pid, out var c)) return;
        KillChildProcess(c);
        c.DisposeLog();
        DeleteKeyFile(pid);
        _logger.LogInformation(
            "Game pid {Pid} exited — killed its Frida child and deleted key file game-session-{Pid}.key.json.",
            pid, pid);
    }

    /// <summary>Update crash bookkeeping when a child exited while its game is still alive.</summary>
    private void AccountForChildExit(Child c, DateTimeOffset now)
    {
        var uptime = now - c.StartedUtc;
        var exitCode = TryGetExitCode(c.Process);

        if (uptime >= TimeSpan.FromSeconds(Math.Max(1, _config.HealthyUptimeSeconds)))
            c.RapidRespawns = 0;   // ran healthily for a while; treat the death as a fresh restart
        else
            c.RapidRespawns++;

        DisposeChildProcess(c);    // release the handle + close the stdout log; keep the supervised entry

        var backoff = ComputeBackoff(c.RapidRespawns);
        c.NextEligibleUtc = now + backoff;

        if (c.RapidRespawns >= Math.Max(1, _config.MaxRapidRespawns))
        {
            c.CircuitBroken = true;
            _logger.LogError(
                "Frida child for game pid {Pid} exited {N} times in rapid succession (last uptime {Up:F1}s, exit {Code}). " +
                "Giving up auto-respawn for this PID; its live key file (if any) is preserved.",
                c.Pid, c.RapidRespawns, uptime.TotalSeconds, exitCode);
            return;
        }

        _logger.LogWarning(
            "Frida child for game pid {Pid} exited (uptime {Up:F1}s, exit {Code}); respawn #{N} in {Backoff}s. " +
            "Key file preserved (game still alive).",
            c.Pid, uptime.TotalSeconds, exitCode, c.RapidRespawns, (int)backoff.TotalSeconds);
    }

    private void SpawnChild(Child c, DateTimeOffset now)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _config.FridaPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        // ArgumentList quotes each token, so a script path with spaces is safe.
        psi.ArgumentList.Add("-p");
        psi.ArgumentList.Add(c.Pid.ToString());
        psi.ArgumentList.Add("-l");
        psi.ArgumentList.Add(_scriptPath);
        psi.ArgumentList.Add("--runtime=v8");
        psi.ArgumentList.Add("-q");           // quiet: no REPL banner, clean stdout
        psi.ArgumentList.Add("-t");
        psi.ArgumentList.Add("inf");          // run forever; the child dies when the game exits or we kill it

        Process? proc;
        try
        {
            proc = Process.Start(psi);
        }
        catch (Win32Exception ex)
        {
            // Distinguish persistent config faults from transient launch failures. File-not-found (2),
            // path-not-found (3) and access-denied (5) won't fix themselves, so circuit-break this PID
            // with an actionable message. Any other native code (out-of-memory, AV/sharing locks, …)
            // may clear, so fall through to ordinary backoff instead of permanently disabling the PID.
            if (ex.NativeErrorCode is 2 or 3 or 5)
            {
                c.CircuitBroken = true;
                _logger.LogError(ex,
                    "Cannot start Frida ('{Frida}') to attach to game pid {Pid}: {Msg} (win32 {Code}). " +
                    "Auto-spawn disabled for this PID — fix Proxy:Keyfeed:FridaPath (run elevated if access is denied).",
                    _config.FridaPath, c.Pid, ex.Message, ex.NativeErrorCode);
                return;
            }

            c.RapidRespawns++;
            c.NextEligibleUtc = now + ComputeBackoff(c.RapidRespawns);
            _logger.LogError(ex,
                "Transient failure starting Frida for game pid {Pid}: {Msg} (win32 {Code}); retrying with backoff",
                c.Pid, ex.Message, ex.NativeErrorCode);
            return;
        }
        catch (Exception ex)
        {
            c.RapidRespawns++;
            c.NextEligibleUtc = now + ComputeBackoff(c.RapidRespawns);
            _logger.LogError(ex, "Failed to start Frida child for game pid {Pid}", c.Pid);
            return;
        }

        if (proc is null)
        {
            c.RapidRespawns++;
            c.NextEligibleUtc = now + ComputeBackoff(c.RapidRespawns);
            _logger.LogError("Process.Start returned no Frida child for game pid {Pid}", c.Pid);
            return;
        }

        var logPath = Path.Combine(_outputDir, $"keyfeed-{c.Pid}.log");
        c.OpenLog(logPath);
        proc.OutputDataReceived += (_, e) => c.OnChildLine(e.Data, _logger);
        proc.ErrorDataReceived += (_, e) => c.OnChildLine(e.Data, _logger);
        try
        {
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
        }
        catch
        {
            // The child can race to exit before the readers attach; the next tick will respawn it.
        }

        c.Process = proc;
        c.StartedUtc = now;
        _logger.LogInformation(
            "Spawned Frida keyfeed child for game pid {Pid} (frida pid {ChildPid}); stdout → {Log}",
            c.Pid, SafeChildPid(proc), logPath);
    }

    /// <summary>
    /// Snapshot of live game PIDs, or <see langword="null"/> if the enumeration itself FAILED. The
    /// null is load-bearing: an empty set legitimately authorizes reaping every supervised PID, so a
    /// transient <see cref="Process.GetProcessesByName(string)"/> failure must NOT collapse into an
    /// empty set (that would delete every live account's key). The caller skips the whole tick on null.
    /// </summary>
    private HashSet<int>? GetLiveGamePids()
    {
        Process[] procs;
        try
        {
            procs = Process.GetProcessesByName(_processBaseName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to enumerate '{Process}' processes — skipping this reconcile tick (no reap, no spawn) " +
                "so a transient enumeration failure can never delete a live key file",
                _processBaseName);
            return null;
        }

        try { return procs.Select(p => p.Id).ToHashSet(); }
        finally { foreach (var p in procs) p.Dispose(); }
    }

    private void DeleteKeyFile(int pid)
    {
        var path = Path.Combine(_keysDirectory, $"game-session-{pid}.key.json");
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete key file {Path} after game exit", path);
        }
    }

    private static TimeSpan ComputeBackoff(int rapidRespawns)
    {
        var seconds = Math.Min(MaxBackoffSeconds, BaseBackoffSeconds * Math.Pow(2, Math.Max(0, rapidRespawns - 1)));
        return TimeSpan.FromSeconds(seconds);
    }

    private static string TryGetExitCode(Process? proc)
    {
        try { return proc is { HasExited: true } ? proc.ExitCode.ToString() : "?"; }
        catch { return "?"; }
    }

    private static int SafeChildPid(Process proc)
    {
        try { return proc.Id; }
        catch { return -1; }
    }

    /// <summary>Kill a child (used on reap and shutdown) and release its handle.</summary>
    private static void KillChildProcess(Child c)
    {
        var proc = c.Process;
        c.Process = null;
        if (proc is null) return;
        try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
        catch { /* already exited / access race */ }
        try { proc.Dispose(); } catch { /* best effort */ }
    }

    /// <summary>Release a child's handle + log without killing (the process already exited on its own).</summary>
    private static void DisposeChildProcess(Child c)
    {
        var proc = c.Process;
        c.Process = null;
        if (proc is not null) { try { proc.Dispose(); } catch { /* best effort */ } }
        c.DisposeLog();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var c in _children.Values)
            {
                KillChildProcess(c);
                c.DisposeLog();
            }
            _children.Clear();
            // Key files are intentionally NOT deleted here: proxy shutdown is not a game exit
            // (lifecycle rule), so live keys persist for the next run.
        }
    }

    /// <summary>Per-game-PID supervised child: the Frida process, its crash bookkeeping, and a
    /// thread-safe pump of its stdout/stderr to a per-PID log file.</summary>
    private sealed class Child(int pid)
    {
        private readonly object _logSync = new();
        private StreamWriter? _log;
        private bool _loggedLive;

        public int Pid { get; } = pid;
        public Process? Process { get; set; }
        public DateTimeOffset StartedUtc { get; set; }
        public int RapidRespawns { get; set; }
        public DateTimeOffset NextEligibleUtc { get; set; }
        public bool CircuitBroken { get; set; }

        public void OpenLog(string path)
        {
            lock (_logSync)
            {
                try
                {
                    _log = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
                    {
                        AutoFlush = true,
                    };
                }
                catch { _log = null; }
                _loggedLive = false;
            }
        }

        public void OnChildLine(string? line, ILogger logger)
        {
            if (string.IsNullOrEmpty(line)) return;
            lock (_logSync)
            {
                try { _log?.WriteLine(line); } catch { /* log file vanished mid-write */ }
                if (!_loggedLive)
                {
                    _loggedLive = true;
                    logger.LogInformation("Frida child for game pid {Pid} is live: {Line}", Pid, line);
                }
            }
        }

        public void DisposeLog()
        {
            lock (_logSync)
            {
                try { _log?.Dispose(); } catch { /* best effort */ }
                _log = null;
            }
        }
    }
}
