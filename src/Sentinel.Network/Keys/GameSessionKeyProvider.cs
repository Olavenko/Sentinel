using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Sentinel.Crypto;

namespace Sentinel.Network.Keys;

/// <summary>
/// Watches the <c>keys\</c> directory for per-PID Frida keyfeed files
/// (<c>game-session-&lt;pid&gt;.key.json</c>) and exposes every live key as a
/// <see cref="Candidates"/> snapshot. Each Conquer.exe client contributes its own
/// file (written atomically by the keyfeed via temp + rename), so several accounts
/// can be active at once; a connection is bound to the right key by content-matching
/// (length → seal), never by PID. Events are debounced PER FILE (a separate timer per
/// path) so two files written within the debounce window never cancel each other's
/// reload. A relogin reuses the same PID's file, so its dictionary entry is replaced
/// in place; a deleted file (e.g. when the supervisor reaps a dead client) removes its
/// entry. <see cref="Current"/> is the most-recently-loaded key, a convenience for the
/// single-account (N=1) path.
/// </summary>
public sealed class GameSessionKeyProvider : IGameSessionKeyProvider, IDisposable
{
    private const int DebounceMs = 60;
    private const string FilePattern = "game-session-*.key.json";
    private const string NamePrefix = "game-session-";
    private const string NameSuffix = ".key.json";

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly string _dir;
    private readonly ILogger<GameSessionKeyProvider> _logger;
    private readonly FileSystemWatcher _watcher;

    // One entry per live keyfeed file, keyed by the producing Conquer.exe PID.
    private readonly ConcurrentDictionary<int, GameSessionKey> _byPid = new();
    // Per-file debounce timers (keyed by full path) so distinct files never coalesce.
    private readonly ConcurrentDictionary<string, Timer> _debouncers = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private bool _disposed;

    private volatile GameSessionKey? _current;
    public GameSessionKey? Current => _current;

    public IReadOnlyCollection<GameSessionKey> Candidates => _byPid.Values.ToArray();

    public event Action<GameSessionKey>? KeyChanged;

    public GameSessionKeyProvider(string path, ILogger<GameSessionKeyProvider> logger)
    {
        _logger = logger;

        // The configured GameSessionKeyPath is a path whose DIRECTORY is the keys
        // folder; we watch that whole directory for per-PID files rather than one fixed
        // file. The file-name component (if any) is only used to locate the directory.
        var resolved = Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
        _dir = (Path.HasExtension(resolved) ? Path.GetDirectoryName(resolved) : resolved) ?? resolved;
        Directory.CreateDirectory(_dir); // FileSystemWatcher throws if the dir is missing

        // Load any pre-existing key files immediately, then watch for changes.
        foreach (var file in Directory.EnumerateFiles(_dir, FilePattern))
            LoadFile(file, "startup");

        _watcher = new FileSystemWatcher(_dir, FilePattern)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName |
                           NotifyFilters.Size | NotifyFilters.CreationTime,
            EnableRaisingEvents = true,
        };
        _watcher.Created += OnChanged;
        _watcher.Changed += OnChanged;
        _watcher.Renamed += OnChanged;
        _watcher.Deleted += OnChanged; // routed through the same existence-checking reloader

        _logger.LogInformation("Watching game session key directory: {Dir} ({Pattern})", _dir, FilePattern);
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        if (_disposed) return;
        // Per-file debounce: coalesce the burst of events one write/rename/delete
        // produces into a single, settled reload for THAT file. A separate timer per
        // path means two different files written in the same window never cancel each
        // other (no blocking sleeps).
        var path = e.FullPath;
        var timer = _debouncers.GetOrAdd(path,
            p => new Timer(_ => LoadFile(p, "watch"), null, Timeout.Infinite, Timeout.Infinite));
        timer.Change(DebounceMs, Timeout.Infinite);
    }

    /// <summary>
    /// (Re)load a single per-PID key file by path. Existence-checking, so it also
    /// handles deletion: a missing file removes that PID's entry. Upserts on
    /// create/change so a relogin on the same PID replaces the entry in place.
    /// </summary>
    private void LoadFile(string path, string reason)
    {
        lock (_gate)
        {
            if (_disposed) return;

            var pid = PidFromFileName(path);
            if (pid is null) return; // not a game-session-<pid>.key.json file

            try
            {
                if (!File.Exists(path))
                {
                    if (_byPid.TryRemove(pid.Value, out var removed))
                    {
                        RecomputeCurrentAfterRemoval(pid.Value);
                        _logger.LogInformation(
                            "Removed game session key for PID {Pid} (session {Session}) — file deleted; candidates={Count}",
                            pid.Value, removed.SessionId, _byPid.Count);
                    }
                    return;
                }

                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return;

                var key = Parse(json);
                if (key is null) return;

                // The file name's PID is the routing identity; keep the model consistent
                // even if a malformed file omitted the JSON "pid".
                if (key.Pid != pid.Value) key = key with { Pid = pid.Value };

                _byPid[pid.Value] = key; // upsert: relogin on the same PID replaces the entry
                _current = key;          // newest = most recently loaded
                _logger.LogInformation(
                    "Loaded game session key ({Reason}): pid={Pid} session={Session} send_off={SendOff} recv_off={RecvOff} send_ivec={SendReady} recv_ivec={RecvReady}; candidates={Count}",
                    reason, pid.Value, key.SessionId, key.SendSwitchOffset, key.RecvSwitchOffset,
                    key.SendIvec is not null, key.RecvIvec is not null, _byPid.Count);

                KeyChanged?.Invoke(key);
            }
            catch (IOException)
            {
                // File briefly locked mid-rename; the next watcher event (the keyfeed
                // writes several times per session) will retry.
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read/parse game session key file {Path}", path);
            }
        }
    }

    /// <summary>Keep <see cref="Current"/> pointing at a live key after a removal.</summary>
    private void RecomputeCurrentAfterRemoval(int removedPid)
    {
        var cur = _current;
        if (cur is not null && cur.Pid == removedPid)
            _current = _byPid.Values.FirstOrDefault();
    }

    /// <summary>Parse the PID out of a <c>game-session-&lt;pid&gt;.key.json</c> file name.</summary>
    private static int? PidFromFileName(string path)
    {
        var name = Path.GetFileName(path);
        if (!name.StartsWith(NamePrefix, StringComparison.OrdinalIgnoreCase) ||
            !name.EndsWith(NameSuffix, StringComparison.OrdinalIgnoreCase))
            return null;
        var mid = name[NamePrefix.Length..^NameSuffix.Length];
        return int.TryParse(mid, out var pid) ? pid : null;
    }

    private GameSessionKey? Parse(string json)
    {
        var dto = JsonSerializer.Deserialize<KeyFileDto>(json, JsonOptions);
        if (dto?.ScheduleHex is null || dto.ScheduleHex.Length == 0)
            return null; // schedule not written yet → not usable

        uint[] schedule;
        try { schedule = HexUtil.ParseLeDwords(dto.ScheduleHex); }
        catch (FormatException ex) { _logger.LogWarning(ex, "Bad schedule_hex in key file"); return null; }

        if (schedule.Length < 33)
        {
            _logger.LogWarning("Key file schedule has {Count} words, need >= 33", schedule.Length);
            return null;
        }

        var sendIvec = ParseIvec(dto.SendIvecHex, "send");
        var recvIvec = ParseIvec(dto.RecvIvecHex, "recv");

        return new GameSessionKey(
            SessionId: dto.SessionId ?? "unknown",
            Schedule: schedule,
            SendIvec: sendIvec,
            SendNum: dto.SendNum ?? 0,
            SendSwitchOffset: dto.SendSwitchOffset,
            RecvIvec: recvIvec,
            RecvNum: dto.RecvNum ?? 0,
            RecvSwitchOffset: dto.RecvSwitchOffset,
            Pid: dto.Pid);
    }

    private byte[]? ParseIvec(string? hex, string label)
    {
        if (string.IsNullOrEmpty(hex)) return null;
        try
        {
            var b = HexUtil.ParseBytes(hex);
            if (b.Length != 8)
            {
                _logger.LogWarning("Key file {Label}_ivec_hex is {Len} bytes, expected 8", label, b.Length);
                return null;
            }
            return b;
        }
        catch (FormatException ex)
        {
            _logger.LogWarning(ex, "Bad {Label}_ivec_hex in key file", label);
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher.EnableRaisingEvents = false;
        _watcher.Created -= OnChanged;
        _watcher.Changed -= OnChanged;
        _watcher.Renamed -= OnChanged;
        _watcher.Deleted -= OnChanged;
        _watcher.Dispose();
        foreach (var t in _debouncers.Values) t.Dispose();
        _debouncers.Clear();
    }

    private sealed class KeyFileDto
    {
        [JsonPropertyName("pid")] public int? Pid { get; set; }
        [JsonPropertyName("session_id")] public string? SessionId { get; set; }
        [JsonPropertyName("schedule_hex")] public string? ScheduleHex { get; set; }
        [JsonPropertyName("send_ivec_hex")] public string? SendIvecHex { get; set; }
        [JsonPropertyName("recv_ivec_hex")] public string? RecvIvecHex { get; set; }
        [JsonPropertyName("send_num")] public int? SendNum { get; set; }
        [JsonPropertyName("recv_num")] public int? RecvNum { get; set; }
        [JsonPropertyName("send_switch_offset")] public long? SendSwitchOffset { get; set; }
        [JsonPropertyName("recv_switch_offset")] public long? RecvSwitchOffset { get; set; }
    }
}
