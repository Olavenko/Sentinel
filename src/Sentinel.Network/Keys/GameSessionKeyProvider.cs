using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Sentinel.Crypto;

namespace Sentinel.Network.Keys;

/// <summary>
/// Watches the Frida keyfeed file (<c>keys/game-session.key.json</c>) and exposes
/// the latest parsed <see cref="GameSessionKey"/>. The keyfeed rewrites the file
/// atomically (temp + rename) on every new session and on each direction's stream
/// start, so we debounce rapid events and reload on a short, settled delay.
/// </summary>
public sealed class GameSessionKeyProvider : IGameSessionKeyProvider, IDisposable
{
    private const int DebounceMs = 60;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly string _path;
    private readonly ILogger<GameSessionKeyProvider> _logger;
    private readonly FileSystemWatcher _watcher;
    private readonly Timer _debounce;
    private readonly object _gate = new();
    private bool _disposed;

    private volatile GameSessionKey? _current;
    public GameSessionKey? Current => _current;

    // Single-file backing for now (Seam 2): the candidate set is just the current key
    // (0 or 1 element). Seam 3 replaces this with a directory-backed multi-key collection.
    public IReadOnlyCollection<GameSessionKey> Candidates
    {
        get
        {
            var c = _current;
            if (c is null) return [];
            return [c];
        }
    }

    public event Action<GameSessionKey>? KeyChanged;

    public GameSessionKeyProvider(string path, ILogger<GameSessionKeyProvider> logger)
    {
        _logger = logger;
        _path = Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);

        var dir = Path.GetDirectoryName(_path)!;
        var file = Path.GetFileName(_path);
        Directory.CreateDirectory(dir); // FileSystemWatcher throws if the dir is missing

        _debounce = new Timer(_ => Load("watch"), null, Timeout.Infinite, Timeout.Infinite);

        // Load any pre-existing key immediately, then watch for changes.
        Load("startup");

        _watcher = new FileSystemWatcher(dir, file)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName |
                           NotifyFilters.Size | NotifyFilters.CreationTime,
            EnableRaisingEvents = true,
        };
        _watcher.Created += OnChanged;
        _watcher.Changed += OnChanged;
        _watcher.Renamed += OnChanged;

        _logger.LogInformation("Watching game session key file: {Path}", _path);
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        // Coalesce the burst of events a write/rename produces into a single,
        // settled reload (no blocking sleeps).
        if (!_disposed) _debounce.Change(DebounceMs, Timeout.Infinite);
    }

    private void Load(string reason)
    {
        lock (_gate)
        {
            if (_disposed) return;
            try
            {
                if (!File.Exists(_path)) return;
                var json = File.ReadAllText(_path);
                if (string.IsNullOrWhiteSpace(json)) return;

                var key = Parse(json);
                if (key is null) return;

                _current = key;
                _logger.LogInformation(
                    "Loaded game session key ({Reason}): session={Session} send_off={SendOff} recv_off={RecvOff} send_ivec={SendReady} recv_ivec={RecvReady}",
                    reason, key.SessionId, key.SendSwitchOffset, key.RecvSwitchOffset,
                    key.SendIvec is not null, key.RecvIvec is not null);

                KeyChanged?.Invoke(key);
            }
            catch (IOException)
            {
                // File briefly locked mid-rename; the next watcher event (the keyfeed
                // writes several times per session) will retry.
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read/parse game session key file {Path}", _path);
            }
        }
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
        _watcher.Dispose();
        _debounce.Dispose();
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
