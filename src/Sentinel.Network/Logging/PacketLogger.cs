using System.Buffers;
using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Core.Enums;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;

namespace Sentinel.Network.Logging;

/// <summary>
/// Logs raw packet data to binary files (one per session) and optionally to console.
///
/// Binary file format per entry:
///   [8 bytes] timestamp (UTC ticks, little-endian Int64)
///   [1 byte]  direction (0 = C→S, 1 = S→C)
///   [4 bytes] data length (little-endian Int32)
///   [N bytes] raw packet data
/// </summary>
public sealed class PacketLogger : IPacketLogger
{
    private readonly ILogger<PacketLogger> _logger;
    private readonly bool _logToConsole;
    private readonly string _logDirectory;

    private readonly ConcurrentDictionary<Guid, FileStream> _sessionFiles = new();

    // Reusable header buffer: 8 (timestamp) + 1 (direction) + 4 (length) = 13 bytes
    private const int HeaderSize = 13;

    public PacketLogger(IOptions<ProxyConfiguration> config, ILogger<PacketLogger> logger)
    {
        _logger = logger;
        _logToConsole = config.Value.LogToConsole;
        _logDirectory = config.Value.LogDirectory;

        Directory.CreateDirectory(_logDirectory);
    }

    public async ValueTask LogPacketAsync(
        Guid sessionId,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        if (data.Length == 0)
            return;

        // Write to binary file
        var stream = GetOrCreateSessionFile(sessionId);
        await WriteBinaryEntryAsync(stream, direction, data, timestamp);

        // Write to console
        if (_logToConsole)
            WriteConsoleEntry(sessionId, direction, data, timestamp);
    }

    public async ValueTask FlushAsync()
    {
        foreach (var stream in _sessionFiles.Values)
        {
            try { await stream.FlushAsync(); } catch { }
        }
    }

    private FileStream GetOrCreateSessionFile(Guid sessionId)
    {
        return _sessionFiles.GetOrAdd(sessionId, id =>
        {
            var fileName = $"session_{id:N}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.bin";
            var filePath = Path.Combine(_logDirectory, fileName);
            _logger.LogDebug("Created packet log: {Path}", filePath);
            return new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read,
                bufferSize: 65536, useAsync: true);
        });
    }

    private static async ValueTask WriteBinaryEntryAsync(
        FileStream stream,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        // Write header
        var header = ArrayPool<byte>.Shared.Rent(HeaderSize);
        try
        {
            BitConverter.TryWriteBytes(header.AsSpan(0, 8), timestamp.UtcTicks);
            header[8] = (byte)direction;
            BitConverter.TryWriteBytes(header.AsSpan(9, 4), data.Length);

            await stream.WriteAsync(header.AsMemory(0, HeaderSize));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }

        // Write data
        await stream.WriteAsync(data);
    }

    private static void WriteConsoleEntry(
        Guid sessionId,
        PacketDirection direction,
        ReadOnlyMemory<byte> data,
        DateTimeOffset timestamp)
    {
        var arrow = direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
        var sessionShort = sessionId.ToString()[..8];
        var time = timestamp.ToLocalTime().ToString("HH:mm:ss.fff");

        // Summary line
        var sb = new StringBuilder(128);
        sb.Append($"[{time}] [{sessionShort}] {arrow}  {data.Length,6} bytes");

        // First 32 bytes as hex preview
        var previewLength = Math.Min(data.Length, 32);
        var span = data.Span[..previewLength];

        sb.Append("   ");
        for (var i = 0; i < previewLength; i++)
        {
            sb.Append(span[i].ToString("X2"));
            if (i < previewLength - 1)
                sb.Append(' ');
        }

        if (data.Length > 32)
            sb.Append(" ...");

        Console.WriteLine(sb.ToString());
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var kvp in _sessionFiles)
        {
            try
            {
                await kvp.Value.FlushAsync();
                await kvp.Value.DisposeAsync();
            }
            catch { }
        }
        _sessionFiles.Clear();
    }
}
