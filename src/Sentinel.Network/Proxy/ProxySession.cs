using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Enums;
using Sentinel.Core.Interfaces;

namespace Sentinel.Network.Proxy;

/// <summary>
/// A single proxied connection between a game client and the remote server.
/// Forwards all bytes bidirectionally using System.IO.Pipelines.
/// </summary>
public sealed class ProxySession : IProxySession
{
    private readonly TcpClient _client;
    private readonly TcpClient _server;
    private readonly IPacketLogger _packetLogger;
    private readonly ILogger<ProxySession> _logger;
    private readonly string _endpointName;

    private long _bytesToServer;
    private long _bytesToClient;
    private long _packetsToServer;
    private long _packetsToClient;
    private bool _isActive;

    public Guid Id { get; } = Guid.NewGuid();
    public DateTimeOffset ConnectedAt { get; } = DateTimeOffset.UtcNow;
    public bool IsActive => _isActive;
    public long BytesSentToServer => Interlocked.Read(ref _bytesToServer);
    public long BytesSentToClient => Interlocked.Read(ref _bytesToClient);
    public long PacketsSentToServer => Interlocked.Read(ref _packetsToServer);
    public long PacketsSentToClient => Interlocked.Read(ref _packetsToClient);
    public string EndpointName => _endpointName;

    public event Action<IProxySession, Exception?>? Disconnected;

    public ProxySession(
        TcpClient client,
        TcpClient server,
        IPacketLogger packetLogger,
        ILogger<ProxySession> logger,
        string endpointName)
    {
        _client = client;
        _server = server;
        _packetLogger = packetLogger;
        _logger = logger;
        _endpointName = endpointName;
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        _isActive = true;
        Exception? disconnectReason = null;

        try
        {
            var clientStream = _client.GetStream();
            var serverStream = _server.GetStream();

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var clientToServer = ForwardAsync(
                clientStream, serverStream,
                PacketDirection.ClientToServer,
                linkedCts.Token);

            var serverToClient = ForwardAsync(
                serverStream, clientStream,
                PacketDirection.ServerToClient,
                linkedCts.Token);

            // Wait for the first direction to finish (one side stopped sending).
            // Do NOT cancel the other direction — it may still have data in flight
            // (e.g. client sends HTTP request then closes write side; server response
            //  hasn't arrived yet).
            var first = await Task.WhenAny(clientToServer, serverToClient);

            // TCP half-close: signal the other side that no more data is coming
            // from this direction, without tearing down the full connection.
            if (first == clientToServer)
                try { _server.Client.Shutdown(SocketShutdown.Send); } catch { }
            else
                try { _client.Client.Shutdown(SocketShutdown.Send); } catch { }

            // Now wait for the remaining direction to complete naturally
            try { await clientToServer; } catch (OperationCanceledException) { }
            try { await serverToClient; } catch (OperationCanceledException) { }

            if (clientToServer.IsFaulted)
                disconnectReason = clientToServer.Exception?.InnerException;
            else if (serverToClient.IsFaulted)
                disconnectReason = serverToClient.Exception?.InnerException;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            disconnectReason = ex;
        }
        finally
        {
            _isActive = false;
            await _packetLogger.FlushAsync();
            Disconnected?.Invoke(this, disconnectReason);
        }
    }

    /// <summary>
    /// Forward all data from source to destination, logging each chunk.
    /// Uses PipeReader for efficient buffered reads from the source stream.
    /// </summary>
    private async Task ForwardAsync(
        NetworkStream source,
        NetworkStream destination,
        PacketDirection direction,
        CancellationToken ct)
    {
        var dirLabel = direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
        _logger.LogDebug("[{Endpoint}] {Dir} relay started", _endpointName, dirLabel);

        var reader = PipeReader.Create(source, new StreamPipeReaderOptions(
            bufferSize: 8192,
            leaveOpen: true));

        try
        {
            while (true)
            {
                var result = await reader.ReadAsync(ct);
                var buffer = result.Buffer;

                if (buffer.Length > 0)
                {
                    var timestamp = DateTimeOffset.UtcNow;

                    // Process each segment in the buffer
                    foreach (var segment in buffer)
                    {
                        // Count bytes and packets per segment
                        if (direction == PacketDirection.ClientToServer)
                        {
                            Interlocked.Add(ref _bytesToServer, segment.Length);
                            Interlocked.Increment(ref _packetsToServer);
                        }
                        else
                        {
                            Interlocked.Add(ref _bytesToClient, segment.Length);
                            Interlocked.Increment(ref _packetsToClient);
                        }
                        // Logging must never kill the relay
                        try
                        {
                            await _packetLogger.LogPacketAsync(Id, direction, segment, timestamp);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex,
                                "[{Endpoint}] {Dir} packet logging failed ({Bytes} bytes)",
                                _endpointName, dirLabel, segment.Length);
                        }

                        // [DIAGNOSTIC] Scan for IPs and protocol detection — remove after rewrite phase
                        DiagnosticScanPacket(direction, segment);

                        await destination.WriteAsync(segment, ct);
                    }
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                {
                    _logger.LogDebug("[{Endpoint}] {Dir} stream completed (remote closed)",
                        _endpointName, dirLabel);
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("[{Endpoint}] {Dir} relay cancelled", _endpointName, dirLabel);
            throw;
        }
        catch (IOException ex)
        {
            _logger.LogDebug("[{Endpoint}] {Dir} relay ended — IOException: {Message}",
                _endpointName, dirLabel, ex.Message);
        }
        catch (SocketException ex)
        {
            _logger.LogDebug("[{Endpoint}] {Dir} relay ended — SocketException: {Message}",
                _endpointName, dirLabel, ex.Message);
        }
        finally
        {
            await reader.CompleteAsync();
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // DIAGNOSTIC — IP detection & protocol sniffing (temporary, remove after rewrite phase)
    // ═══════════════════════════════════════════════════════════════════

    // Game server: 170.33.9.35
    private static readonly byte[] GameIpAscii = "170.33.9.35"u8.ToArray();
    private static readonly byte[] GameIpBinary = [0xAA, 0x21, 0x09, 0x23];

    // Auth server: 121.207.250.57
    private static readonly byte[] AuthIpAscii = "121.207.250.57"u8.ToArray();
    private static readonly byte[] AuthIpBinary = [0x79, 0xCF, 0xFA, 0x39];

    private void DiagnosticScanPacket(PacketDirection direction, ReadOnlyMemory<byte> data)
    {
        try
        {
            var span = data.Span;
            if (span.Length == 0) return;

            if (direction == PacketDirection.ServerToClient)
            {
                ScanForPattern(span, GameIpAscii, "game server IP (ASCII '170.33.9.35')");
                ScanForPattern(span, GameIpBinary, "game server IP (binary 0xAA210923)");
                ScanForPattern(span, AuthIpAscii, "auth server IP (ASCII '121.207.250.57')");
                ScanForPattern(span, AuthIpBinary, "auth server IP (binary 0x79CFFA39)");
            }
            else
            {
                // Detect non-HTTP packets (possible game protocol)
                if (span.Length >= 4 &&
                    !span.StartsWith("GET "u8) &&
                    !span.StartsWith("POST"u8) &&
                    !span.StartsWith("HEAD"u8) &&
                    !span.StartsWith("PUT "u8) &&
                    !span.StartsWith("HTTP"u8))
                {
                    var previewLen = Math.Min(span.Length, 64);
                    _logger.LogDebug(
                        "[{Endpoint}] GAME PROTOCOL (C→S) — {Len} bytes: {Hex}",
                        _endpointName, span.Length, DiagFormatHex(span[..previewLen]));
                }
            }
        }
        catch
        {
            // Diagnostic code must never break the relay
        }
    }

    private void ScanForPattern(ReadOnlySpan<byte> data, ReadOnlySpan<byte> pattern, string label)
    {
        var searchFrom = 0;
        while (searchFrom <= data.Length - pattern.Length)
        {
            var idx = data[searchFrom..].IndexOf(pattern);
            if (idx < 0) break;

            var foundAt = searchFrom + idx;
            var ctxStart = Math.Max(0, foundAt - 16);
            var ctxEnd = Math.Min(data.Length, foundAt + pattern.Length + 16);

            _logger.LogDebug(
                "[{Endpoint}] FOUND {Label} at offset {Offset}/{Total} — context: {Hex}",
                _endpointName, label, foundAt, data.Length,
                DiagFormatHex(data[ctxStart..ctxEnd]));

            searchFrom = foundAt + pattern.Length;
        }
    }

    private static string DiagFormatHex(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(data.Length * 3);
        for (var i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(data[i].ToString("X2"));
        }
        return sb.ToString();
    }

    // ═══════════════════════════════════════════════════════════════════
    // END DIAGNOSTIC
    // ═══════════════════════════════════════════════════════════════════

    public async ValueTask DisposeAsync()
    {
        _isActive = false;

        try { _client.Close(); } catch { }
        try { _server.Close(); } catch { }

        _client.Dispose();
        _server.Dispose();

        await _packetLogger.FlushAsync();
    }
}
