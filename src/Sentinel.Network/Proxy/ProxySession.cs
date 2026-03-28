using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
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
    private bool _isActive;

    public Guid Id { get; } = Guid.NewGuid();
    public DateTimeOffset ConnectedAt { get; } = DateTimeOffset.UtcNow;
    public bool IsActive => _isActive;
    public long BytesSentToServer => Interlocked.Read(ref _bytesToServer);
    public long BytesSentToClient => Interlocked.Read(ref _bytesToClient);

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

            // Run both directions concurrently — when either completes, cancel the other
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var clientToServer = ForwardAsync(
                clientStream, serverStream,
                PacketDirection.ClientToServer,
                linkedCts.Token);

            var serverToClient = ForwardAsync(
                serverStream, clientStream,
                PacketDirection.ServerToClient,
                linkedCts.Token);

            // Wait for either direction to finish (one side disconnected)
            var completed = await Task.WhenAny(clientToServer, serverToClient);

            // Cancel the other direction
            await linkedCts.CancelAsync();

            // Await both to ensure clean shutdown and surface any exceptions
            try { await clientToServer; } catch (OperationCanceledException) { }
            try { await serverToClient; } catch (OperationCanceledException) { }

            // If the completed task faulted, capture the exception
            if (completed.IsFaulted)
                disconnectReason = completed.Exception?.InnerException;
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
                        await _packetLogger.LogPacketAsync(Id, direction, segment, timestamp);
                        await destination.WriteAsync(segment, ct);
                    }

                    if (direction == PacketDirection.ClientToServer)
                        Interlocked.Add(ref _bytesToServer, buffer.Length);
                    else
                        Interlocked.Add(ref _bytesToClient, buffer.Length);
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                    break;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (IOException)
        {
            // Connection closed by remote side — normal disconnect
        }
        catch (SocketException)
        {
            // Connection reset — normal disconnect
        }
        finally
        {
            await reader.CompleteAsync();
        }
    }

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
