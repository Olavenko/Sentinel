using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;

namespace Sentinel.Network.Proxy;

/// <summary>
/// Listens for incoming game client connections on a single endpoint (auth or game)
/// and creates proxy sessions that forward traffic to the remote server.
/// </summary>
public sealed class ProxyServer : IProxyServer
{
    private readonly ProxyEndpointConfig _config;
    private readonly IPacketLogger _packetLogger;
    private readonly ILogger<ProxySession> _sessionLogger;
    private readonly ILogger<ProxyServer> _logger;

    private readonly ConcurrentDictionary<Guid, IProxySession> _sessions = new();
    private TcpListener? _listener;

    public bool IsListening { get; private set; }
    public IReadOnlyCollection<IProxySession> ActiveSessions => _sessions.Values.ToList().AsReadOnly();

    public event Action<IProxySession>? SessionStarted;
    public event Action<IProxySession>? SessionEnded;

    public ProxyServer(
        ProxyEndpointConfig config,
        IPacketLogger packetLogger,
        ILogger<ProxySession> sessionLogger,
        ILogger<ProxyServer> logger)
    {
        _config = config;
        _packetLogger = packetLogger;
        _sessionLogger = sessionLogger;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _listener = new TcpListener(IPAddress.Any, _config.ListenPort);
        _listener.Start();
        IsListening = true;

        _logger.LogInformation("[{Name}] Listening on port {Port} → forwarding to {Host}:{RemotePort}",
            _config.Name, _config.ListenPort, _config.RemoteHost, _config.RemotePort);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                // Fire and forget — each session runs independently
                _ = HandleClientAsync(client, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        finally
        {
            IsListening = false;
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        var clientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        TcpClient? server = null;

        try
        {
            // Connect to the real server
            server = new TcpClient();
            await server.ConnectAsync(_config.RemoteHost, _config.RemotePort, ct);

            var session = new ProxySession(client, server, _packetLogger, _sessionLogger, _config.Name);

            _sessions.TryAdd(session.Id, session);
            SessionStarted?.Invoke(session);

            _logger.LogInformation("[{Name}] Session {Id:N8} started — client {Client} → {Host}:{Port}",
                _config.Name, session.Id.ToString()[..8], clientEndpoint,
                _config.RemoteHost, _config.RemotePort);

            session.Disconnected += OnSessionDisconnected;

            await session.RunAsync(ct);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (SocketException ex)
        {
            _logger.LogWarning("[{Name}] Failed to connect to remote server {Host}:{Port} — {Message}",
                _config.Name, _config.RemoteHost, _config.RemotePort, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{Name}] Unexpected error in session for client {Client}",
                _config.Name, clientEndpoint);
        }
        finally
        {
            if (server is not null)
            {
                try { server.Close(); } catch { }
                server.Dispose();
            }
            try { client.Close(); } catch { }
            client.Dispose();
        }
    }

    private void OnSessionDisconnected(IProxySession session, Exception? reason)
    {
        _sessions.TryRemove(session.Id, out _);
        SessionEnded?.Invoke(session);

        if (reason is not null)
        {
            _logger.LogWarning("[{Name}] Session {Id:N8} disconnected — {Reason}",
                _config.Name, session.Id.ToString()[..8], reason.Message);
        }
        else
        {
            _logger.LogInformation("[{Name}] Session {Id:N8} disconnected — C→S: {ToServer} bytes, S→C: {ToClient} bytes",
                _config.Name, session.Id.ToString()[..8],
                session.BytesSentToServer, session.BytesSentToClient);
        }
    }

    public async Task StopAsync()
    {
        _listener?.Stop();
        IsListening = false;

        // Dispose all active sessions
        foreach (var session in _sessions.Values)
        {
            await session.DisposeAsync();
        }
        _sessions.Clear();

        _logger.LogInformation("[{Name}] Server stopped", _config.Name);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
    }
}
