using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;

namespace Sentinel.Network.Proxy;

/// <summary>
/// Orchestrates both proxy servers (auth + game) and manages their lifecycle.
/// </summary>
public sealed class ProxyHost : IAsyncDisposable
{
    private readonly ProxyServer _authServer;
    private readonly ProxyServer _gameServer;
    private readonly ILogger<ProxyHost> _logger;

    public ProxyHost(
        IOptions<ProxyConfiguration> config,
        IPacketLogger packetLogger,
        ILogger<ProxySession> sessionLogger,
        ILogger<ProxyServer> serverLogger,
        ILogger<ProxyHost> logger)
    {
        var cfg = config.Value;
        _authServer = new ProxyServer(cfg.Auth, packetLogger, sessionLogger, serverLogger);
        _gameServer = new ProxyServer(cfg.Game, packetLogger, sessionLogger, serverLogger);
        _logger = logger;
    }

    /// <summary>
    /// Start both auth and game proxy servers.
    /// Returns when cancellation is requested.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Sentinel proxy starting...");

        var authTask = _authServer.StartAsync(cancellationToken);
        var gameTask = _gameServer.StartAsync(cancellationToken);

        await Task.WhenAll(authTask, gameTask);

        _logger.LogInformation("Sentinel proxy stopped");
    }

    public async ValueTask DisposeAsync()
    {
        await _authServer.DisposeAsync();
        await _gameServer.DisposeAsync();
    }
}
