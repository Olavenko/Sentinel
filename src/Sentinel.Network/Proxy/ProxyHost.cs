using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;

namespace Sentinel.Network.Proxy;

/// <summary>
/// Orchestrates all proxy servers and manages their lifecycle.
/// </summary>
public sealed class ProxyHost : IAsyncDisposable
{
    private readonly List<ProxyServer> _servers;
    private readonly string _consoleVerbosity;
    private readonly ILogger<ProxyHost> _logger;

    public ProxyHost(
        IOptions<ProxyConfiguration> config,
        IPacketLogger packetLogger,
        ILogger<ProxySession> sessionLogger,
        ILogger<ProxyServer> serverLogger,
        ILogger<ProxyHost> logger)
    {
        var cfg = config.Value;
        _servers = cfg.Endpoints
            .Select(ep => new ProxyServer(ep, packetLogger, sessionLogger, serverLogger))
            .ToList();
        _consoleVerbosity = (cfg.ConsoleVerbosity ?? "minimal").ToLowerInvariant();
        _logger = logger;
    }

    /// <summary>
    /// Start all proxy servers.
    /// Returns when cancellation is requested.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Sentinel proxy starting ({Count} endpoints)...", _servers.Count);

        // Start periodic summary if minimal verbosity
        Task? summaryTask = null;
        if (_consoleVerbosity == "minimal")
            summaryTask = RunPeriodicSummaryAsync(cancellationToken);

        var tasks = _servers.Select(s => s.StartAsync(cancellationToken));
        await Task.WhenAll(tasks);

        // Wait for summary to stop cleanly
        if (summaryTask is not null)
            try { await summaryTask; } catch (OperationCanceledException) { }

        _logger.LogInformation("Sentinel proxy stopped");
    }

    private async Task RunPeriodicSummaryAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));

        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                foreach (var server in _servers)
                {
                    foreach (var session in server.ActiveSessions)
                    {
                        if (!session.IsActive) continue;

                        Console.WriteLine(
                            "[{0}] {1}  ↑{2} pkts ({3})  ↓{4} pkts ({5})",
                            session.EndpointName,
                            session.Id.ToString()[..8],
                            session.PacketsSentToServer,
                            FormatBytes(session.BytesSentToServer),
                            session.PacketsSentToClient,
                            FormatBytes(session.BytesSentToClient));
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
    }

    private static string FormatBytes(long bytes)
    {
        return bytes switch
        {
            < 1024 => $"{bytes} B",
            < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
            _ => $"{bytes / (1024.0 * 1024.0):F1} MB"
        };
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var server in _servers)
            await server.DisposeAsync();
    }
}
