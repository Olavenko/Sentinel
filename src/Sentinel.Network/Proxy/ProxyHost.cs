using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Core.Interfaces;
using Sentinel.Core.Models;
using Sentinel.Crypto;
using Sentinel.Crypto.Interfaces;
using Sentinel.Network.Keys;

namespace Sentinel.Network.Proxy;

/// <summary>
/// Orchestrates all proxy servers and manages their lifecycle.
/// </summary>
public sealed class ProxyHost : IAsyncDisposable
{
    private readonly List<ProxyServer> _servers;
    private readonly string _consoleVerbosity;
    private readonly ILogger<ProxyHost> _logger;
    private readonly GameSessionKeyProvider? _keyProvider;
    private readonly KeyfeedSupervisor? _supervisor;

    public ProxyHost(
        IOptions<ProxyConfiguration> config,
        IPacketLogger packetLogger,
        ILogger<ProxySession> sessionLogger,
        ILogger<ProxyServer> serverLogger,
        ILogger<ProxyHost> logger,
        ILogger<GameSessionKeyProvider> keyLogger,
        ILogger<KeyfeedSupervisor> keyfeedLogger)
    {
        var cfg = config.Value;

        // Load chain table once; all MITM-enabled sessions share the same read-only table.
        var chainTable = ChainTableLoader.TryLoadFromFile(cfg.HandshakeChainTablePath);
        if (chainTable.Count == 0 && cfg.Endpoints.Any(e => e.EnableMitm))
            logger.LogWarning(
                "MITM is enabled on at least one endpoint but the chain table at '{Path}' " +
                "is empty or missing. Handshake decryption will fail — run the Frida " +
                "keystream-capture script to populate it.",
                cfg.HandshakeChainTablePath);

        Func<bool, ICipher>? factory = chainTable.Count > 0
            ? encrypting => new ChainTableCfb64Cipher(chainTable, encrypting)
            : null;

        // The port-19000 CAST5 gameplay decrypt path is seeded from the live Frida keyfeed
        // file; create one shared watcher when any endpoint enables it.
        var cast5Enabled = cfg.Endpoints.Any(e => e.EnableCast5GameplayDecrypt);
        _keyProvider = cast5Enabled
            ? new GameSessionKeyProvider(cfg.GameSessionKeyPath, keyLogger)
            : null;

        // Proxy-only key production: when AutoSpawn is on, the supervisor attaches the Frida keyfeed
        // to each game client itself. Default OFF — until it is enabled, keys must be produced
        // manually, so warn loudly if CAST5 decrypt is on but no key files are present.
        if (cast5Enabled && cfg.Keyfeed.AutoSpawn)
        {
            _supervisor = new KeyfeedSupervisor(cfg.Keyfeed, _keyProvider!.KeysDirectory, keyfeedLogger);
        }
        else if (cast5Enabled && _keyProvider!.Candidates.Count == 0)
        {
            logger.LogWarning(
                "CAST5 gameplay decrypt is ENABLED but keyfeed AutoSpawn is OFF and no " +
                "game-session-<pid>.key.json files are present in '{Dir}'. The proxy will BUFFER " +
                "encrypted gameplay with ZERO KEYS and decrypt nothing until a key file appears. " +
                "Run tools/frida_v22_keyfeed.js against each Conquer.exe manually, or set " +
                "Proxy:Keyfeed:AutoSpawn=true.",
                _keyProvider.KeysDirectory);
        }

        _servers = cfg.Endpoints
            .Select(ep => new ProxyServer(ep, packetLogger, sessionLogger, serverLogger, factory, _keyProvider))
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

        // Start the proxy-only keyfeed supervisor (no-op when AutoSpawn is off).
        Task? keyfeedTask = _supervisor?.RunAsync(cancellationToken);

        var tasks = _servers.Select(s => s.StartAsync(cancellationToken));
        await Task.WhenAll(tasks);

        // Wait for summary to stop cleanly
        if (summaryTask is not null)
            try { await summaryTask; } catch (OperationCanceledException) { }

        // Wait for the supervisor loop to stop cleanly
        if (keyfeedTask is not null)
            try { await keyfeedTask; } catch (OperationCanceledException) { }

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

        // Kill any Frida children (does NOT delete key files — shutdown is not a game exit).
        _supervisor?.Dispose();
        _keyProvider?.Dispose();
    }
}
