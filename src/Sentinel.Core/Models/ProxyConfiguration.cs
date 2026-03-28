namespace Sentinel.Core.Models;

/// <summary>
/// Configuration for a single proxy listener (auth or game).
/// </summary>
public sealed class ProxyEndpointConfig
{
    /// <summary>Local port to listen on for client connections.</summary>
    public required int ListenPort { get; init; }

    /// <summary>Remote server hostname or IP to forward traffic to.</summary>
    public required string RemoteHost { get; init; }

    /// <summary>Remote server port to forward traffic to.</summary>
    public required int RemotePort { get; init; }

    /// <summary>Human-readable name for logging (e.g. "Auth", "Game").</summary>
    public required string Name { get; init; }
}

/// <summary>
/// Top-level proxy configuration, bound from appsettings.json.
/// </summary>
public sealed class ProxyConfiguration
{
    public const string SectionName = "Proxy";

    /// <summary>Auth server proxy endpoint.</summary>
    public ProxyEndpointConfig Auth { get; init; } = new()
    {
        ListenPort = 9959,
        RemoteHost = "127.0.0.1",
        RemotePort = 9958,
        Name = "Auth"
    };

    /// <summary>Game server proxy endpoint.</summary>
    public ProxyEndpointConfig Game { get; init; } = new()
    {
        ListenPort = 5816,
        RemoteHost = "127.0.0.1",
        RemotePort = 5815,
        Name = "Game"
    };

    /// <summary>Directory to save packet log files.</summary>
    public string LogDirectory { get; init; } = "logs";

    /// <summary>Whether to output packet hex to console.</summary>
    public bool LogToConsole { get; init; } = true;
}
