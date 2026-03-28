namespace Sentinel.Core.Models;

/// <summary>
/// Configuration for a single proxy listener (auth or game).
/// </summary>
public sealed class ProxyEndpointConfig
{
    /// <summary>Local port to listen on for client connections.</summary>
    public int ListenPort { get; set; }

    /// <summary>Remote server hostname or IP to forward traffic to.</summary>
    public string RemoteHost { get; set; } = "127.0.0.1";

    /// <summary>Remote server port to forward traffic to.</summary>
    public int RemotePort { get; set; }

    /// <summary>Human-readable name for logging (e.g. "Auth", "Game").</summary>
    public string Name { get; set; } = "";
}

/// <summary>
/// Top-level proxy configuration, bound from appsettings.json.
/// </summary>
public sealed class ProxyConfiguration
{
    public const string SectionName = "Proxy";

    /// <summary>All proxy endpoints to listen on.</summary>
    public List<ProxyEndpointConfig> Endpoints { get; set; } = [];

    /// <summary>Directory to save packet log files.</summary>
    public string LogDirectory { get; set; } = "logs";

    /// <summary>Whether to output packet hex to console.</summary>
    public bool LogToConsole { get; set; } = true;

    /// <summary>
    /// Console output verbosity: "minimal", "normal", or "verbose".
    /// minimal = session start/end + periodic summary only.
    /// normal  = session start/end + per-packet one-liner (direction, size, no hex).
    /// verbose = everything including hex dumps (for debugging).
    /// </summary>
    public string ConsoleVerbosity { get; set; } = "minimal";
}
