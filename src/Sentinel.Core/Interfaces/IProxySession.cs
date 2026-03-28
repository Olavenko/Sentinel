using Sentinel.Core.Enums;

namespace Sentinel.Core.Interfaces;

/// <summary>
/// Represents a single proxied connection between a game client and server.
/// One session = one client connected through the proxy.
/// </summary>
public interface IProxySession : IAsyncDisposable
{
    /// <summary>Unique identifier for this session.</summary>
    Guid Id { get; }

    /// <summary>When this session was established.</summary>
    DateTimeOffset ConnectedAt { get; }

    /// <summary>Whether the session is currently active.</summary>
    bool IsActive { get; }

    /// <summary>Total bytes forwarded from client to server.</summary>
    long BytesSentToServer { get; }

    /// <summary>Total bytes forwarded from server to client.</summary>
    long BytesSentToClient { get; }

    /// <summary>
    /// Start bidirectional forwarding between client and server.
    /// Returns when either side disconnects or cancellation is requested.
    /// </summary>
    Task RunAsync(CancellationToken cancellationToken = default);

    /// <summary>Fired when the session ends (from either side disconnecting).</summary>
    event Action<IProxySession, Exception?>? Disconnected;
}
