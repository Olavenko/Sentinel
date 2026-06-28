using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Sentinel.Core.Enums;

namespace Sentinel.Network.Keys;

/// <summary>
/// A captured port-19000 CAST5-variant session key, parsed from one Frida
/// keyfeed file (<c>keys/game-session-&lt;pid&gt;.key.json</c>). <see cref="Pid"/> is the
/// producing Conquer.exe PID (a label / file discriminator); <see cref="ScheduleId"/>
/// is the authoritative content identity used for routing.
/// <para>
/// One 33-word schedule serves both directions. Each direction additionally has
/// an 8-byte CFB64 stream-start ivec, a starting <c>num</c> (always 0 at the
/// stream start), and the cumulative wire byte offset at which the DH stream
/// begins (the number of static-handshake bytes that precede it in that
/// direction). A direction is only usable once its ivec and switch offset are
/// present — the keyfeed writes the schedule first, then each direction's start
/// as it occurs, so a freshly-written file may have one direction still null.
/// </para>
/// </summary>
public sealed record GameSessionKey(
    string SessionId,
    uint[] Schedule,
    byte[]? SendIvec,
    int SendNum,
    long? SendSwitchOffset,
    byte[]? RecvIvec,
    int RecvNum,
    long? RecvSwitchOffset,
    int? Pid = null)
{
    /// <summary>
    /// Stable, collision-free identity for this key's DH session, derived from the
    /// FULL 33-word schedule content (SHA-256 hex). This — never the 32-bit djb2
    /// <see cref="SessionId"/> label — gates candidate selection and the per-direction
    /// rejected-set in multi-account routing, so two live accounts can never collide on
    /// identity. Recomputed on access (cheap; the schedule is 132 bytes).
    /// </summary>
    public string ScheduleId =>
        Convert.ToHexString(SHA256.HashData(MemoryMarshal.AsBytes(Schedule.AsSpan())));

    /// <summary>The per-direction stream-start parameters, or nulls if not yet captured.</summary>
    public (byte[]? Ivec, int Num, long? SwitchOffset) ForDirection(PacketDirection direction) =>
        direction == PacketDirection.ClientToServer
            ? (SendIvec, SendNum, SendSwitchOffset)
            : (RecvIvec, RecvNum, RecvSwitchOffset);

    /// <summary>True when the given direction has both an ivec and a switch offset.</summary>
    public bool IsDirectionReady(PacketDirection direction)
    {
        var (ivec, _, off) = ForDirection(direction);
        return ivec is { Length: 8 } && off is not null;
    }
}

/// <summary>
/// Provides the latest captured <see cref="GameSessionKey"/> and notifies when it changes.
/// Backed by a file watcher over the Frida keyfeed output.
/// </summary>
public interface IGameSessionKeyProvider
{
    /// <summary>
    /// The most recently loaded key, or <see langword="null"/> if none yet. Convenience
    /// for the single-account (N=1) path; multi-account consumers bind per connection via
    /// <see cref="Candidates"/> and content-matching.
    /// </summary>
    GameSessionKey? Current { get; }

    /// <summary>
    /// All currently-known session keys — one per live keyfeed file (one per Conquer.exe
    /// PID). A connection is bound to the right one by content-matching (length → seal),
    /// never by PID. Empty until the first key lands.
    /// </summary>
    IReadOnlyCollection<GameSessionKey> Candidates { get; }

    /// <summary>Raised whenever a new key is successfully loaded.</summary>
    event Action<GameSessionKey>? KeyChanged;
}
