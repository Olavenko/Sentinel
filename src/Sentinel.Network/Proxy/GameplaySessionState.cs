using Sentinel.Core.Enums;

namespace Sentinel.Network.Proxy;

/// <summary>
/// Tracks per-connection state required for gameplay packet decryption.
/// </summary>
/// <remarks>
/// <para>
/// <b>Handshake phase</b> — the CO 7xxx handshake consists of exactly
/// 1 client→server message (DH init) and 1 server→client message (DH response).
/// Both are passed through unchanged.
/// </para>
/// <para>
/// <b>Gameplay phase</b> — every subsequent packet is encrypted with the CO 7xxx
/// dual-table cipher (<see cref="Sentinel.Crypto.ConquerCipher"/>).
/// </para>
/// <para>
/// <b>Server→Client counters</b> (<see cref="RecvCounterA"/> / <see cref="RecvCounterB"/>)
/// are cumulative: they advance by one for every byte received and must be preserved
/// across packet boundaries for the entire lifetime of the session.
/// </para>
/// <para>
/// <b>Client→Server counters</b> are always reset to (0, 0) for each packet, so no
/// per-session tracking is needed on the send path.
/// </para>
/// </remarks>
public class GameplaySessionState
{
    /// <summary>Gets or sets the current phase of this session.</summary>
    public SessionPhase Phase { get; set; } = SessionPhase.Handshake;

    /// <summary>Number of client→server messages seen during the handshake. Transitions at 2.</summary>
    public int ClientToServerCount { get; set; } = 0;

    /// <summary>Number of server→client messages seen during the handshake. Transitions at 1.</summary>
    public int ServerToClientCount { get; set; } = 0;

    /// <summary>Total bytes forwarded client→server during the handshake phase.</summary>
    public long TotalClientToServerBytes { get; set; } = 0;

    /// <summary>Total bytes forwarded server→client during the handshake phase.</summary>
    public long TotalServerToClientBytes { get; set; } = 0;

    /// <summary>
    /// Gets or sets the rolling TableA index for server→client decryption.
    /// Advances by one per received byte; wraps at 255.
    /// </summary>
    public int RecvCounterA { get; set; } = 0;

    /// <summary>
    /// Gets or sets the rolling TableB index for server→client decryption.
    /// Increments when <see cref="RecvCounterA"/> wraps; wraps at 255.
    /// </summary>
    public int RecvCounterB { get; set; } = 0;

    /// <summary>
    /// Records one handshake message by direction and transitions to
    /// <see cref="SessionPhase.Gameplay"/> once 2 C→S (DH init + DH reply) and 1 S→C
    /// (DH response) have been seen.
    /// Handshake = 2 C→S (DH init + DH reply) + 1 S→C (DH response).
    /// After these 3 messages, gameplay cipher starts at counters (0,0).
    /// </summary>
    /// <param name="direction">Direction of the message being recorded.</param>
    /// <param name="byteCount">Size of the TCP segment in bytes, accumulated for diagnostics.</param>
    /// <returns>
    /// <see langword="true"/> if this call caused the transition to gameplay;
    /// <see langword="false"/> if the session is still in the handshake phase.
    /// </returns>
    public bool OnHandshakeMessage(PacketDirection direction, int byteCount)
    {
        if (direction == PacketDirection.ClientToServer)
        {
            ClientToServerCount++;
            TotalClientToServerBytes += byteCount;
        }
        else
        {
            ServerToClientCount++;
            TotalServerToClientBytes += byteCount;
        }

        if (ClientToServerCount >= 2 && ServerToClientCount >= 1)
        {
            Phase = SessionPhase.Gameplay;
            return true;
        }
        return false;
    }
}

/// <summary>Describes the current encryption phase of a proxy session.</summary>
public enum SessionPhase
{
    /// <summary>
    /// Key-exchange phase. The first 3 messages are passed through without
    /// applying the gameplay cipher.
    /// </summary>
    Handshake,

    /// <summary>
    /// Active gameplay. All packets are encrypted with the CO 7xxx dual-table
    /// cipher and must be transformed before inspection.
    /// </summary>
    Gameplay,
}
