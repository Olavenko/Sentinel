using System.Text;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Enums;
using Sentinel.Crypto;
using Sentinel.Network.Keys;

namespace Sentinel.Network.Proxy;

/// <summary>
/// Read-only port-19000 CAST5-variant gameplay decryption state for one session.
/// <para>
/// The proxy forwards the original encrypted bytes untouched; this class observes
/// a copy per direction for logging only. Because decryption is decoupled from
/// forwarding, the connection never blocks on the key: each direction buffers its
/// ciphertext from connection start, and when the keyfeed key lands it seeds the
/// cipher at that direction's switch offset, re-decrypts the buffered run, and
/// validates the first packet (2-byte LE length prefix → 8-byte <c>TQClient</c>/
/// <c>TQServer</c> seal). On success it emits the caught-up plaintext, drops the
/// buffer, and decrypts subsequent chunks live. The pre-switch static-handshake
/// bytes are dropped (they are the DH negotiation, not gameplay). If no valid key
/// arrives within the buffer cap, it falls back to raw passthrough with a warning.
/// </para>
/// </summary>
public sealed class Cast5GameplayState : IDisposable
{
    // The static prefix is a few hundred bytes and the key lands within the first
    // DH packet, so a healthy session commits almost immediately. The cap only
    // bounds the pathological "key never arrives / never matches" case.
    private const int MaxBufferBytes = 256 * 1024; // per direction
    private const int MaxPacketLen = 8192;          // sanity bound on the u16 length prefix

    private static readonly byte[] SealClientToServer = Encoding.ASCII.GetBytes("TQClient");
    private static readonly byte[] SealServerToClient = Encoding.ASCII.GetBytes("TQServer");

    private readonly IGameSessionKeyProvider _keys;
    private readonly ILogger _logger;
    private readonly string _endpoint;
    private readonly string _idTag;

    private readonly DirectionState _send;
    private readonly DirectionState _recv;

    public Cast5GameplayState(IGameSessionKeyProvider keys, ILogger logger, string endpoint, string idTag)
    {
        _keys = keys;
        _logger = logger;
        _endpoint = endpoint;
        _idTag = idTag;
        _send = new DirectionState(PacketDirection.ClientToServer, SealClientToServer);
        _recv = new DirectionState(PacketDirection.ServerToClient, SealServerToClient);
    }

    /// <summary>
    /// Observe one forwarded ciphertext chunk for the given direction. Returns the
    /// decrypted plaintext to log (the caught-up run on commit, or the
    /// live-decrypted chunk afterwards), or <see langword="null"/> when there is
    /// nothing to log yet (still buffering the handshake / awaiting the key).
    /// </summary>
    public byte[]? OnChunk(PacketDirection direction, ReadOnlySpan<byte> ciphertext)
    {
        var d = direction == PacketDirection.ClientToServer ? _send : _recv;

        if (d.Fallback)
            return null; // degraded: original is still forwarded; nothing decrypted to log

        if (d.Committed)
        {
            var live = ciphertext.ToArray();
            d.Cipher!.Decrypt(live);
            return live;
        }

        // Pre-commit: accumulate the ciphertext stream from connection start.
        d.Buffer.AddRange(ciphertext);

        var key = _keys.Current;
        if (key is null || !key.IsDirectionReady(direction))
            return GuardCap(d);                          // no usable key for this direction yet
        if (key.SessionId == d.RejectedSession)
            return GuardCap(d);                          // this key already failed for this stream

        var (ivec, num, offsetN) = key.ForDirection(direction);
        var offset = (int)offsetN!.Value;

        if (d.Buffer.Count < offset + 2)
            return GuardCap(d);                          // not yet at the DH stream start + length prefix

        // Decrypt buffer[offset..] with a fresh, correctly-seeded cipher and
        // validate the first packet. Re-run per chunk until it commits.
        var run = new byte[d.Buffer.Count - offset];
        d.Buffer.CopyTo(offset, run, 0, run.Length);

        var cipher = new Cast5VariantCfb64Cipher(encrypting: false);
        cipher.SetRawState(key.Schedule);
        cipher.SetIv(ivec!);
        cipher.SetNum(num);
        cipher.Decrypt(run);

        switch (Validate(run, d.Seal))
        {
            case Verdict.Pending:
                cipher.Dispose();
                return GuardCap(d);                      // need more bytes for the first packet + seal

            case Verdict.Invalid:
                cipher.Dispose();
                d.RejectedSession = key.SessionId;       // wrong key for this stream; stop retrying it
                _logger.LogDebug(
                    "[{Endpoint}] Session {Id} — CAST5 {Dir} key {Session} did not validate; awaiting a new key",
                    _endpoint, _idTag, Label(direction), key.SessionId);
                return GuardCap(d);

            default: // Verdict.Valid → commit
                d.Cipher = cipher;                       // already positioned at the end of the buffered run
                d.Committed = true;
                var caughtUp = run.Length;
                d.Buffer.Clear();
                d.Buffer.TrimExcess();
                _logger.LogInformation(
                    "[{Endpoint}] Session {Id} — CAST5 {Dir} decrypt ENGAGED at offset {Offset} (session {Session}, {Bytes} bytes caught up)",
                    _endpoint, _idTag, Label(direction), offset, key.SessionId, caughtUp);
                return run;
        }
    }

    private byte[]? GuardCap(DirectionState d)
    {
        if (!d.Fallback && d.Buffer.Count > MaxBufferBytes)
        {
            d.Fallback = true;
            d.Buffer.Clear();
            d.Buffer.TrimExcess();
            _logger.LogWarning(
                "[{Endpoint}] Session {Id} — CAST5 {Dir} decrypt FALLBACK to raw passthrough: no valid key before the {Cap}-byte buffer cap. Original traffic is still forwarded untouched.",
                _endpoint, _idTag, Label(d.Direction), MaxBufferBytes);
        }
        return null;
    }

    private static string Label(PacketDirection d) =>
        d == PacketDirection.ClientToServer ? "C→S" : "S→C";

    private enum Verdict { Pending, Valid, Invalid }

    /// <summary>
    /// Validate a decrypted run as a well-formed packet start: a sane 2-byte LE
    /// length prefix whose value points exactly at the 8-byte ASCII seal.
    /// </summary>
    private static Verdict Validate(ReadOnlySpan<byte> pt, ReadOnlySpan<byte> seal)
    {
        if (pt.Length < 2) return Verdict.Pending;
        int len = pt[0] | (pt[1] << 8);
        if (len < 4 || len > MaxPacketLen) return Verdict.Invalid;
        if (pt.Length < len + seal.Length) return Verdict.Pending;
        return pt.Slice(len, seal.Length).SequenceEqual(seal) ? Verdict.Valid : Verdict.Invalid;
    }

    public void Dispose()
    {
        _send.Cipher?.Dispose();
        _recv.Cipher?.Dispose();
    }

    private sealed class DirectionState(PacketDirection direction, byte[] seal)
    {
        public PacketDirection Direction { get; } = direction;
        public byte[] Seal { get; } = seal;
        public List<byte> Buffer { get; } = [];
        public bool Committed { get; set; }
        public bool Fallback { get; set; }
        public string? RejectedSession { get; set; }
        public Cast5VariantCfb64Cipher? Cipher { get; set; }
    }
}
