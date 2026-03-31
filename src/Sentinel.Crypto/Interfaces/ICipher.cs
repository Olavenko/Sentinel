namespace Sentinel.Crypto.Interfaces;

/// <summary>
/// Symmetric cipher for encrypting/decrypting game traffic.
/// Implementation will be determined during the RE phase.
/// Each direction (C→S, S→C) uses its own cipher instance
/// since they maintain independent state (counters, IVs).
/// </summary>
public interface ICipher : IDisposable
{
    /// <summary>
    /// Initialize the cipher with a session key.
    /// </summary>
    void SetKey(ReadOnlySpan<byte> key);

    /// <summary>
    /// Decrypt data in place.
    /// </summary>
    void Decrypt(Span<byte> data);

    /// <summary>
    /// Encrypt data in place.
    /// </summary>
    void Encrypt(Span<byte> data);

    /// <summary>
    /// Set the initialization vector for CFB/CBC modes.
    /// Resets the streaming counter to 0.
    /// </summary>
    void SetIv(ReadOnlySpan<byte> iv);

    /// <summary>
    /// Reset cipher state (counters, IVs) without changing the key.
    /// </summary>
    void Reset();
}
