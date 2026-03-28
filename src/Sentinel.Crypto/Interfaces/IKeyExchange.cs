namespace Sentinel.Crypto.Interfaces;

/// <summary>
/// Key exchange protocol for establishing session keys.
/// Implementation will be determined during the RE phase
/// (likely Diffie-Hellman, but may differ in 7xxx).
/// </summary>
public interface IKeyExchange : IDisposable
{
    /// <summary>
    /// Generate our public key to send to the remote side.
    /// </summary>
    byte[] GeneratePublicKey();

    /// <summary>
    /// Compute the shared secret from the remote side's public key.
    /// </summary>
    byte[] ComputeSharedSecret(ReadOnlySpan<byte> remotePublicKey);
}
