using Microsoft.Extensions.Logging;
using Sentinel.Crypto;
using Sentinel.Crypto.Interfaces;

namespace Sentinel.Network.Handshake;

/// <summary>
/// Four BF-CFB64 ciphers established after a successful MITM handshake.
/// Ownership of the ciphers transfers to the caller; the caller is responsible
/// for disposing them.
/// </summary>
public readonly record struct HandshakeResult(
    BlowfishCfb64Cipher ClientDecrypt,
    BlowfishCfb64Cipher ClientEncrypt,
    BlowfishCfb64Cipher ServerDecrypt,
    BlowfishCfb64Cipher ServerEncrypt);

/// <summary>
/// Performs the CO 7xxx DH man-in-the-middle handshake.
///
/// CO 7xxx flow (client-first, reversed from 5xxx):
///   1. Client sends DH init  (P, G, ClientPub, ClientIvec, ServerIvec)
///   2. Server sends DH reply (ServerPub)
///
/// The proxy intercepts both packets, replaces the public keys with its own
/// ephemeral keys, and derives two independent shared secrets:
///   - sharedSecretClient = DH(proxyPriv_c, realClientPub)
///   - sharedSecretServer = DH(proxyPriv_s, realServerPub)
///
/// After the handshake, all game traffic uses standard BF-CFB64 keyed with
/// the derived shared secrets and the IVecs exchanged during the init packet.
/// </summary>
public sealed class HandshakeMitm(
    Func<bool, ICipher> handshakeCipherFactory,
    ILogger? logger = null)
{
    public async Task<HandshakeResult> PerformAsync(
        Stream clientStream,
        Stream serverStream,
        CancellationToken ct)
    {
        // ── Step 1: Read the client's DH init packet ──────────────────────────
        logger?.LogDebug("MITM: waiting for client DH init...");

        var clientHsRaw = await ReadPacketAsync(clientStream, ct);

        // ── Step 2: Decrypt with a fresh ChainTable cipher (IV = zeros) ───────
        using var initDecrypt = handshakeCipherFactory(false);
        initDecrypt.SetIv(new byte[8]);
        initDecrypt.Decrypt(clientHsRaw);

        // ── Step 3: Parse the client's handshake ──────────────────────────────
        // The client sends the same TQ buffer format as the 5xxx server init:
        // Header + TqSize + NonStaticRandom + ClientIvec + ServerIvec + P + G + PublicKey + TqServer.
        // The "ServerPublicKey" slot carries the CLIENT'S public key in this flow.
        var clientHs = HandshakeParser.ParseServerHandshake(clientHsRaw);
        var realClientPubKey = clientHs.ServerPublicKey;

        logger?.LogDebug(
            "MITM: client init parsed — P={P}B G={G}B PubKey={K}B ClientIvec={CI}B ServerIvec={SI}B",
            clientHs.Prime.Length, clientHs.Generator.Length, realClientPubKey.Length,
            clientHs.ClientIvec.Length, clientHs.ServerIvec.Length);

        // ── Step 4: Generate proxy→server ephemeral DH keypair ────────────────
        using var dhForServer = new DiffieHellman();
        dhForServer.Initialize(clientHs.Prime, clientHs.Generator);
        var proxyPubKeyForServer = dhForServer.GeneratePublicKey();

        // ── Step 5: Substitute proxy's pubkey and forward to server ───────────
        clientHs.ServerPublicKey = proxyPubKeyForServer;
        var modifiedClientHs = HandshakeParser.BuildServerHandshake(clientHs);

        using var initEncryptToServer = handshakeCipherFactory(true);
        initEncryptToServer.SetIv(new byte[8]);
        initEncryptToServer.Encrypt(modifiedClientHs);
        await serverStream.WriteAsync(modifiedClientHs, ct);

        logger?.LogDebug("MITM: modified init forwarded to server ({Bytes}B)", modifiedClientHs.Length);

        // ── Step 6: Read the server's DH reply ────────────────────────────────
        logger?.LogDebug("MITM: waiting for server DH reply...");

        var serverReplyRaw = await ReadPacketAsync(serverStream, ct);

        // The server reply is formatted as the 5xxx ClientHandshakeReply:
        // Header + Data + PublicKey + TqClient.
        // The "ClientPublicKey" slot carries the SERVER'S public key here.
        // Try parsing as plaintext first; if that throws, decrypt and retry.
        ClientHandshakeReply serverReply;
        try
        {
            serverReply = HandshakeParser.ParseClientReply(serverReplyRaw);
        }
        catch
        {
            using var replyDecrypt = handshakeCipherFactory(false);
            replyDecrypt.SetIv(new byte[8]);
            replyDecrypt.Decrypt(serverReplyRaw);
            serverReply = HandshakeParser.ParseClientReply(serverReplyRaw);
        }

        var realServerPubKey = serverReply.ClientPublicKey;

        logger?.LogDebug("MITM: server reply parsed — PubKey={K}B", realServerPubKey.Length);

        // ── Step 7: Generate proxy→client ephemeral DH keypair ────────────────
        using var dhForClient = new DiffieHellman();
        dhForClient.Initialize(clientHs.Prime, clientHs.Generator);
        var proxyPubKeyForClient = dhForClient.GeneratePublicKey();

        // ── Step 8: Substitute proxy's pubkey and forward to client ───────────
        serverReply.ClientPublicKey = proxyPubKeyForClient;
        var modifiedServerReply = HandshakeParser.BuildClientReply(serverReply);

        // Server replies in the same encryption style as the init packet.
        // Re-encrypt for the client before forwarding.
        using var replyEncryptToClient = handshakeCipherFactory(true);
        replyEncryptToClient.SetIv(new byte[8]);
        replyEncryptToClient.Encrypt(modifiedServerReply);
        await clientStream.WriteAsync(modifiedServerReply, ct);

        logger?.LogDebug("MITM: modified reply forwarded to client ({Bytes}B)", modifiedServerReply.Length);

        // ── Step 9: Compute shared secrets ────────────────────────────────────
        var sharedSecretServer = dhForServer.ComputeSharedSecret(realServerPubKey);
        var sharedSecretClient = dhForClient.ComputeSharedSecret(realClientPubKey);

        logger?.LogDebug(
            "MITM: shared secrets — client={CLen}B server={SLen}B",
            sharedSecretClient.Length, sharedSecretServer.Length);

        // ── Step 10: Initialise 4 session ciphers (standard BF, NOT chain table) ─
        //
        // IV assignment (from gProxy reference):
        //   Proxy←Client (decrypt): IV = ClientIvec   ← client encrypts outbound with ClientIvec
        //   Proxy→Client (encrypt): IV = ServerIvec   ← client decrypts inbound with ServerIvec
        //   Proxy←Server (decrypt): IV = ServerIvec   ← server encrypts outbound with ServerIvec
        //   Proxy→Server (encrypt): IV = ClientIvec   ← server decrypts inbound with ClientIvec
        //
        // Key size: Blowfish accepts 4–56 bytes. Clamp the shared secret to that range.
        // TODO: confirm whether CO 7xxx uses raw DH output, a hash, or a fixed-size slice.
        var clientKey = TrimToBlowfishKeySize(sharedSecretClient);
        var serverKey = TrimToBlowfishKeySize(sharedSecretServer);

        var clientDecrypt = new BlowfishCfb64Cipher(encrypting: false);
        clientDecrypt.SetKey(clientKey);
        clientDecrypt.SetIv(clientHs.ClientIvec);

        var clientEncrypt = new BlowfishCfb64Cipher(encrypting: true);
        clientEncrypt.SetKey(clientKey);
        clientEncrypt.SetIv(clientHs.ServerIvec);

        var serverDecrypt = new BlowfishCfb64Cipher(encrypting: false);
        serverDecrypt.SetKey(serverKey);
        serverDecrypt.SetIv(clientHs.ServerIvec);

        var serverEncrypt = new BlowfishCfb64Cipher(encrypting: true);
        serverEncrypt.SetKey(serverKey);
        serverEncrypt.SetIv(clientHs.ClientIvec);

        logger?.LogDebug("MITM: 4 session ciphers initialised");

        return new HandshakeResult(clientDecrypt, clientEncrypt, serverDecrypt, serverEncrypt);
    }

    /// <summary>
    /// Blowfish key range is 4–56 bytes. If the DH shared secret is longer
    /// (common with 1024-bit+ DH groups), take the leading 56 bytes.
    /// TODO: verify the exact key derivation once real CO 7xxx traffic is captured.
    /// </summary>
    private static ReadOnlySpan<byte> TrimToBlowfishKeySize(byte[] key) =>
        key.Length <= 56 ? key : key.AsSpan(0, 56);

    /// <summary>
    /// Read one handshake packet from <paramref name="stream"/>.
    /// Performs a single ReadAsync call — handshake packets arrive in a single
    /// TCP segment, so one read captures the complete packet.
    /// </summary>
    private static async Task<byte[]> ReadPacketAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[4096];
        var n = await stream.ReadAsync(buffer.AsMemory(), ct);
        if (n == 0)
            throw new IOException("Stream closed before handshake packet was received.");
        return buffer[..n];
    }
}
