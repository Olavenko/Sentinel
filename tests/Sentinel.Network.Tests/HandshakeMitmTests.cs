using System.IO.Pipelines;
using Sentinel.Crypto;
using Sentinel.Crypto.Interfaces;
using Sentinel.Network.Handshake;

namespace Sentinel.Network.Tests;

/// <summary>
/// Integration tests for <see cref="HandshakeMitm"/> using mock pipe-based streams.
///
/// The test uses standard Blowfish as the handshake cipher (instead of ChainTableCfb64Cipher)
/// so it runs deterministically without requiring a real Frida-captured chain table.
/// The MITM logic — DH interception, public-key substitution, shared-secret derivation,
/// and session-cipher initialisation — is fully exercised regardless of which cipher
/// is used for the handshake transport.
/// </summary>
public class HandshakeMitmTests
{
    // RFC 3526 Group 14 (2048-bit MODP) prime and generator.
    // Fixed values make the test deterministic without generating DH params at runtime.
    private static readonly byte[] DhPrime = Convert.FromHexString(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF");

    private static readonly byte[] DhGenerator = [0x02];

    // Test handshake cipher: standard BF keyed with a fixed test key.
    // The MITM uses one factory call per cipher direction per packet.
    private static readonly byte[] TestHandshakeKey = "TestHandshakeKey"u8.ToArray();

    private static ICipher MakeTestCipher(bool encrypting)
    {
        var c = new BlowfishCfb64Cipher(encrypting);
        c.SetKey(TestHandshakeKey);
        return c;
    }

    // -------------------------------------------------------------------------
    // Core flow test
    // -------------------------------------------------------------------------

    [Fact]
    public async Task PerformAsync_ClientFirstFlow_EstablishesSessionCiphers()
    {
        // ── Setup: build a real client DH keypair ─────────────────────────────
        using var clientDh = new DiffieHellman();
        clientDh.Initialize(DhPrime, DhGenerator);
        var clientPubKey = clientDh.GeneratePublicKey();

        var clientIvec = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        var serverIvec = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

        // ── Build the client's DH init packet ─────────────────────────────────
        // Mirrors the TQ wire format: the client sends its public key in the
        // "ServerPublicKey" slot of the ServerHandshake structure.
        var clientHs = new ServerHandshake
        {
            Header = new byte[11],
            TqSize = 0,
            NonStaticRandomData = [0xAA, 0xBB, 0xCC, 0xDD],
            ClientIvec = clientIvec,
            ServerIvec = serverIvec,
            Prime = DhPrime,
            Generator = DhGenerator,
            ServerPublicKey = clientPubKey,   // client's own pubkey goes here
            TqServer = new byte[8],
            FinalSize = 0,
        };
        var clientHsBytes = HandshakeParser.BuildServerHandshake(clientHs);

        // Encrypt as the client would: fresh handshake cipher, IV = zeros.
        using var clientEnc = MakeTestCipher(true);
        clientEnc.SetIv(new byte[8]);
        clientEnc.Encrypt(clientHsBytes);

        // ── Create connected stream pairs ──────────────────────────────────────
        // proxyClientStream: MITM reads client packets from, writes to client
        // proxyServerStream: MITM writes to server, reads server packets from
        var (proxyClientStream, clientEnd) = DuplexPipeStreamPair.Create();
        var (proxyServerStream, serverEnd) = DuplexPipeStreamPair.Create();

        // ── Step A: client writes its init packet ─────────────────────────────
        await clientEnd.WriteAsync(clientHsBytes);
        clientEnd.CompleteWrite(); // signal no more data from client side

        // ── Step B: run the MITM in a background task ─────────────────────────
        var mitmTask = Task.Run(async () =>
            await new HandshakeMitm(MakeTestCipher).PerformAsync(
                proxyClientStream, proxyServerStream, CancellationToken.None));

        // ── Step C: simulate the server ───────────────────────────────────────
        // 1. Read the modified init from the MITM.
        var serverReceived = new byte[4096];
        var serverReceivedLen = await serverEnd.ReadAsync(serverReceived.AsMemory());
        var serverReceivedData = serverReceived[..serverReceivedLen];

        // 2. Decrypt it (same handshake cipher, IV=zeros).
        using var serverDec = MakeTestCipher(false);
        serverDec.SetIv(new byte[8]);
        serverDec.Decrypt(serverReceivedData);

        // 3. Parse to extract the proxy's server-side public key.
        var receivedHs = HandshakeParser.ParseServerHandshake(serverReceivedData);
        var proxyServerPubKey = receivedHs.ServerPublicKey; // proxy's ephemeral key

        // Verify the init was modified: proxy's key ≠ original client key.
        Assert.False(proxyServerPubKey.SequenceEqual(clientPubKey),
            "Proxy must substitute its own pubkey, not forward the client's.");

        // 4. Server generates its own keypair and computes shared secret.
        using var serverDh = new DiffieHellman();
        serverDh.Initialize(DhPrime, DhGenerator);
        var serverPubKey = serverDh.GeneratePublicKey();
        var serverSharedSecret = serverDh.ComputeSharedSecret(proxyServerPubKey);

        // 5. Build the server's reply with its pubkey.
        var serverReply = new ClientHandshakeReply
        {
            Header = new byte[11],
            Data = [0xFF],
            ClientPublicKey = serverPubKey,   // server's pubkey in this slot
            TqClient = new byte[8],
        };
        var serverReplyBytes = HandshakeParser.BuildClientReply(serverReply);
        // Server sends its reply in plaintext (no encryption — MITM tries plaintext first).
        await serverEnd.WriteAsync(serverReplyBytes);
        serverEnd.CompleteWrite();

        // ── Step D: wait for the MITM to complete ─────────────────────────────
        var result = await mitmTask;

        // ── Step E: verify ciphers were initialised ────────────────────────────
        Assert.NotNull(result.ClientDecrypt);
        Assert.NotNull(result.ClientEncrypt);
        Assert.NotNull(result.ServerDecrypt);
        Assert.NotNull(result.ServerEncrypt);

        // ── Step F: verify the client received the proxy's modified reply ──────
        var clientReceived = new byte[4096];
        var clientReceivedLen = await clientEnd.ReadAsync(clientReceived.AsMemory());
        var clientReceivedData = clientReceived[..clientReceivedLen];
        Assert.True(clientReceivedLen > 0, "MITM must forward a reply to the client.");

        // Decrypt what the client received (same handshake cipher, IV=zeros).
        using var clientDec = MakeTestCipher(false);
        clientDec.SetIv(new byte[8]);
        clientDec.Decrypt(clientReceivedData);

        var modifiedReply = HandshakeParser.ParseClientReply(clientReceivedData);
        var proxyClientPubKey = modifiedReply.ClientPublicKey;

        // Proxy must have substituted its own client-side pubkey.
        Assert.False(proxyClientPubKey.SequenceEqual(serverPubKey),
            "Proxy must substitute its own pubkey, not forward the server's.");

        // ── Step G: verify session ciphers produce matching shared secrets ─────
        // The client's shared secret: DH(clientPriv, proxyClientPubKey)
        var clientSharedSecretRaw = clientDh.ComputeSharedSecret(proxyClientPubKey);
        // Must apply same key truncation as HandshakeMitm (BF max 56 bytes).
        var clientSharedSecret = clientSharedSecretRaw[..Math.Min(56, clientSharedSecretRaw.Length)];

        // Encrypt a test message with clientSharedSecret / ClientIvec (client's outbound cipher).
        var testMsg = "Hello CO 7xxx!"u8.ToArray();
        var encBuf = testMsg.ToArray();

        var testClientEncrypt = new BlowfishCfb64Cipher(encrypting: true);
        testClientEncrypt.SetKey(clientSharedSecret);
        testClientEncrypt.SetIv(clientIvec);
        testClientEncrypt.Encrypt(encBuf);

        // Decrypt with the MITM's _clientDecrypt cipher (same key and IV).
        result.ClientDecrypt.Decrypt(encBuf);

        Assert.Equal(testMsg, encBuf);

        // Cleanup
        result.ClientDecrypt.Dispose();
        result.ClientEncrypt.Dispose();
        result.ServerDecrypt.Dispose();
        result.ServerEncrypt.Dispose();
        testClientEncrypt.Dispose();
    }

    // -------------------------------------------------------------------------
    // Sanity: ChainTableLoader correctly skips metadata keys
    // -------------------------------------------------------------------------

    [Fact]
    public void ChainTableLoader_SkipsUnderscoreKeys()
    {
        var json = """
            {
              "_comment": "ignored",
              "0000000000000000": "bc8a80e5bfb0141d"
            }
            """;

        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, json);
            var table = ChainTableLoader.LoadFromFile(path);
            Assert.Single(table);
            Assert.Equal(0xbc8a80e5bfb0141dUL, table[0x0000000000000000UL]);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ChainTableLoader_TryLoadFromFile_ReturnsEmpty_WhenMissing()
    {
        var table = ChainTableLoader.TryLoadFromFile("nonexistent/path/table.json");
        Assert.Empty(table);
    }
}

// =============================================================================
// Helpers: bidirectional pipe-based streams for in-process testing
// =============================================================================

internal sealed class DuplexPipeStreamPair
{
    private readonly Pipe _inbound = new();   // A writes → B reads
    private readonly Pipe _outbound = new();  // B writes → A reads

    private DuplexPipeStreamPair() { }

    /// <summary>
    /// Creates a connected stream pair (sideA, sideB).
    /// Bytes written to sideA are readable from sideB and vice versa.
    /// </summary>
    public static (DuplexStream sideA, DuplexStream sideB) Create()
    {
        var pair = new DuplexPipeStreamPair();
        var a = new DuplexStream(
            pair._outbound.Reader.AsStream(),
            pair._inbound.Writer.AsStream(),
            () => pair._inbound.Writer.Complete());
        var b = new DuplexStream(
            pair._inbound.Reader.AsStream(),
            pair._outbound.Writer.AsStream(),
            () => pair._outbound.Writer.Complete());
        return (a, b);
    }
}

internal sealed class DuplexStream(Stream reader, Stream writer, Action completeWrite) : Stream
{
    public override bool CanRead  => true;
    public override bool CanWrite => true;
    public override bool CanSeek  => false;
    public override long Length   => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => writer.Flush();
    public override Task FlushAsync(CancellationToken ct) => writer.FlushAsync(ct);

    public override int Read(byte[] buffer, int offset, int count) =>
        reader.Read(buffer, offset, count);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        reader.ReadAsync(buffer, offset, count, ct);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        reader.ReadAsync(buffer, ct);

    public override void Write(byte[] buffer, int offset, int count) =>
        writer.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        writer.WriteAsync(buffer, offset, count, ct);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
        writer.WriteAsync(buffer, ct);

    /// <summary>Signal that no more data will be written to this end.</summary>
    public void CompleteWrite() => completeWrite();

    public override void SetLength(long value) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
}
