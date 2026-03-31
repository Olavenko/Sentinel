using System.Buffers.Binary;

namespace Sentinel.Crypto;

/// <summary>
/// Parsed server handshake (CHandshake).
/// Format: [11 header][4 TqSize][buf NonStaticRandom][buf ClientIvec][buf ServerIvec][buf P][buf G][buf PubKey][8 TqServer]
/// </summary>
public sealed class ServerHandshake
{
    public required byte[] Header { get; set; }        // 11 bytes
    public required int TqSize { get; set; }
    public required byte[] NonStaticRandomData { get; set; }
    public required byte[] ClientIvec { get; set; }    // 8 bytes
    public required byte[] ServerIvec { get; set; }    // 8 bytes
    public required byte[] Prime { get; set; }
    public required byte[] Generator { get; set; }
    public required byte[] ServerPublicKey { get; set; }
    public required byte[] TqServer { get; set; }      // 8 bytes
    public required int FinalSize { get; set; }
}

/// <summary>
/// Parsed client handshake reply (CHandshakeReply).
/// Format: [11 header][buf Data][buf ClientPubKey][8 TqClient]
/// </summary>
public sealed class ClientHandshakeReply
{
    public required byte[] Header { get; set; }        // 11 bytes
    public required byte[] Data { get; set; }
    public required byte[] ClientPublicKey { get; set; }
    public required byte[] TqClient { get; set; }      // 8 bytes
}

/// <summary>
/// Parses and rebuilds the DH handshake packets used in the TQ protocol.
/// Matches the gProxy CHandshake/CHandshakeReply format exactly.
/// </summary>
public static class HandshakeParser
{
    public static ServerHandshake ParseServerHandshake(ReadOnlySpan<byte> data)
    {
        var offset = 0;

        var header = ReadBytes(data, ref offset, 11);

        var tqSize = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;

        var nonStaticRandom = ReadBuffer(data, ref offset);
        var clientIvec = ReadBuffer(data, ref offset);
        var serverIvec = ReadBuffer(data, ref offset);
        var prime = ReadBuffer(data, ref offset);
        var generator = ReadBuffer(data, ref offset);
        var pubKey = ReadBuffer(data, ref offset);
        var tqServer = ReadBytes(data, ref offset, 8);

        var finalSize = data.Length - 8;
        if (pubKey.Length == 126)
        {
            finalSize += 2;
            tqSize += 2;
        }

        return new ServerHandshake
        {
            Header = header,
            TqSize = tqSize,
            NonStaticRandomData = nonStaticRandom,
            ClientIvec = clientIvec,
            ServerIvec = serverIvec,
            Prime = prime,
            Generator = generator,
            ServerPublicKey = pubKey,
            TqServer = tqServer,
            FinalSize = finalSize
        };
    }

    public static byte[] BuildServerHandshake(ServerHandshake hs)
    {
        // Recalculate TqSize and FinalSize based on current pubkey
        var bodySize = 11 + 4
            + BufferSize(hs.NonStaticRandomData)
            + BufferSize(hs.ClientIvec)
            + BufferSize(hs.ServerIvec)
            + BufferSize(hs.Prime)
            + BufferSize(hs.Generator)
            + BufferSize(hs.ServerPublicKey)
            + 8;

        var result = new byte[bodySize];
        var offset = 0;

        WriteBytes(result, ref offset, hs.Header);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(offset, 4), hs.TqSize);
        offset += 4;

        WriteBuffer(result, ref offset, hs.NonStaticRandomData);
        WriteBuffer(result, ref offset, hs.ClientIvec);
        WriteBuffer(result, ref offset, hs.ServerIvec);
        WriteBuffer(result, ref offset, hs.Prime);
        WriteBuffer(result, ref offset, hs.Generator);
        WriteBuffer(result, ref offset, hs.ServerPublicKey);
        WriteBytes(result, ref offset, hs.TqServer);

        return result;
    }

    public static ClientHandshakeReply ParseClientReply(ReadOnlySpan<byte> data)
    {
        var offset = 0;

        var header = ReadBytes(data, ref offset, 11);
        var replyData = ReadBuffer(data, ref offset);
        var pubKey = ReadBuffer(data, ref offset);
        var tqClient = ReadBytes(data, ref offset, 8);

        return new ClientHandshakeReply
        {
            Header = header,
            Data = replyData,
            ClientPublicKey = pubKey,
            TqClient = tqClient
        };
    }

    public static byte[] BuildClientReply(ClientHandshakeReply reply)
    {
        var bodySize = 11
            + BufferSize(reply.Data)
            + BufferSize(reply.ClientPublicKey)
            + 8;

        var result = new byte[bodySize];
        var offset = 0;

        WriteBytes(result, ref offset, reply.Header);
        WriteBuffer(result, ref offset, reply.Data);
        WriteBuffer(result, ref offset, reply.ClientPublicKey);
        WriteBytes(result, ref offset, reply.TqClient);

        return result;
    }

    // TQ "ReadBuffer": 2-byte LE length prefix, then that many bytes
    private static byte[] ReadBuffer(ReadOnlySpan<byte> data, ref int offset)
    {
        var length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
        offset += 2;
        var buffer = data.Slice(offset, length).ToArray();
        offset += length;
        return buffer;
    }

    private static byte[] ReadBytes(ReadOnlySpan<byte> data, ref int offset, int count)
    {
        var buffer = data.Slice(offset, count).ToArray();
        offset += count;
        return buffer;
    }

    // TQ "WriteBuffer": 2-byte LE length prefix, then the bytes
    private static void WriteBuffer(byte[] dest, ref int offset, byte[] data)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(dest.AsSpan(offset, 2), (ushort)data.Length);
        offset += 2;
        Buffer.BlockCopy(data, 0, dest, offset, data.Length);
        offset += data.Length;
    }

    private static void WriteBytes(byte[] dest, ref int offset, byte[] data)
    {
        Buffer.BlockCopy(data, 0, dest, offset, data.Length);
        offset += data.Length;
    }

    // Total size of a buffer field (2-byte prefix + data)
    private static int BufferSize(byte[] data) => 2 + data.Length;
}
