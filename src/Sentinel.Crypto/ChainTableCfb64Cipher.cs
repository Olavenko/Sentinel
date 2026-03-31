using Sentinel.Crypto.Interfaces;

namespace Sentinel.Crypto;

/// <summary>
/// CFB64 cipher identical to OpenSSL's BF_cfb64_encrypt, but replaces BF_encrypt
/// with a dictionary lookup of pre-captured input→output pairs.
///
/// Used for the CO 7xxx handshake where the full Blowfish key schedule cannot be
/// reproduced (modified S-box init), but individual BF_encrypt(IV)→output pairs
/// can be captured from the running process via Frida.
///
/// Throws <see cref="InvalidOperationException"/> when an IV is encountered that
/// is not in the table — the error message names the missing entry so you know
/// exactly which pair to capture next.
///
/// The table is loaded from a JSON resource file; see <see cref="ChainTableLoader"/>.
/// </summary>
public sealed class ChainTableCfb64Cipher : ICipher
{
    private readonly Dictionary<ulong, ulong> _table;
    private readonly bool _encrypting;
    private readonly byte[] _iv = new byte[8];
    private int _num;
    private bool _disposed;

    public ChainTableCfb64Cipher(Dictionary<ulong, ulong> table, bool encrypting)
    {
        ArgumentNullException.ThrowIfNull(table);
        _table = table;
        _encrypting = encrypting;
    }

    /// <summary>
    /// No-op — the lookup table is the key material.
    /// Satisfies the <see cref="ICipher"/> contract.
    /// </summary>
    public void SetKey(ReadOnlySpan<byte> key) { }

    public void SetIv(ReadOnlySpan<byte> iv)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (iv.Length != 8)
            throw new ArgumentException("IV must be exactly 8 bytes for BF-CFB64.", nameof(iv));
        iv.CopyTo(_iv);
        _num = 0;
    }

    public void Encrypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_encrypting)
            throw new InvalidOperationException("This instance is configured for decryption.");

        for (var i = 0; i < data.Length; i++)
        {
            if (_num == 0) EncryptIvBlock();
            _iv[_num] ^= data[i];
            data[i] = _iv[_num];
            _num = (_num + 1) & 7;
        }
    }

    public void Decrypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_encrypting)
            throw new InvalidOperationException("This instance is configured for encryption.");

        for (var i = 0; i < data.Length; i++)
        {
            if (_num == 0) EncryptIvBlock();
            var c = data[i];
            data[i] = (byte)(_iv[_num] ^ c);
            _iv[_num] = c;
            _num = (_num + 1) & 7;
        }
    }

    public void Reset()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Array.Clear(_iv);
        _num = 0;
    }

    public void Dispose()
    {
        _disposed = true;
        Array.Clear(_iv);
    }

    private void EncryptIvBlock()
    {
        var input = ReadBE64(_iv);
        if (!_table.TryGetValue(input, out var output))
            throw new InvalidOperationException(
                $"BF_encrypt(0x{input:x16}) is missing from the chain table.\n" +
                "Add this entry to resources/handshake-chain-table.json by running the " +
                "Frida keystream-capture script against the game process.");
        WriteBE64(_iv, output);
    }

    private static ulong ReadBE64(byte[] b) =>
        ((ulong)b[0] << 56) | ((ulong)b[1] << 48) | ((ulong)b[2] << 40) | ((ulong)b[3] << 32) |
        ((ulong)b[4] << 24) | ((ulong)b[5] << 16) | ((ulong)b[6] <<  8) |  b[7];

    private static void WriteBE64(byte[] b, ulong v)
    {
        b[0] = (byte)(v >> 56); b[1] = (byte)(v >> 48);
        b[2] = (byte)(v >> 40); b[3] = (byte)(v >> 32);
        b[4] = (byte)(v >> 24); b[5] = (byte)(v >> 16);
        b[6] = (byte)(v >>  8); b[7] = (byte) v;
    }
}
