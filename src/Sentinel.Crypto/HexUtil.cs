namespace Sentinel.Crypto;

/// <summary>
/// Hex-string parsing helpers shared by the crypto layer and the key loader.
/// <para>
/// <see cref="ParseLeDwords"/> mirrors the little-endian dword layout used by the
/// CAST5-variant schedule capture (each 8 hex chars = one 32-bit word, low byte
/// first), matching the keyfeed's <c>schedule_hex</c> encoding exactly.
/// </para>
/// </summary>
public static class HexUtil
{
    /// <summary>Parse a hex string into bytes. Length must be even.</summary>
    public static byte[] ParseBytes(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if ((hex.Length & 1) != 0)
            throw new FormatException($"Hex string length must be even (got {hex.Length}).");

        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    /// <summary>
    /// Parse a hex string into little-endian <see cref="uint"/> words (8 hex chars
    /// per word, low byte first). Length must be a multiple of 8.
    /// </summary>
    public static uint[] ParseLeDwords(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length % 8 != 0)
            throw new FormatException($"Hex string length must be a multiple of 8 (got {hex.Length}).");

        var words = new uint[hex.Length / 8];
        for (var i = 0; i < words.Length; i++)
        {
            var o = i * 8;
            uint b0 = Convert.ToByte(hex.Substring(o, 2), 16);
            uint b1 = Convert.ToByte(hex.Substring(o + 2, 2), 16);
            uint b2 = Convert.ToByte(hex.Substring(o + 4, 2), 16);
            uint b3 = Convert.ToByte(hex.Substring(o + 6, 2), 16);
            words[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        return words;
    }
}
