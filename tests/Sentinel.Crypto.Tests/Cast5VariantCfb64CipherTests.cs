using System.Text;
using Sentinel.Crypto;

namespace Sentinel.Crypto.Tests;

/// <summary>
/// Known-answer regression tests for the port-19000 TQ-customized CAST5 cipher
/// (<see cref="Cast5VariantCfb64Cipher"/>). The three vectors are live packets that
/// were independently reproduced OUTSIDE the game (see <c>cast_repro.js</c> /
/// <c>capstone_decrypt.js</c>), spanning both directions, both per-session keys,
/// and three different starting <c>num</c> values (0, 7, 2). Together they lock the
/// transform's correctness — a wrong S-box or round step cannot pass all three.
/// </summary>
public class Cast5VariantCfb64CipherTests
{
    // Recv-side schedule (S→C) shared by pkt1 + pkt2 — captured "eecd2285…" session.
    private const string RecvSchedHex =
        "eecd228511000000f63d25220200000016d8d0b808000000c6791a5d05000000" +
        "d0935b8011000000998ef13b12000000efd6eb3d1f0000006b58bf1612000000" +
        "2f21f27114000000dcc692650f000000a42a82bc10000000ce5de00a19000000" +
        "91d700621b0000003086d11f09000000055b07f31e0000001454c6d611000000" +
        "00000000";

    // Send-side schedule (C→S) for the capstone — captured "8e7457db…" session.
    private const string SendSchedHex =
        "8e7457db13000000eb3a33dc17000000187db7f51f00000053121c541a000000" +
        "b5fd089f05000000ae0bb9b60c000000c3bc10d008000000061ca3d31e000000" +
        "ea1babf214000000f37f42ad190000003237db9f150000002d34b2e817000000" +
        "deba984008000000d78f2cdb03000000eb6119b30c000000880a1c681e000000" +
        "000000000c000000000000000ad16e8d46cd0af1b26906850e256229ba013efd";

    [Fact]
    public void Pkt1_Recv_Num0_DecryptsToExpectedPlaintext()
    {
        var plain = DecryptVector(
            schedHex:       RecvSchedHex,
            ivecHex:        "b0289db82eac0c4b",
            startNum:       0,
            ciphertextHex:  "eca4872b150eeb97c7b8397ee7905af30ce4d5739c1fbab2" +
                            "9ef14c310f0673f1f98887783c0e111a979973acef6bd2a1",
            expectedHex:    "fd080a595354525f54657861735f4d6f6e657940404d6572" +
                            "637572794040376173376173404031393539383337343435");

        // Sanity: this is the "...YSTR_Texas_Money@@Mercury@@7as7as@@..." chat packet.
        Assert.Contains("Texas_Money", Encoding.Latin1.GetString(plain));
    }

    [Fact]
    public void Pkt2_Recv_Num7_DecryptsToExpectedPlaintext()
    {
        var plain = DecryptVector(
            schedHex:       RecvSchedHex,
            ivecHex:        "b21cd7420d8fc48a",
            startNum:       7,
            ciphertextHex:  "bd3eedfc2153179c8ffef7a2599c92ecac3f2d38ba678dde" +
                            "2cf6bbefd0f53a3cfb954352bcb492ef1cb0289db82eac",
            // Verbatim from cast_repro.js (47 bytes); kept on one line to avoid a
            // line-wrap dropping a zero byte from the padding.
            expectedHex:    "370803678801002b2b2b5f4e617275746f5f2b2b2b0000000000000000000000000000000000005451536572766572");

        Assert.Contains("Naruto", Encoding.Latin1.GetString(plain));
    }

    [Fact]
    public void Capstone_Send_Num2_DecryptsToSentinelProbe123()
    {
        var plain = DecryptVector(
            schedHex:       SendSchedHex,
            ivecHex:        "ec17cea70d96087c",
            startNum:       2,
            ciphertextHex:  "90a7349f0083843c0842d0c0ccf59225871f1bdb704f56b1" +
                            "1eb051e26436e352fb5d312fe6f1b8c02bfe644ecfe08bbc" +
                            "95f19f79cf9cfa74a4826511379e9c694e2cbf7316a99512" +
                            "a5c0282d0bc5cfe218d49adb6527291310aab5b9b0dd",
            expectedHex:    "5e00390908ffffffff0f10d00f180020a50a280030c0a525" +
                            "48006000680072074c65706f53656e7204416c6c20720072" +
                            "1053454e54494e454c50524f424531323372007200720078" +
                            "00800102900100980100a00101c00100c80100d00101");

        // The capstone known-plaintext: we typed SENTINELPROBE123 in-game.
        Assert.Contains("SENTINELPROBE123", Encoding.Latin1.GetString(plain));
    }

    /// <summary>
    /// Seed a decrypt-mode cipher with the captured schedule + ivec + starting num,
    /// decrypt the captured ciphertext, and assert it matches the expected plaintext
    /// byte-for-byte. Returns the decrypted bytes.
    /// </summary>
    private static byte[] DecryptVector(
        string schedHex, string ivecHex, int startNum, string ciphertextHex, string expectedHex)
    {
        var schedule   = ParseLe(schedHex);
        var ivec       = Convert.FromHexString(ivecHex);
        var ciphertext = Convert.FromHexString(ciphertextHex);
        var expected   = Convert.FromHexString(expectedHex);

        using var cipher = new Cast5VariantCfb64Cipher(encrypting: false);
        cipher.SetRawState(schedule);
        cipher.SetIv(ivec);
        cipher.SetNum(startNum); // after SetIv/SetRawState, which reset num to 0

        var buffer = (byte[])ciphertext.Clone();
        cipher.Decrypt(buffer);

        Assert.Equal(expected, buffer);
        return buffer;
    }

    private static uint[] ParseLe(string hex)
    {
        var n = hex.Length / 8;
        var a = new uint[n];
        for (var i = 0; i < n; i++)
        {
            var o = i * 8;
            uint b0 = Convert.ToByte(hex.Substring(o,     2), 16);
            uint b1 = Convert.ToByte(hex.Substring(o + 2, 2), 16);
            uint b2 = Convert.ToByte(hex.Substring(o + 4, 2), 16);
            uint b3 = Convert.ToByte(hex.Substring(o + 6, 2), 16);
            a[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        return a;
    }
}
