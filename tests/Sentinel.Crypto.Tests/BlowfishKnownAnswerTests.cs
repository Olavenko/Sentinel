using Sentinel.Crypto;

namespace Sentinel.Crypto.Tests;

/// <summary>
/// Known-answer tests against IO captured directly from Conquer.exe's
/// BF_cfb64_encrypt call via Frida instrumentation.
///
/// These tests prove whether SetRawKeySchedule + a given S-box set reproduces
/// the game's actual cipher output. Run them after any change to the S-box
/// source to confirm correctness before enabling MITM on a live session.
///
/// STATUS: Zero-S-box variant expected to FAIL (S-boxes are not zero).
///         Tests will print the actual vs expected keystream to guide the
///         next Frida capture (full S0-S3 dump).
/// </summary>
public class BlowfishKnownAnswerTests
{
    // -----------------------------------------------------------------------
    // Frida-captured P-array (16 entries, handshake cipher context)
    // -----------------------------------------------------------------------
    private static readonly uint[] FridaP =
    [
        0xdb298a75, 0x3c83ff0c, 0x0dec4548, 0xf8c273e0,
        0x38a99512, 0xfc7fcfc8, 0x4e110080, 0xf8c13f63,
        0x8523e092, 0x8f496087, 0x9fbc973b, 0x22969a7b,
        0xb892fffa, 0xf6d19ec7, 0xf6c53add, 0x5a66f96e,
    ];

    // -----------------------------------------------------------------------
    // Derived from the test vectors (do not edit — these are ground truth):
    //
    //   BF_encrypt(IV=0x0000000000000000) = 0xbc8a80e5_bfb0141d
    //   BF_encrypt(IV=0x4c667e70cca6b2aa) = 0x96cbb7d3_e9067970  (encrypt path)
    //   BF_encrypt(IV=0xdb09701df591fa9b) = 0x38ef9f86_91d4c8f4  (decrypt path)
    //
    // Derivation:
    //   Capture #1 decrypt, IV=zeros:
    //     keystream[0..7] = ciphertext[0..7] XOR plaintext[0..7]
    //                     = db09701d_f591fa9b XOR 6783f0f8_4a21ee86
    //                     = bc8a80e5_bfb0141d
    //   Capture #3 encrypt, IV=zeros:
    //     keystream[0..7] = ciphertext[0..7] XOR plaintext[0..7]
    //                     = 4c667e70_cca6b2aa XOR f0ecfe95_7316a6b7
    //                     = bc8a80e5_bfb0141d  (same — consistent ✓)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // BLOCK-LEVEL DIAGNOSTIC
    // Tests the raw BF block encrypt in isolation.
    // Makes it trivial to see the keystream delta when S-boxes are wrong.
    // -----------------------------------------------------------------------

    [Fact]
    public void BlockEncrypt_AllZeroIV_MatchesExpectedKeystream()
    {
        // Encrypt 8 zero bytes with zero IV → output = BF_encrypt(0,0)
        // In CFB64: plaintext=0 means output = keystream verbatim.
        var iv     = new byte[8]; // all zeros
        var input  = new byte[8]; // all zeros
        var expect = new byte[] { 0xbc, 0x8a, 0x80, 0xe5, 0xbf, 0xb0, 0x14, 0x1d };

        var buf = input.ToArray();
        using var enc = new BlowfishCfb64Cipher(encrypting: true);
        enc.SetRawKeySchedule(FridaP);
        enc.SetIv(iv);
        enc.Encrypt(buf);

        Assert.True(buf.SequenceEqual(expect),
            "BF_encrypt(IV=zeros) mismatch.\n" +
            $"  actual   : {Hex(buf)}\n" +
            $"  expected : {Hex(expect)}\n" +
            "S-boxes are not zero — run Frida script to capture S0-S3 from game memory.\n" +
            "Hint: ECX+204 (512 B) and ECX+724 (836 B) may contain packed S-box data.");
    }

    // -----------------------------------------------------------------------
    // CAPTURE #1 — DECRYPT, 15 bytes
    //   IV_before  : 00 00 00 00 00 00 00 00
    //   num_before : 0
    //   input      : db 09 70 1d f5 91 fa 9b  a7 aa 14 d2 90 d4 c8
    //   expected   : 67 83 f0 f8 4a 21 ee 86  9f 45 8b 54 01 00 00
    //   IV_after   : a7 aa 14 d2 90 d4 c8 f4
    //   num_after  : 7
    // -----------------------------------------------------------------------

    [Fact]
    public void KnownAnswer_Decrypt_Capture1_OutputMatches()
    {
        var iv    = new byte[8];
        var input = new byte[]
        {
            0xdb, 0x09, 0x70, 0x1d, 0xf5, 0x91, 0xfa, 0x9b,
            0xa7, 0xaa, 0x14, 0xd2, 0x90, 0xd4, 0xc8,
        };
        var expect = new byte[]
        {
            0x67, 0x83, 0xf0, 0xf8, 0x4a, 0x21, 0xee, 0x86,
            0x9f, 0x45, 0x8b, 0x54, 0x01, 0x00, 0x00,
        };

        var buf = input.ToArray();
        using var dec = new BlowfishCfb64Cipher(encrypting: false);
        dec.SetRawKeySchedule(FridaP);
        dec.SetIv(iv);
        dec.Decrypt(buf);

        Assert.True(buf.SequenceEqual(expect),
            BuildMismatchMessage("Capture #1 decrypt", buf, expect));
    }

    [Fact]
    public void KnownAnswer_Decrypt_Capture1_IVAfterMatches()
    {
        // Verifies the IV state is updated correctly after 15 bytes.
        // IV_after[0..6] = last 7 ciphertext bytes; IV_after[7] = keystream[7]
        // of the second block (not yet consumed, stays from BF_encrypt output).
        var ivExpect = new byte[] { 0xa7, 0xaa, 0x14, 0xd2, 0x90, 0xd4, 0xc8, 0xf4 };

        // We can probe IV state by encrypting 1 more known byte immediately after.
        // After 15 bytes (num=7), the next Decrypt call uses ivec[7] for XOR.
        // ivec[7] = 0xf4 (keystream byte that was precomputed but not yet used).
        // Decrypt(0x00) = 0x00 ^ 0xf4 = 0xf4, then ivec[7] = 0x00 (ciphertext byte).
        var input = new byte[]
        {
            0xdb, 0x09, 0x70, 0x1d, 0xf5, 0x91, 0xfa, 0x9b,
            0xa7, 0xaa, 0x14, 0xd2, 0x90, 0xd4, 0xc8,
            0x00, // probe byte — decrypt with ivec[7]=0xf4 → plaintext = 0x00^0xf4 = 0xf4
        };

        var buf = input.ToArray();
        using var dec = new BlowfishCfb64Cipher(encrypting: false);
        dec.SetRawKeySchedule(FridaP);
        dec.SetIv(new byte[8]);
        dec.Decrypt(buf);

        // The last output byte is 0x00 XOR ivec[7].  If ivec[7]=0xf4, it's 0xf4.
        Assert.True(buf[15] == 0xf4,
            $"Probe byte mismatch: ivec[7] expected 0xf4, got 0x{buf[15]:x2}.\n" +
            "The IV is not being updated correctly after 15 bytes.");
    }

    // -----------------------------------------------------------------------
    // CAPTURE #3 — ENCRYPT, 16 bytes
    //   IV_before  : 00 00 00 00 00 00 00 00
    //   num_before : 0
    //   input      : f0 ec fe 95 73 16 a6 b7  00 00 00 23 00 00 00 55
    //   expected   : 4c 66 7e 70 cc a6 b2 aa  96 cb b7 f0 e9 06 79 25
    // -----------------------------------------------------------------------

    [Fact]
    public void KnownAnswer_Encrypt_Capture3_OutputMatches()
    {
        var iv    = new byte[8];
        var input = new byte[]
        {
            0xf0, 0xec, 0xfe, 0x95, 0x73, 0x16, 0xa6, 0xb7,
            0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x55,
        };
        var expect = new byte[]
        {
            0x4c, 0x66, 0x7e, 0x70, 0xcc, 0xa6, 0xb2, 0xaa,
            0x96, 0xcb, 0xb7, 0xf0, 0xe9, 0x06, 0x79, 0x25,
        };

        var buf = input.ToArray();
        using var enc = new BlowfishCfb64Cipher(encrypting: true);
        enc.SetRawKeySchedule(FridaP);
        enc.SetIv(iv);
        enc.Encrypt(buf);

        Assert.True(buf.SequenceEqual(expect),
            BuildMismatchMessage("Capture #3 encrypt", buf, expect));
    }

    [Fact]
    public void KnownAnswer_Encrypt_And_Decrypt_AreInverse()
    {
        // Sanity: decrypt(encrypt(x)) == x using the Frida P-array.
        var iv = new byte[8];
        var original = new byte[]
        {
            0xf0, 0xec, 0xfe, 0x95, 0x73, 0x16, 0xa6, 0xb7,
            0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x55,
        };

        var buf = original.ToArray();

        using var enc = new BlowfishCfb64Cipher(encrypting: true);
        enc.SetRawKeySchedule(FridaP);
        enc.SetIv(iv);
        enc.Encrypt(buf);

        using var dec = new BlowfishCfb64Cipher(encrypting: false);
        dec.SetRawKeySchedule(FridaP);
        dec.SetIv(iv);
        dec.Decrypt(buf);

        Assert.Equal(original, buf);
    }

    // -----------------------------------------------------------------------
    private static string BuildMismatchMessage(string label, byte[] actual, byte[] expected)
    {
        // Compute which keystream was actually used vs expected.
        // For CFB64: plaintext ^ ciphertext = keystream (both directions).
        // Here we don't have both, but we can show the byte delta.
        var delta = actual.Zip(expected, (a, e) => (byte)(a ^ e)).ToArray();
        return
            $"{label} mismatch.\n" +
            $"  actual   : {Hex(actual)}\n" +
            $"  expected : {Hex(expected)}\n" +
            $"  XOR delta: {Hex(delta)}\n" +
            "If first 8 bytes of delta are non-zero: BF_encrypt(IV=zeros) is wrong → S-boxes needed.\n" +
            "If first 8 bytes match but bytes 8-15 differ: IV feedback after block 1 is wrong.";
    }

    private static string Hex(IEnumerable<byte> bytes) =>
        string.Join(" ", bytes.Select(b => b.ToString("x2")));
}
