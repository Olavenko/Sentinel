using Sentinel.Crypto;

namespace Sentinel.Crypto.Tests;

/// <summary>
/// S-box investigation tests and nuclear chain-table CFB64 cipher.
///
/// BACKGROUND
/// ----------
/// CO 7xxx's modified Blowfish (14 Feistel rounds, 16 P entries) uses non-zero
/// S-boxes. Without them, BF_encrypt(0,0) produces c1 97 e1 12 f4 b5 e8 21
/// instead of the game's bc 8a 80 e5 bf b0 14 1d — a consistent 8-byte delta.
///
/// Two candidate S-box memory regions were observed via Frida at:
///   ECX+0x0CC : 512 bytes  (SBOX_A)
///   ECX+0x2D4 : 489 bytes  (SBOX_B)
///
/// STRATEGY
/// --------
/// 1. Hypothesis tests (A–E) try different interpretations of the SBOX_A/B data.
///    They are skipped until the full Frida dump is pasted into SboxA_Raw/SboxB_Raw.
///
/// 2. Nuclear option: bypass S-box discovery by using known BF_encrypt(in)→out
///    pairs captured directly from the running game. The chain-table cipher does
///    CFB64 identically to OpenSSL but calls a dictionary lookup instead of
///    computing BF_encrypt. As long as the table contains every IV the handshake
///    will generate, decryption is exact.
/// </summary>
public class BlowfishSboxInvestigationTests
{
    private static readonly uint[] FridaP =
    [
        0xdb298a75, 0x3c83ff0c, 0x0dec4548, 0xf8c273e0,
        0x38a99512, 0xfc7fcfc8, 0x4e110080, 0xf8c13f63,
        0x8523e092, 0x8f496087, 0x9fbc973b, 0x22969a7b,
        0xb892fffa, 0xf6d19ec7, 0xf6c53add, 0x5a66f96e,
    ];

    private static readonly byte[] ExpectedBfEncryptZeroIv =
        [0xbc, 0x8a, 0x80, 0xe5, 0xbf, 0xb0, 0x14, 0x1d];

    // =========================================================================
    // NUCLEAR OPTION — chain-table CFB64
    //
    // Dictionary of known BF_encrypt(input) → output pairs.
    //
    // Sources:
    //   Chain file — 512 consecutive BF_encrypt calls starting from IV=zeros:
    //     BF_encrypt(0000000000000000) = bc8a80e5bfb0141d
    //     BF_encrypt(bc8a80e5bfb0141d) = 694d6035a12e9daf
    //     BF_encrypt(694d6035a12e9daf) = ec3699e9846441a2
    //     BF_encrypt(ec3699e9846441a2) = 6acf349c4aa71eac
    //
    //   Derived from Capture #1 (decrypt, 15 bytes, IV=zeros):
    //     After block 0: IV = db09701df591fa9b (first 8 ciphertext bytes)
    //     keystream[8..15] = plaintext[8..14] XOR ciphertext[8..14] + ivec[7]
    //     → BF_encrypt(db09701df591fa9b) = 38ef9f8691d4c8f4
    //
    //   Derived from Capture #3 (encrypt, 16 bytes, IV=zeros):
    //     After block 0: IV = 4c667e70cca6b2aa (first 8 ciphertext bytes)
    //     keystream[8..15] = ciphertext[8..15] XOR plaintext[8..15]
    //     → BF_encrypt(4c667e70cca6b2aa) = 96cbb7d3e9067970
    //
    // To extend the table: run the Frida keystream-capture script and add entries.
    // =========================================================================

    private static readonly Dictionary<ulong, ulong> BfEncryptTable = new()
    {
        // Chain pairs from BF_encrypt capture (starting at IV=zeros)
        [0x0000000000000000UL] = 0xbc8a80e5bfb0141dUL,
        [0xbc8a80e5bfb0141dUL] = 0x694d6035a12e9dafUL,
        [0x694d6035a12e9dafUL] = 0xec3699e9846441a2UL,
        [0xec3699e9846441a2UL] = 0x6acf349c4aa71eacUL,
        // Derived from Capture #1 decrypt (IV after block 0)
        [0xdb09701df591fa9bUL] = 0x38ef9f8691d4c8f4UL,
        // Derived from Capture #3 encrypt (IV after block 0)
        [0x4c667e70cca6b2aaUL] = 0x96cbb7d3e9067970UL,
    };

    // -----------------------------------------------------------------------
    // Sanity checks on the table itself
    // -----------------------------------------------------------------------

    [Fact]
    public void BfEncryptTable_ZeroIv_EntryIsCorrect()
    {
        Assert.True(BfEncryptTable.TryGetValue(0UL, out var v));
        Assert.Equal(0xbc8a80e5bfb0141dUL, v);
    }

    [Fact]
    public void BfEncryptTable_ChainIsConsistent()
    {
        // Each chain link's output must be the next link's input.
        ulong cursor = 0;
        for (var i = 0; i < 4; i++)
        {
            Assert.True(BfEncryptTable.ContainsKey(cursor),
                $"Chain broken at link {i}: 0x{cursor:x16} not in table.");
            cursor = BfEncryptTable[cursor];
        }
    }

    // -----------------------------------------------------------------------
    // Nuclear cipher — Capture #1 decrypt
    // -----------------------------------------------------------------------

    [Fact]
    public void ChainTable_Decrypt_Capture1_OutputMatches()
    {
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
        using var dec = new ChainTableCfb64Cipher(BfEncryptTable, encrypting: false);
        dec.SetIv(new byte[8]);
        dec.Decrypt(buf);

        Assert.True(buf.SequenceEqual(expect),
            $"Nuclear decrypt Capture #1 mismatch.\n" +
            $"  actual  : {Hex(buf)}\n" +
            $"  expected: {Hex(expect)}");
    }

    [Fact]
    public void ChainTable_Decrypt_Capture1_IVAfterMatches()
    {
        // After 15 bytes (num=7), ivec[7] holds the unused keystream byte = 0xf4.
        // Probe by decrypting one extra zero byte: output = 0x00 ^ 0xf4 = 0xf4.
        var input = new byte[]
        {
            0xdb, 0x09, 0x70, 0x1d, 0xf5, 0x91, 0xfa, 0x9b,
            0xa7, 0xaa, 0x14, 0xd2, 0x90, 0xd4, 0xc8,
            0x00, // probe
        };

        var buf = input.ToArray();
        using var dec = new ChainTableCfb64Cipher(BfEncryptTable, encrypting: false);
        dec.SetIv(new byte[8]);
        dec.Decrypt(buf);

        Assert.True(buf[15] == 0xf4,
            $"Probe byte mismatch: ivec[7] expected 0xf4, got 0x{buf[15]:x2}.");
    }

    // -----------------------------------------------------------------------
    // Nuclear cipher — Capture #3 encrypt
    // -----------------------------------------------------------------------

    [Fact]
    public void ChainTable_Encrypt_Capture3_OutputMatches()
    {
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
        using var enc = new ChainTableCfb64Cipher(BfEncryptTable, encrypting: true);
        enc.SetIv(new byte[8]);
        enc.Encrypt(buf);

        Assert.True(buf.SequenceEqual(expect),
            $"Nuclear encrypt Capture #3 mismatch.\n" +
            $"  actual  : {Hex(buf)}\n" +
            $"  expected: {Hex(expect)}");
    }

    [Fact]
    public void ChainTable_EncryptThenDecrypt_Roundtrip()
    {
        var original = new byte[]
        {
            0xf0, 0xec, 0xfe, 0x95, 0x73, 0x16, 0xa6, 0xb7,
            0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x55,
        };

        var buf = original.ToArray();
        using var enc = new ChainTableCfb64Cipher(BfEncryptTable, encrypting: true);
        enc.SetIv(new byte[8]);
        enc.Encrypt(buf);

        using var dec = new ChainTableCfb64Cipher(BfEncryptTable, encrypting: false);
        dec.SetIv(new byte[8]);
        dec.Decrypt(buf);

        Assert.Equal(original, buf);
    }

    // =========================================================================
    // S-BOX HYPOTHESIS TESTS
    //
    // These are skipped until the full Frida memory dump is provided.
    //
    // To activate:
    //   1. Run the Frida SBOX capture script against Conquer.exe
    //   2. Paste the hex output into SboxA_Raw and SboxB_Raw below
    //   3. Remove or change the Skip="..." attribute on each test
    //   4. Run: dotnet test --filter "SboxHypothesis"
    //
    // Memory regions to capture:
    //   ECX+0x0CC : 512 bytes → SboxA_Raw
    //   ECX+0x2D4 : 489 bytes → SboxB_Raw  (pad to 512 with zeros if needed)
    // =========================================================================

    // PASTE full 512-byte big-endian dump from ECX+0x0CC here.
    // First 4 bytes from prior capture: f6 d0 ec 86 ...
    private static readonly byte[] SboxA_Raw = [];  // TODO: paste full dump

    // PASTE full 489-byte dump from ECX+0x2D4 here (zero-pad to 512 if needed).
    // First 4 bytes from prior capture: 9d 90 83 8a ...
    private static readonly byte[] SboxB_Raw = [];  // TODO: paste full dump

    [Fact(Skip = "Requires full SBOX dump — populate SboxA_Raw from Frida (ECX+0x0CC, 512 bytes)")]
    public void SboxHypothesisA_4x32_FromSboxA_BfEncryptZeroIv_Matches()
    {
        // Hypothesis: SBOX_A (512 bytes = 128 uint32s) = four 32-entry S-boxes (5-bit index, mask=31)
        // Layout:  S0[0..31]=bytes[0..127], S1[0..31]=bytes[128..255], S2/S3 likewise.
        Assert.True(SboxA_Raw.Length >= 512, "SboxA_Raw must be 512 bytes.");
        var s = ToUInt32ArrayBE(SboxA_Raw, 128);
        RunBfEncryptZeroIvTest(s[0..32], s[32..64], s[64..96], s[96..128],
            "HypA: 4×32 from SBOX_A (big-endian)");
    }

    [Fact(Skip = "Requires full SBOX dump — populate SboxA_Raw from Frida (ECX+0x0CC, 512 bytes)")]
    public void SboxHypothesisA2_4x32_FromSboxA_LittleEndian_BfEncryptZeroIv_Matches()
    {
        // Same layout as A but treat uint32s as little-endian.
        Assert.True(SboxA_Raw.Length >= 512, "SboxA_Raw must be 512 bytes.");
        var s = ToUInt32ArrayLE(SboxA_Raw, 128);
        RunBfEncryptZeroIvTest(s[0..32], s[32..64], s[64..96], s[96..128],
            "HypA2: 4×32 from SBOX_A (little-endian)");
    }

    [Fact(Skip = "Requires full SBOX dump — populate SboxA_Raw from Frida (ECX+0x0CC, 512 bytes)")]
    public void SboxHypothesisB_4x64_FromSboxA_And_SboxB_BfEncryptZeroIv_Matches()
    {
        // Hypothesis: SBOX_A (512 bytes = 128 uint32s) = two 64-entry S-boxes (6-bit index, mask=63).
        //             SBOX_B provides S2+S3 (first 512 bytes used, zero-padded if shorter).
        Assert.True(SboxA_Raw.Length >= 512, "SboxA_Raw must be 512 bytes.");
        Assert.True(SboxB_Raw.Length >= 256, "SboxB_Raw must be ≥256 bytes.");
        var sA = ToUInt32ArrayBE(SboxA_Raw, 128); // 128 entries → S0[0..63], S1[0..63]
        var sBPadded = SboxB_Raw.Length >= 512
            ? SboxB_Raw
            : [..SboxB_Raw, ..new byte[512 - SboxB_Raw.Length]];
        var sB = ToUInt32ArrayBE(sBPadded, 128);
        RunBfEncryptZeroIvTest(sA[0..64], sA[64..128], sB[0..64], sB[64..128],
            "HypB: 4×64, S0/S1 from SBOX_A, S2/S3 from SBOX_B");
    }

    [Fact(Skip = "Requires full SBOX dump — populate SboxA_Raw from Frida (ECX+0x0CC, 512 bytes)")]
    public void SboxHypothesisC_2x128_FromSboxA_SharedSboxes_BfEncryptZeroIv_Matches()
    {
        // Hypothesis: SBOX_A is a single 128-entry table shared by all four S-box slots.
        // BF_F(x) = ((T[(x>>24)&127] + T[(x>>16)&127]) ^ T[(x>>8)&127]) + T[x&127]
        Assert.True(SboxA_Raw.Length >= 512, "SboxA_Raw must be 512 bytes.");
        var s = ToUInt32ArrayBE(SboxA_Raw, 128);
        RunBfEncryptZeroIvTest(s, s, s, s, "HypC: single 128-entry table for all S-boxes");
    }

    [Fact(Skip = "Requires full SBOX dump — populate SboxA_Raw from Frida (ECX+0x0CC, 512 bytes)")]
    public void SboxHypothesisD_4x32_InterleavedFromSboxA_BfEncryptZeroIv_Matches()
    {
        // Hypothesis: SBOX_A entries are interleaved: S0[0],S1[0],S2[0],S3[0],S0[1],...
        Assert.True(SboxA_Raw.Length >= 512, "SboxA_Raw must be 512 bytes.");
        var flat = ToUInt32ArrayBE(SboxA_Raw, 128);
        var s0 = new uint[32]; var s1 = new uint[32];
        var s2 = new uint[32]; var s3 = new uint[32];
        for (var i = 0; i < 32; i++)
        {
            s0[i] = flat[i * 4 + 0];
            s1[i] = flat[i * 4 + 1];
            s2[i] = flat[i * 4 + 2];
            s3[i] = flat[i * 4 + 3];
        }
        RunBfEncryptZeroIvTest(s0, s1, s2, s3, "HypD: 4×32 interleaved from SBOX_A");
    }

    [Fact(Skip = "Requires full SBOX dump — populate SboxA_Raw from Frida (ECX+0x0CC, 512 bytes)")]
    public void SboxHypothesisE_4x32_SboxA_Tail_BfEncryptZeroIv_Matches()
    {
        // Hypothesis: the FIRST 128 bytes of SBOX_A are header/metadata; real S-boxes start at offset 128.
        // This covers the case where ECX+0xCC starts mid-struct and S-boxes begin at +0x4C from there.
        Assert.True(SboxA_Raw.Length >= 512, "SboxA_Raw must be 512 bytes.");
        var s = ToUInt32ArrayBE(SboxA_Raw[128..], 96); // remaining 384 bytes → 96 entries
        if (s.Length < 128)
        {
            // Pad to 4×32 if needed
            var padded = new uint[128];
            s.CopyTo(padded, 0);
            s = padded;
        }
        RunBfEncryptZeroIvTest(s[0..32], s[32..64], s[64..96], s.Length >= 128 ? s[96..128] : new uint[32],
            "HypE: 4×32 from SBOX_A tail (skip first 128 bytes)");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void RunBfEncryptZeroIvTest(uint[] s0, uint[] s1, uint[] s2, uint[] s3, string label)
    {
        var iv    = new byte[8];
        var input = new byte[8]; // all zeros → output = BF_encrypt(0,0) verbatim

        using var enc = new BlowfishCfb64Cipher(encrypting: true);
        enc.SetRawState(FridaP, s0, s1, s2, s3);
        enc.SetIv(iv);
        enc.Encrypt(input);

        Assert.True(input.SequenceEqual(ExpectedBfEncryptZeroIv),
            $"{label}: BF_encrypt(0,0) mismatch.\n" +
            $"  actual  : {Hex(input)}\n" +
            $"  expected: {Hex(ExpectedBfEncryptZeroIv)}\n" +
            $"  delta   : {Hex(input.Zip(ExpectedBfEncryptZeroIv, (a, e) => (byte)(a ^ e)))}");
    }

    /// <summary>Read bytes as big-endian uint32 array (game memory dump format).</summary>
    private static uint[] ToUInt32ArrayBE(byte[] bytes, int count)
    {
        var result = new uint[count];
        for (var i = 0; i < count && (i + 1) * 4 <= bytes.Length; i++)
            result[i] = ((uint)bytes[i * 4] << 24) | ((uint)bytes[i * 4 + 1] << 16) |
                        ((uint)bytes[i * 4 + 2] << 8) | bytes[i * 4 + 3];
        return result;
    }

    /// <summary>Read bytes as little-endian uint32 array (x86 native).</summary>
    private static uint[] ToUInt32ArrayLE(byte[] bytes, int count)
    {
        var result = new uint[count];
        for (var i = 0; i < count && (i + 1) * 4 <= bytes.Length; i++)
            result[i] = bytes[i * 4] | ((uint)bytes[i * 4 + 1] << 8) |
                        ((uint)bytes[i * 4 + 2] << 16) | ((uint)bytes[i * 4 + 3] << 24);
        return result;
    }

    private static string Hex(IEnumerable<byte> bytes) =>
        string.Join(" ", bytes.Select(b => b.ToString("x2")));
}

