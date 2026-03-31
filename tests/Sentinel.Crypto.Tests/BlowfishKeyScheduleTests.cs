using System.Reflection;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Sentinel.Crypto.Tests;

/// <summary>
/// Investigates the CO 7xxx modified Blowfish variant and validates that
/// raw P-array injection into BlowfishCfb64Cipher works correctly.
///
/// Key findings so far:
///   - Standard 18-round BF with "R3Xx97ra5i8D6uZz" → P[0]=0xf63b79f9 (wrong)
///   - 14-round BF with Pi S-boxes              → P[0]=0xfe0612fa (wrong)
///   - Hypothesis: CO uses 14-round BF with ZERO S-boxes (F=0 always)
///
/// Frida-observed P[0]-P[15] for the handshake cipher context:
/// </summary>
public class BlowfishKeyScheduleTests
{
    private const uint FridaP0 = 0xdb298a75u;
    private static readonly byte[] HandshakeKey = "R3Xx97ra5i8D6uZz"u8.ToArray();

    // The 16 P-array values captured directly from Conquer.exe memory via Frida.
    // These are the COMPLETE cipher state for the handshake cipher — no S-boxes needed
    // if the zero-S-box hypothesis is correct.
    private static readonly uint[] FridaP = [
        0xdb298a75, 0x3c83ff0c, 0x0dec4548, 0xf8c273e0,
        0x38a99512, 0xfc7fcfc8, 0x4e110080, 0xf8c13f63,
        0x8523e092, 0x8f496087, 0x9fbc973b, 0x22969a7b,
        0xb892fffa, 0xf6d19ec7, 0xf6c53add, 0x5a66f96e,
    ];

    // -----------------------------------------------------------------------
    // HYPOTHESIS TEST — does zero-S-box 14-round key schedule reproduce
    // the Frida-observed P[0] = 0xdb298a75?
    // If this passes, the complete CO handshake cipher algorithm is confirmed.
    // -----------------------------------------------------------------------

    [Fact]
    public void ZeroSbox14Round_HandshakeKey_ProducesExpectedP0()
    {
        // Zero S-boxes: F(x) = ((0+0)^0)+0 = 0 for every input.
        // This makes BF a simple sequence of XOR operations — no lookup tables.
        var zeroSbox = new uint[256];
        var p = Blowfish14RoundSchedule.Compute(HandshakeKey, GetPiP(), zeroSbox, zeroSbox, zeroSbox, zeroSbox);

        Assert.True(p[0] == FridaP0,
            $"Zero-S-box 14-round key schedule does NOT match Frida.\n" +
            $"  Key:      \"{Encoding.ASCII.GetString(HandshakeKey)}\"\n" +
            $"  Actual P[0]:   0x{p[0]:x8}\n" +
            $"  Expected P[0]: 0x{FridaP0:x8}\n" +
            $"  Next step: capture S-boxes from Frida — the game does NOT use zero S-boxes.");
    }

    [Fact]
    public void ZeroSbox14Round_HandshakeKey_AllPValuesMatchFrida()
    {
        var zeroSbox = new uint[256];
        var p = Blowfish14RoundSchedule.Compute(HandshakeKey, GetPiP(), zeroSbox, zeroSbox, zeroSbox, zeroSbox);

        var sb = new StringBuilder();
        var allMatch = true;
        for (var i = 0; i < 16; i++)
        {
            var match = p[i] == FridaP[i];
            if (!match) allMatch = false;
            sb.AppendLine($"P[{i:D2}] computed=0x{p[i]:x8}  frida=0x{FridaP[i]:x8}  {(match ? "OK" : "MISMATCH")}");
        }

        Assert.True(allMatch,
            $"Computed P-array does not fully match Frida dump:\n{sb}");
    }

    // -----------------------------------------------------------------------
    // ALGORITHM TEST — does a BF-CFB64 cipher initialised with the Frida
    // P-array and zero S-boxes round-trip correctly?
    // This validates the algorithm regardless of key schedule outcome.
    // -----------------------------------------------------------------------

    [Fact]
    public void FridaPArray_ZeroSbox_EncryptDecrypt_Roundtrip()
    {
        var plaintext = new byte[]
        {
            (byte)'T', (byte)'Q', (byte)'C', (byte)'l',
            (byte)'i', (byte)'e', (byte)'n', (byte)'t',
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        };

        var iv = new byte[8];
        var buffer = plaintext.ToArray();

        using var enc = new Sentinel.Crypto.BlowfishCfb64Cipher(encrypting: true);
        enc.SetRawKeySchedule(FridaP);
        enc.SetIv(iv);
        enc.Encrypt(buffer);

        Assert.False(buffer.SequenceEqual(plaintext),
            "Encrypt with Frida P-array produced no change — raw key schedule not applied.");

        using var dec = new Sentinel.Crypto.BlowfishCfb64Cipher(encrypting: false);
        dec.SetRawKeySchedule(FridaP);
        dec.SetIv(iv);
        dec.Decrypt(buffer);

        Assert.Equal(plaintext, buffer);
    }

    [Fact]
    public void FridaPArray_ZeroSbox_StreamingChunks_MatchSinglePass()
    {
        var message = new byte[37];
        for (var i = 0; i < message.Length; i++)
            message[i] = (byte)(i * 13 + 7);

        var iv = new byte[8];

        var singlePass = message.ToArray();
        using var enc1 = new Sentinel.Crypto.BlowfishCfb64Cipher(encrypting: true);
        enc1.SetRawKeySchedule(FridaP);
        enc1.SetIv(iv);
        enc1.Encrypt(singlePass);

        var chunked = message.ToArray();
        using var enc2 = new Sentinel.Crypto.BlowfishCfb64Cipher(encrypting: true);
        enc2.SetRawKeySchedule(FridaP);
        enc2.SetIv(iv);
        enc2.Encrypt(chunked.AsSpan(0, 1));
        enc2.Encrypt(chunked.AsSpan(1, 7));
        enc2.Encrypt(chunked.AsSpan(8, 8));
        enc2.Encrypt(chunked.AsSpan(16, 13));
        enc2.Encrypt(chunked.AsSpan(29, 8));

        Assert.Equal(singlePass, chunked);
    }

    // -----------------------------------------------------------------------
    // PREVIOUS DIAGNOSTIC — kept for reference, always fails with full table.
    // -----------------------------------------------------------------------

    [Fact]
    public void CompareAllVariants_PArrayDump()
    {
        var engine = new BlowfishEngine();
        engine.Init(true, new KeyParameter(HandshakeKey));

        var pStd = typeof(BlowfishEngine)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(f => f.FieldType == typeof(uint[]) && !f.IsStatic)
            .Select(f => (uint[])f.GetValue(engine)!)
            .First(arr => arr.Length == 18);

        var piP   = GetPiP();
        var piS   = GetPiSboxes();
        var zeroS = new uint[256];

        var p14Pi   = Blowfish14RoundSchedule.Compute(HandshakeKey, piP, piS[0], piS[1], piS[2], piS[3]);
        var p14Zero = Blowfish14RoundSchedule.Compute(HandshakeKey, piP, zeroS,  zeroS,  zeroS,  zeroS);

        var sb = new StringBuilder();
        sb.AppendLine($"\nKey: \"{Encoding.ASCII.GetString(HandshakeKey)}\"");
        sb.AppendLine($"Frida anchor: P[0] = 0x{FridaP0:x8}\n");
        sb.AppendLine($"{"Index",-7} {"Std-18",-14} {"14r-PiSbox",-14} {"14r-ZeroSbox",-14} Frida");
        sb.AppendLine(new string('-', 72));
        for (var i = 0; i < 16; i++)
        {
            var s  = pStd[i];
            var pi = p14Pi[i];
            var z  = p14Zero[i];
            var f  = FridaP[i];
            sb.AppendLine($"P[{i:D2}]   0x{s:x8}  0x{pi:x8}  0x{z:x8}  0x{f:x8}" +
                          (z == f ? "  ← ZERO-SBOX MATCH" : ""));
        }
        sb.AppendLine(new string('-', 72));
        sb.AppendLine($"P[16]  0x{pStd[16]:x8}  absent     absent     (Frida:0x00000000)");
        sb.AppendLine($"P[17]  0x{pStd[17]:x8}  absent     absent     (Frida:0x00000000)");

        sb.AppendLine($"\nVERDICT:");
        sb.AppendLine($"  Std-18      P[0]=0x{pStd[0]:x8}  {Match(pStd[0])}");
        sb.AppendLine($"  14r-PiSbox  P[0]=0x{p14Pi[0]:x8}  {Match(p14Pi[0])}");
        sb.AppendLine($"  14r-ZeroS   P[0]=0x{p14Zero[0]:x8}  {Match(p14Zero[0])}");

        Assert.Fail(sb.ToString());

        static string Match(uint v) => v == 0xdb298a75u ? "MATCHES FRIDA" : "no match";
    }

    // -----------------------------------------------------------------------
    // Helpers — extract Pi constants from BouncyCastle's static fields so we
    // don't embed 1024 uint literals in this file.
    // -----------------------------------------------------------------------

    private static uint[] GetPiP()
    {
        var kp = (uint[])typeof(BlowfishEngine)
            .GetField("KP", BindingFlags.NonPublic | BindingFlags.Static)!
            .GetValue(null)!;
        return kp[..16].ToArray();
    }

    private static uint[][] GetPiSboxes()
    {
        var t = typeof(BlowfishEngine);
        var flags = BindingFlags.NonPublic | BindingFlags.Static;
        return [
            (uint[])t.GetField("KS0", flags)!.GetValue(null)!,
            (uint[])t.GetField("KS1", flags)!.GetValue(null)!,
            (uint[])t.GetField("KS2", flags)!.GetValue(null)!,
            (uint[])t.GetField("KS3", flags)!.GetValue(null)!,
        ];
    }
}

/// <summary>
/// Self-contained 14-round Blowfish key schedule (16 P-array entries).
/// S-boxes are supplied as parameters — pass zero-filled arrays to test the
/// hypothesis that CO 7xxx uses Blowfish with no S-box initialisation.
///
/// With zero S-boxes F(x) = 0 for every input, reducing each round to a
/// simple XOR of the two halves with the corresponding P value.
/// </summary>
internal static class Blowfish14RoundSchedule
{
    private const int P_SIZE   = 16;
    private const int ROUNDS   = 14;
    private const int SBOX_SIZE = 256;

    public static uint[] Compute(
        byte[] key,
        uint[] kp,           // initial P values (Pi digits for standard; any for custom)
        uint[] ks0, uint[] ks1, uint[] ks2, uint[] ks3)  // S-boxes (pass zeros to test zero-sbox variant)
    {
        var P  = kp[..P_SIZE].ToArray();
        var S0 = ks0.ToArray();
        var S1 = ks1.ToArray();
        var S2 = ks2.ToArray();
        var S3 = ks3.ToArray();

        // Step 1: XOR P[0..15] with repeating key bytes.
        var keyOff = 0;
        for (var i = 0; i < P_SIZE; i++)
        {
            uint word = 0;
            for (var b = 0; b < 4; b++)
            {
                word = (word << 8) | key[keyOff % key.Length];
                keyOff++;
            }
            P[i] ^= word;
        }

        // Step 2: Fill P, then S-boxes by successive encryption of an
        // all-zero block with the evolving key state.
        uint xL = 0, xR = 0;

        for (var i = 0; i < P_SIZE; i += 2)
        {
            (xL, xR) = Encrypt(xL, xR, P, S0, S1, S2, S3);
            P[i] = xL; P[i + 1] = xR;
        }
        for (var i = 0; i < SBOX_SIZE; i += 2)
        {
            (xL, xR) = Encrypt(xL, xR, P, S0, S1, S2, S3);
            S0[i] = xL; S0[i + 1] = xR;
        }
        for (var i = 0; i < SBOX_SIZE; i += 2)
        {
            (xL, xR) = Encrypt(xL, xR, P, S0, S1, S2, S3);
            S1[i] = xL; S1[i + 1] = xR;
        }
        for (var i = 0; i < SBOX_SIZE; i += 2)
        {
            (xL, xR) = Encrypt(xL, xR, P, S0, S1, S2, S3);
            S2[i] = xL; S2[i + 1] = xR;
        }
        for (var i = 0; i < SBOX_SIZE; i += 2)
        {
            (xL, xR) = Encrypt(xL, xR, P, S0, S1, S2, S3);
            S3[i] = xL; S3[i + 1] = xR;
        }

        return P;
    }

    // 14-round BF encrypt.  Output convention: (xr, xl) — standard BF output swap.
    internal static (uint, uint) Encrypt(
        uint xl, uint xr,
        uint[] P, uint[] S0, uint[] S1, uint[] S2, uint[] S3)
    {
        xl ^= P[0];
        for (var i = 1; i <= ROUNDS - 1; i += 2)
        {
            xr ^= F(xl, S0, S1, S2, S3) ^ P[i];
            xl ^= F(xr, S0, S1, S2, S3) ^ P[i + 1];
        }
        xr ^= P[ROUNDS + 1]; // P[15]
        return (xr, xl);     // output swap
    }

    private static uint F(uint x, uint[] S0, uint[] S1, uint[] S2, uint[] S3) =>
        ((S0[x >> 24] + S1[(x >> 16) & 0xFF]) ^ S2[(x >> 8) & 0xFF]) + S3[x & 0xFF];
}
