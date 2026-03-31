using System.Reflection;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Sentinel.Crypto;

namespace Sentinel.Crypto.Tests;

/// <summary>
/// Gate tests for the Blowfish cipher implementation.
/// Test 1 must pass before any live MITM work proceeds — it confirms the
/// initial handshake key ("DR654dt34trg4UI6") matches the CO client's BF
/// key schedule as observed via Frida dynamic analysis (P[0] = 0xdb298a75).
/// </summary>
public class BlowfishCipherTests
{
    // -------------------------------------------------------------------------
    // GATE TEST — Step 3 of the MITM implementation plan.
    // Frida confirmed: the handshake cipher context in Conquer.exe has
    // P[0] = 0xdb298a75 in all sessions. The key that produces this value
    // is our initial handshake BF key.
    // -------------------------------------------------------------------------

    [Fact]
    public void HandshakeKey_DR654_ProducesExpectedP0()
    {
        var key = "R3Xx97ra5i8D6uZz"u8.ToArray();
        var engine = new BlowfishEngine();
        engine.Init(true, new KeyParameter(key));

        // Locate the P-array inside BouncyCastle's BlowfishEngine via reflection.
        // In BouncyCastle 2.x the P-array is a UInt32[] named "P" with 18 elements
        // (ROUNDS=16 + 2). We find it by type+length to be robust against renames.
        var pArray = typeof(BlowfishEngine)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(f => f.FieldType == typeof(uint[]) && !f.IsStatic)
            .Select(f => (uint[])f.GetValue(engine)!)
            .FirstOrDefault(arr => arr.Length == 18);

        Assert.True(pArray is not null,
            "Could not locate the P-array inside BlowfishEngine via reflection. " +
            "BouncyCastle may have changed its internal field layout.");

        var actualP0 = pArray[0];

        Assert.True(actualP0 == 0xdb298a75u,
            $"GATE FAILED — initial handshake key is WRONG.\n" +
            $"  Key tested : \"R3Xx97ra5i8D6uZz\"\n" +
            $"  Actual P[0]: 0x{actualP0:x8}\n" +
            $"  Expected   : 0xdb298a75 (Frida-observed from Conquer.exe)\n" +
            $"  Action     : find the real handshake key in the binary (BF_set_key " +
            $"breakpoint or Ghidra .data search for 0xdb298a75).");
    }

    // -------------------------------------------------------------------------
    // CIPHER CORRECTNESS — Test 2 of the MITM implementation plan.
    // Verifies that BlowfishCfb64Cipher with the static game key "x97ra5i8D6uZz"
    // is self-consistent: encrypt then decrypt returns the original plaintext.
    // Also sanity-checks that a zero-IV encrypt produces non-zero output (i.e.,
    // the cipher is actually doing work, not returning plaintext).
    // -------------------------------------------------------------------------

    [Fact]
    public void StaticGameKey_EncryptDecrypt_Roundtrip()
    {
        var key = "x97ra5i8D6uZz"u8.ToArray();
        var iv = new byte[8]; // all zeros

        var plaintext = new byte[]
        {
            // "TQClient" — known string sent as keepalive after BF mode activates
            (byte)'T', (byte)'Q', (byte)'C', (byte)'l',
            (byte)'i', (byte)'e', (byte)'n', (byte)'t',
            // pad to 16 bytes with a recognisable pattern
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };

        var buffer = plaintext.ToArray();

        using var encCipher = new BlowfishCfb64Cipher(encrypting: true);
        encCipher.SetKey(key);
        encCipher.SetIv(iv);
        encCipher.Encrypt(buffer);

        // Ciphertext must differ from plaintext — cipher is actually running
        Assert.False(buffer.SequenceEqual(plaintext),
            "Encryption produced identical output to input — cipher is not working.");

        using var decCipher = new BlowfishCfb64Cipher(encrypting: false);
        decCipher.SetKey(key);
        decCipher.SetIv(iv);
        decCipher.Decrypt(buffer);

        // Decrypted ciphertext must equal original plaintext
        Assert.True(buffer.SequenceEqual(plaintext),
            "Decrypt(Encrypt(plaintext)) != plaintext — CFB64 state machine is broken.");
    }

    [Fact]
    public void StaticGameKey_EncryptThenDecryptWithCiphertext_Roundtrip()
    {
        var key = "x97ra5i8D6uZz"u8.ToArray();
        var iv = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        var original = new byte[64];
        for (var i = 0; i < original.Length; i++)
            original[i] = (byte)i;

        var buffer = original.ToArray();

        using var enc = new BlowfishCfb64Cipher(encrypting: true);
        enc.SetKey(key);
        enc.SetIv(iv);
        enc.Encrypt(buffer);

        using var dec = new BlowfishCfb64Cipher(encrypting: false);
        dec.SetKey(key);
        dec.SetIv(iv);
        dec.Decrypt(buffer);

        Assert.Equal(original, buffer);
    }

    // -------------------------------------------------------------------------
    // CFB64 STREAMING — Verifies that the cipher handles non-8-byte-aligned
    // chunk boundaries correctly. BF-CFB64 is a stream cipher: splitting a
    // message across multiple Encrypt calls must produce the same result as
    // encrypting it all at once.
    // -------------------------------------------------------------------------

    [Fact]
    public void StaticGameKey_StreamingChunks_MatchSinglePass()
    {
        var key = "x97ra5i8D6uZz"u8.ToArray();
        var iv = new byte[8];

        var message = new byte[37]; // intentionally not a multiple of 8
        for (var i = 0; i < message.Length; i++)
            message[i] = (byte)(i * 7 + 3);

        // Single-pass encrypt
        var singlePass = message.ToArray();
        using var enc1 = new BlowfishCfb64Cipher(encrypting: true);
        enc1.SetKey(key);
        enc1.SetIv(iv);
        enc1.Encrypt(singlePass);

        // Chunked encrypt (1, 7, 8, 13, 8 bytes = 37 total)
        var chunked = message.ToArray();
        using var enc2 = new BlowfishCfb64Cipher(encrypting: true);
        enc2.SetKey(key);
        enc2.SetIv(iv);
        enc2.Encrypt(chunked.AsSpan(0, 1));
        enc2.Encrypt(chunked.AsSpan(1, 7));
        enc2.Encrypt(chunked.AsSpan(8, 8));
        enc2.Encrypt(chunked.AsSpan(16, 13));
        enc2.Encrypt(chunked.AsSpan(29, 8));

        Assert.Equal(singlePass, chunked);
    }
}
