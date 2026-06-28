using Sentinel.Crypto.Interfaces;

namespace Sentinel.Crypto;

/// <summary>
/// TQ-customized CAST5 (CAST-128) cipher in CFB64 mode — the port-19000 game
/// stream cipher. Ported faithfully from the verified reference reproduction
/// (<c>cast_repro.js</c>) that reproduced three live packets across both
/// directions and both keys, including a <c>SENTINELPROBE123</c> known-plaintext
/// capture.
///
/// <para>
/// Why a stock CAST5 / BouncyCastle call will NOT work:
/// <list type="bullet">
///   <item>The S-box lookups use the RFC-2144 CAST5 S-box <b>values</b> but with a
///   <b>−1 index offset</b> (box[b] = standard_Sx[b−1]). The boxes embedded below
///   were dumped from Conquer.exe at base <c>0x0171E030</c> with that offset already
///   baked in, so they are indexed directly.</item>
///   <item>The round function pairs S-boxes to input bytes in the TQ-specific
///   arrangement transcribed from <c>FUN_01266300</c>.</item>
/// </list>
/// </para>
///
/// <para>
/// Cipher state model (confirmed by live capture):
/// <list type="bullet">
///   <item><b>One</b> key schedule shared by both directions — inject via
///   <see cref="SetRawState"/>.</item>
///   <item><b>Two</b> independent (ivec, num) stream states, one per direction;
///   this instance holds one, matching the per-direction <see cref="ICipher"/> model.</item>
///   <item>CFB64 framing (8-byte block; ivec feedback; <c>num</c> = byte offset 0..7)
///   is byte-identical to OpenSSL <c>BF_cfb64_encrypt</c> and the verified reference.</item>
/// </list>
/// </para>
///
/// <para>
/// The schedule cannot be derived from a raw key (the DH→schedule KDF is virtualized
/// in the client and un-reversed), so <see cref="SetKey"/> throws; the schedule must
/// be injected from a live capture.
/// </para>
/// </summary>
public sealed class Cast5VariantCfb64Cipher : ICipher
{
    // RFC-2144 CAST5 S-box values with the TQ −1 index offset baked in, dumped
    // from Conquer.exe at 0x0171E030 / E430 / E830 / EC30. Stored little-endian,
    // 256 × uint32 each.
    private const string B0Hex = "bf65815cd440fb300bffa09f2fcdec6b7a8c253f2f3f211ed34d009c40e5036049c99fcf27afd4bfb5bdbb88904003e27596d098e0a0636e190185191d66e7c28effd4226f3b682859d07fc0c87923ffe2505f77d340c34356862fdf1aa47c882dbdd2a2d6e0c9a119486c34876db7612f0f5422e132be2a6b1654aa3a8e5622d041d3a2c840db662f3984a72fff4d00ded2b92dac3f9497d8c1974ab7447652a737f4b5efba2cb859d151d7edf0f76f1f7a095ad0687b822ef5ec9054c0b02235598ebc7f2f6d4ba264bb50104966d22d81e5be902233b79f153be911e48eb45d34ff4b40c245fd3f9731ad2ed0f6c46581fc55adcab1d5ae2daca16db7d4a2500c9bc1f2402288384f6e0cd7bfe4a472a25b4f2f1d4c5619539cc554e349b9fe6946b08aabb6b1dd5813c745c585635d930f11d58a53579304396ae0373de6b3f6542a5f7d783ab5a07662dffca6196a20427ad5d4f92991181bf65e2772bb678150aa91109038eb05b5c68ccbc7840f5ad72a27144a876b93d1a2af86d22a91d256aa604389d70d755c42269eb393c98471182db3006c14bbe2733cbcbea079376254ab9e4564828b323f82cf1877a6cea2592e00ee04e678fe895009ab3fc2f65f32053f3881c8c56369d65acb76c97499d4cf0d18cad5820738f65cfac71115c38a139ee735d091da4786900ff49e41e2a74162363195f41e05043b57aa8d5d804ad00083543c2a3200dfcd64bf8ea657ba2b37c67541d3af507532c1a7f50b5a91abbf546b26140b2bd7c94cab82cd9c4465f2fbf7f3c585ab94db551b24e3d4aa3fbda4cfe2a3ea2d024d209eac25bdc8b355dfea989ebdd5b23112e36cadd52ade2943952845bead220113200fc951aaf66b78aa1e3f51229ba751aacc44d32af0415a7badfb7cd30595061b91e4ec41e632c3b4d4682203cc0a60c96d7e38ce6cb16bbf78fb706ac9d9030dde39dfd4da6310e064f43647d828d35a96cc47b3c30fbb75fb1b519835ccfb4f6acf8bb5bc0a1fe14afec5bf10ec0aa70a5739ac2f44043f53b188612e7a39e079cb27578f41eb9c8dd6ac1c967cd32a9dcb750109ff9dc6f0655bc7d840dbd979770eecd4ea444774321cb19ecb24ddbd541c7ef94411f0b10e24d2fdb375965537aca3af277cd44d5fc85196759056e615bba5f0040358f12c04caea371a01dbaabf8d4a3eba35a0ff2635094d7bc3d96e30bc6626a59825f748569d565effd063ed0ccfb2637ce1450b70f150ead57228a985a7bd1faf704823d4f30b87a7794d3b2d9841e042e7edd00cb80d47264c8181f8d76a4d475c5e0c7c591923d198721b38dbf4d2f5538683ab231e2f6e9e9c718346e091bd6e45569a0c2039dc71c5c8201cda2b96ff96e6e108ab41b1b989ca7c83e7691a4348cc0279c5f7a27df49e429c167b4249f0c95a000f8fdd";
    private const string B1Hex = "f1ec23459410201f5ba70bef7ecfe36980433f397acf61fe7a20c5ee949c88555106fc7279efa7ad35721d4ece635ad5ba3604deef30c49994070c5f7ddbdc18f3efd6a17b2fb5a00536e85994b015ee09d9ffe9860044dc594494efb3cc83bafbcdc3e08141dad1b12a093bc1f197f97bcfe6a5db0d42015befe7e441ffa12506f880e18010c41f7aee9b17a9c67ad3a43058fe7f8bde984e3fe877699292797b9ffa245bc813e18300c4ac253550d75f61eaf754311462634b550d2111685d59c366c873cf633dc034e2ce877ed8d4212b675c81611f077f62f73984301e363b57ebe4a4642f609ccd3ad63546bc1b2d03819e0cf50127b47a849979dfe3a08cf36cba943084105ea93725fe6f6ff41f3bffa16afb8c20748c458f27a2e0d9343ac74e694f88fcdfe84d3e88000eef8d6459358c38458a6643801dfd9b1d72bb8486a5336325e812824e8498808d12b43fd3fee10a28cea59be12752c2a6d5bd5497e4dd55d6c5647066eb4d0b847701a8b6a1a926db8419018519b743f0216058d0e58430f05472f46f0653a11aa35547dcdabf5d62b5e61b5668946bca833bd26e2ddb01cfecbad0d3a65c3d80b609a777af4ca3b433d6c87b39952be25e04530e5f616fed816443e72078135eb49b6318de22a11c88d12667b9e8a749807bdab722252d555e37d272521c95d2794c890dc602b48c485bfea41b6b9fb0a4cf15a81c05300ca263df7188cb2fdeb9e9c9c60c53ffee0b174521e3352854b43c29639f29e741ee7c2d1d6e86520450f385661ec60134f3952ca2305008a731130f93601784f973599826a1445c64eca977c852a633ffcd41172ba0a2d9ba7c6f038021089cd95061483fcb65d76bc2abf6a3647626348022011320fcd1e6e4e610c72080b6f0cd3b4d84174df8ee31e424087eeb49cb2cae3b6a848878f78ff6605dee7356f77adb5cdd2fc13116a1436ff63054ecfab3fad77f15cc7985ef58de52d15efd2fdb19ce328f7af96a30f83ef002d59a31990ffa42c2b0ebe3a706498ec60c23dab828308280c8f3dedc71b15fd3c81b8a0860c5c0bee8c9a3614df5a8bcfaef2fc7992e8222b470c582894ed9d8bc341c8be6161e3079e93b27a6eaffb0c6b8d9616948b2003fceffb73b28dc085af6da439897e1f72fb71976a49b1c8fa03786dcb1d3a716b793c39feb6e13a73ec6bcc64237511abc2868efd6650352ab776a2d4bed273516d21f822e6e5c09fbf292dbcb29ea5ef59258147f4f58917b698354cca8672648601985eaac4b8cd4603883f9e0230d8a7e386c49d2e60a0c6084b21d7335d847c6b1dcea564cacb381bd3eb0ab0e2387bc3864fab1b5f0b3a25e8f424618fc7a6b030abd89b04f89a59d645e4145a32383035cb93b5d3e7295d7437cd06d7e1edfdf06efc46c6c39a5607170bebf7305768783";
    private const string B2Hex = "833735ee40c2ef8d9f5dfa25bf3d90eb07c910e8ff7f60474be49f3644c61f8c90caceaebff9b1beeacafbee5019cfe8ae07df5106880e924805adf0838d3ce1d51070929f7d1011b97d6407d4e4e3b25e284f3d20a8afb9e082defa8b2667a02e797282c0b23f552be29a489497efd4bc3f5e12eefcff21fd1b5b82edc5559240a2571202831a4eff7fe0bae74682520e14578ebff7733388819f8ce84efca6a5b582c9b71dc0a864c29f57314f09675f3fbdf2c1f7ff40fc8db71fc1d26b8e9be57b43bf3db09919018519e6c08d63999d81551cc897a16e2d014a284a88c5716fc3cc13c243b8f143076c3c8909835fdded0f50e87f2f7e7fc0d7bf7f5002049afb5ad0d247a72e1951163ebf70af8013c3582e30985fc4c37c7202b40f0a82ef7f0fadfd968cae2a2c5d499ae98eb888da50a0f427849057ac1e2201132015dc52829b7dbdef7d5972a6d840a8ad0445f54503745dfa05c33ee81a75914fc269569241e9ef232ef103a9f20d2760b6e476027465fd94b2857992cbdb7682768177028d91aff89ef7484edf6d618f0e849de2837d2f84c8e50c3482b6bb9648b1b493ab3c30ef28af4f989baf9f770d56dc92201e4d2288aa378496dc297ddcd35627ee7c908b40d21fb5e37cc0e7a1b466e55e61e9c39d20f83ce3d1946041a39ccd0e46765c3b98ea008178d6d42c5747fdd9ed6cf79c22a8bdaaad7d124e078a4390c0971f8adb1b08be7ea09315ca38b9ff3cb097f8c0c23decb21a8d510e3864fb7bcc6888270fd981014912d4ffe55d6af87edd14e2a2766803a4b98f955d92faff394be9ae39ba0bd3ffa43b93f7fa2386496dfabc3c19457562277af45c82a08bbd61d1421ed1f404adce92a37e12b78d421072a97282a8c470920be57d12c8a15b284ff4623ca5eac03531d205e8fb29894282dffcb4536ab64f5bc17d0eab1f081fae1886106d08fdfc8928fff911cc4b69ae5c6a234dcade12c58c3f2cfe2dd0d29658eff8da52cfe4675b15958c484a490ca8b6b9bc828f5c456bd3893794603aa9c900ec53527144494b870a40bc73d71c67347cf67e71023655eb4fff2fd0a2c460bfd2c0033fd46defb450d18c470788186e00553fe5a2bcd4e6b9168004a233385797677d20d73d8f0fde337bf872334fccab5dc58876b0a6007b01007b94d2750057f888bbf99e014289ffa56442e00263852bd9db72691b97eede2fa26e2bae085f6d617aaf6787c9e5d2eb1fcfc2c8ef617125acf1c23982ccb84c2167d183e5b1623edcb7cebd107f385c0af93d44f00fc66d6e60493a546048c127571d8ae92b3817b48a24bee1200fda96af25844568e53b83997d450d6050932f2862b3348320111dd9a08d6d2b311e2b64005a309c88e6bc528a58031bd5efbaf79ced4241115c31a4c53e32833646efdf01c533a11c53d3e9";
    private const string B3Hex = "d27eef0a2004b39ddee9b61fef7bbea798a273d2db7b4f4a578cad6443045185d10e02faff7a287e63b60fe6a1355f0920f1eb79439d05fdb1b79764631f64f3df4a1e245f7f1428cdb8a24f400043c92022c30c300bd3fd4f37a5c0d9002d1d157b14241a114dee6751ca0f4c90ff71fe5f192d5f64051afefe130cca081b082101170500015380fe5e3ee8f8f49aac0127e77f5feeb8d26142df068a9b9ebb25ea9372dfff84ce018871f5044bd63d3b266fa20084d47ee6eb7e54a04c6d44f5d6f36cdfab4926f5c7a0aec18c3336937e3f50612077d3e138b611030e5072bbb20ef82e50e0abde778dec811e975746674fe1005433c98f31206999bb1d08a504c3ff0518354de35c3d7f19018519a9cc5b5dea6fecda916f929f2f22469f7d4691398e6dbfa54fc4431102839543eb4e21d0b88320020c18b63f1e93f818e65816283e6e4826708ad78bc1e477747ce006b5250a2df3028b097981bbeae4233b122838adde6916ca7415621b87dfb7401c21f99e1aa57b371400c88a1e0403401109d2e459bdd556d1e3d576e84f40a3912fdee87b55a7e4ea00ecc2e50ca6bbb44dffbd56e7ac6933dd35b017ec27235706b0c8af9991c3c8561c81656b1961145e75cb856e02c007be775532c2ecf43f892dc9bf5b253becd0b71a80b7243b6d8def63c720fca566c38028389c0532ce0a8a54c9aa2201132032fa1a045a62161d2c900167547a759bf777d43131b02691db6fcc36468b0bc7486ae6d9795ae556eb4c6a02ff7e4352b4768f2fa580f90de3cd7486eb04daed04bea917dff4182c9d7f74b7b4f72aab204dc3ef7c6b092e54a2411735a0b6e5f6423d21267c1c2c0ff5c261f9da5265f831c2d2690f1325a27f16d8c8f21804a6961a00ab26150d215c3163ec720a5efdfeba49d908791886bd0d8da77011310c649b3ed7103eccb6d3cad588c3ae0ce10130f7ff8a726ca1e2ea716ef39a1f2fd1cbcf1784dec16bbe07acd8a144cb560f9b8bc3883901ca2fc5b1cd31beb4062878d8e2a4a31232e57d6fb67efd5800e91ed0c2ffad24c50f99f4c5aa1197957b1d00d2e7e582f67398109630610021952dc3ff21a1ad158490297f97bb7fdbb39eaf2aedc92965a4e25c2cf330a7e83faad091c05c8ae72c9ed4a954e40c86cd0ad619195f0103910777f63aa0de5e56a878df56e3debe5cf02187e3758b5106c5b3efc3a5b8d2b6eed877be23e5294515c2dfef692ffb7ae6afb2c470f45bebe0f37698ccd60c46e4393885da1f2f838719677300caf84491a99e296b2995c22f49abbe6692696e67b5daddd39b2f057edf1c7025dbee515e1be62453f66ce3fc6a04cc16033e214486d059dcb71f29657943fdd6cc79398241f6cd2b934dc357b682d2df4e0c29e57a6b53b93cfe201e857e553398b0f0ec1372b3ffd3c1c5853f";

    private static readonly uint[] B0 = ParseLe(B0Hex);
    private static readonly uint[] B1 = ParseLe(B1Hex);
    private static readonly uint[] B2 = ParseLe(B2Hex);
    private static readonly uint[] B3 = ParseLe(B3Hex);

    private readonly bool _encrypting;
    private readonly byte[] _iv = new byte[8];

    // Injected schedule: K[2i]=Km[i], K[2i+1]=Kr[i] (i=0..15); K[32] = round flag
    // (0 ⇒ 16 rounds, non-zero ⇒ 12 rounds). One schedule serves both directions.
    private uint[]? _schedule;
    private int _num;
    private bool _disposed;

    /// <param name="encrypting">true for encrypt mode, false for decrypt mode.</param>
    public Cast5VariantCfb64Cipher(bool encrypting) => _encrypting = encrypting;

    /// <summary>
    /// Not supported. The CAST5-variant key schedule is produced inside the client's
    /// virtualized DH handshake (an un-reversed KDF), so it cannot be derived from a
    /// raw key. Inject a captured schedule via <see cref="SetRawState"/> instead.
    /// </summary>
    public void SetKey(ReadOnlySpan<byte> key) =>
        throw new NotSupportedException(
            "Cast5VariantCfb64Cipher cannot derive a schedule from a key — the DH→schedule " +
            "KDF is virtualized in the client. Inject a captured schedule via SetRawState.");

    /// <summary>
    /// Inject a captured CAST5 key schedule. Layout: at least 33 32-bit words, where
    /// K[2i]=Km[i] and K[2i+1]=Kr[i] for i in 0..15, and K[32] is the round-count flag
    /// (0 ⇒ 16 rounds, non-zero ⇒ 12 rounds). A single schedule serves both directions.
    /// Resets the streaming counter to 0.
    /// </summary>
    public void SetRawState(ReadOnlySpan<uint> schedule)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (schedule.Length < 33)
            throw new ArgumentException(
                "CAST5 schedule requires at least 33 words (32 Km/Kr + round flag at index 32).",
                nameof(schedule));
        _schedule = schedule[..33].ToArray();
        _num = 0;
    }

    public void SetIv(ReadOnlySpan<byte> iv)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (iv.Length != 8)
            throw new ArgumentException("IV must be exactly 8 bytes for CFB64.", nameof(iv));
        iv.CopyTo(_iv);
        _num = 0;
    }

    /// <summary>
    /// Set the starting CFB64 byte offset (0..7) within the current 8-byte keystream
    /// block. Must be called AFTER <see cref="SetIv"/> / <see cref="SetRawState"/>, both
    /// of which reset it to 0. Needed to resume a stream mid-block (e.g. a packet
    /// captured at num≠0, like the capstone vector at num=2).
    /// </summary>
    public void SetNum(int num)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (num is < 0 or > 7)
            throw new ArgumentOutOfRangeException(nameof(num), num, "CFB64 num must be 0..7.");
        _num = num;
    }

    public void Encrypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_encrypting)
            throw new InvalidOperationException("This cipher instance is configured for decryption.");
        EnsureSchedule();

        for (var i = 0; i < data.Length; i++)
        {
            if (_num == 0)
                EncryptIvBlock();

            // CFB64 encrypt: ivec[num] ^= plaintext; output = ivec[num] (= ciphertext, the feedback).
            _iv[_num] ^= data[i];
            data[i] = _iv[_num];
            _num = (_num + 1) & 7;
        }
    }

    public void Decrypt(Span<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_encrypting)
            throw new InvalidOperationException("This cipher instance is configured for encryption.");
        EnsureSchedule();

        for (var i = 0; i < data.Length; i++)
        {
            if (_num == 0)
                EncryptIvBlock();

            // CFB64 decrypt: save ciphertext, output = ivec[num] ^ ciphertext, ivec[num] = ciphertext.
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
        if (_disposed) return;
        _disposed = true;
        Array.Clear(_iv);
        _schedule = null;
    }

    private void EnsureSchedule()
    {
        if (_schedule is null)
            throw new InvalidOperationException(
                "No schedule set — call SetRawState with a captured CAST5 schedule first.");
    }

    /// <summary>
    /// CFB64 feedback step: transform the 8-byte IV block in place using the
    /// CAST5-variant block (<c>FUN_01266300</c>). Called whenever the 8-byte keystream
    /// block is exhausted (num wraps to 0). The block uses three alternating round
    /// functions (f1/f2/f3 ≡ <see cref="MixA"/>/<see cref="MixB"/>/<see cref="MixC"/>),
    /// key-dependent 5-bit rotations, and 12/16 rounds selected by K[32].
    /// </summary>
    private void EncryptIvBlock()
    {
        var k = _schedule!;
        uint l = ReadBe(_iv, 0);
        uint r = ReadBe(_iv, 4);

        uint v3 = MixA(Rotl(k[0] + r, k[1])) ^ l;
        uint v4 = r ^ MixB(Rotl(k[2] ^ v3, k[3]));
        v3 ^= MixC(Rotl(k[4] - v4, k[5]));
        v4 ^= MixA(Rotl(k[6] + v3, k[7]));
        v3 ^= MixB(Rotl(k[8] ^ v4, k[9]));
        v4 ^= MixC(Rotl(k[10] - v3, k[11]));
        v3 ^= MixA(Rotl(k[12] + v4, k[13]));
        v4 ^= MixB(Rotl(k[14] ^ v3, k[15]));
        v3 ^= MixC(Rotl(k[16] - v4, k[17]));
        v4 ^= MixA(Rotl(k[18] + v3, k[19]));
        v3 ^= MixB(Rotl(k[20] ^ v4, k[21]));
        v4 ^= MixC(Rotl(k[22] - v3, k[23]));

        if (k[32] == 0) // 16-round schedule
        {
            v3 ^= MixA(Rotl(k[24] + v4, k[25]));
            v4 ^= MixB(Rotl(k[26] ^ v3, k[27]));
            v3 ^= MixC(Rotl(k[28] - v4, k[29]));
            v4 ^= MixA(Rotl(k[30] + v3, k[31]));
        }

        // Block output: left ← v4, right ← v3.
        WriteBe(_iv, 0, v4);
        WriteBe(_iv, 4, v3);
    }

    // Round functions. Box-to-byte pairing transcribed from FUN_01266300:
    //   B0 ← byte1 (u>>8), B1 ← byte0 (u), B2 ← byte3 (u>>24), B3 ← byte2 (u>>16).
    private static uint MixA(uint u) => ((B0[(u >> 8) & 0xff] ^ B1[u & 0xff]) + B3[(u >> 16) & 0xff]) - B2[(u >> 24) & 0xff];
    private static uint MixB(uint u) => ((B0[(u >> 8) & 0xff] - B1[u & 0xff]) + B2[(u >> 24) & 0xff]) ^ B3[(u >> 16) & 0xff];
    private static uint MixC(uint u) => ((B0[(u >> 8) & 0xff] + B1[u & 0xff]) ^ B2[(u >> 24) & 0xff]) - B3[(u >> 16) & 0xff];

    private static uint Rotl(uint x, uint n)
    {
        n &= 31;
        return n == 0 ? x : (x << (int)n) | (x >> (32 - (int)n));
    }

    private static uint ReadBe(byte[] b, int off) =>
        ((uint)b[off] << 24) | ((uint)b[off + 1] << 16) | ((uint)b[off + 2] << 8) | b[off + 3];

    private static void WriteBe(byte[] b, int off, uint v)
    {
        b[off]     = (byte)(v >> 24);
        b[off + 1] = (byte)(v >> 16);
        b[off + 2] = (byte)(v >> 8);
        b[off + 3] = (byte) v;
    }

    /// <summary>Parse a hex string into little-endian uint32 words.</summary>
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
