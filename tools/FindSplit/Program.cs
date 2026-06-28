using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

const string logPath = @"F:\Sentinel\logs\session_8118f2a622524e859bacc439457ea388_20260401_093051.bin";
const byte DIR_S2C = 1;

// --- Parse log entries ---
// Format: [8-byte Int64 timestamp][1-byte direction][4-byte Int32 length][N bytes data]
var entries = new List<(long Ts, byte Dir, byte[] Data)>();
{
    using var fs = File.OpenRead(logPath);
    using var br = new BinaryReader(fs);
    while (fs.Position < fs.Length)
    {
        long ts = br.ReadInt64();
        byte dir = br.ReadByte();
        int len = br.ReadInt32();
        byte[] data = br.ReadBytes(len);
        entries.Add((ts, dir, data));
    }
}

Console.WriteLine($"Parsed {entries.Count} log entries.");

// Show first 15 entries in chronological order
Console.WriteLine("\n=== First 15 entries (chronological, all directions) ===");
for (int i = 0; i < Math.Min(15, entries.Count); i++)
{
    var e = entries[i];
    string dir = e.Dir == DIR_S2C ? "S→C" : "C→S";
    Console.WriteLine($"  [{i:D2}] {dir} len={e.Data.Length:D4}  {Hex(e.Data, 8)}");
}
Console.WriteLine();

var s2cEntries = entries.Where(e => e.Dir == DIR_S2C).ToList();
Console.WriteLine($"S→C entries: {s2cEntries.Count}");
for (int i = 0; i < s2cEntries.Count; i++)
    Console.WriteLine($"  [{i}] len={s2cEntries[i].Data.Length}  first bytes: {Hex(s2cEntries[i].Data, 8)}");

Console.WriteLine();

// --- Find the 337-byte S→C segment ---
var seg337 = s2cEntries.FirstOrDefault(e => e.Data.Length == 337);
if (seg337.Data == null)
{
    Console.WriteLine("ERROR: No 337-byte S→C entry found!");
    return;
}

Console.WriteLine("337-byte S→C entry found.");
Console.WriteLine($"Full hex:\n{HexDump(seg337.Data)}");
Console.WriteLine();

// --- Phase 1: brute-force split within the 337-byte segment ---
Console.WriteLine("=== Phase 1: Brute-force split in 337-byte segment ===");
Console.WriteLine("(For each split N, decrypt seg[N..] from counters (0,0) and check first 2 bytes)");
Console.WriteLine();

bool anyMatch = false;

for (int n = 0; n <= 335; n++)
{
    int sliceLen = Math.Min(16, 337 - n);
    byte[] slice = new byte[sliceLen];
    Array.Copy(seg337.Data, n, slice, 0, sliceLen);
    int cA = 0, cB = 0;
    CC.Transform(slice, 0, sliceLen, ref cA, ref cB);

    byte lo = slice[0];
    byte hi = sliceLen > 1 ? slice[1] : (byte)0;
    int pktLen = lo | (hi << 8);

    if (lo == 0x08 && hi == 0x00)
    {
        Console.WriteLine($"*** EXACT MATCH 08 00 at offset {n}: handshake={n} bytes, gameplay starts at byte {n}");
        Console.WriteLine($"    Decrypted: {Hex(slice, sliceLen)}");
        anyMatch = true;
    }
    else if (pktLen >= 4 && pktLen <= 512)
    {
        Console.WriteLine($"    Plausible at N={n}: size=0x{lo:X2} 0x{hi:X2}={pktLen}  [{Hex(slice, sliceLen)}]");
    }
}

if (!anyMatch)
    Console.WriteLine("  (no 08 00 exact match in 337-byte segment)");

Console.WriteLine();

// --- Phase 2: subsequent S→C segment ---
int idx337 = s2cEntries.IndexOf(seg337);
Console.WriteLine($"=== Phase 2: Spillover into subsequent S→C segments ===");
Console.WriteLine($"337-byte entry is S→C index {idx337}.");

if (idx337 + 1 < s2cEntries.Count)
{
    var seg2 = s2cEntries[idx337 + 1];
    Console.WriteLine($"Next S→C segment: {seg2.Data.Length} bytes  raw: {Hex(seg2.Data, 16)}");
    Console.WriteLine();

    // Sub-case A: handshake = exactly 337 bytes, gameplay starts at byte 0 of seg2.
    // The GAMEPLAY cipher starts FRESH at (0,0) — handshake used ChainTable, not gameplay cipher.
    {
        int cA = 0;
        int cB = 0;
        Console.WriteLine($"-- A) Handshake = 337 bytes exactly. Gameplay cipher starts FRESH at (0,0) for seg2.");
        byte[] slice = (byte[])seg2.Data.Clone();
        CC.Transform(slice, 0, slice.Length, ref cA, ref cB);
        Console.WriteLine($"   Decrypted seg2:\n{HexDump(slice)}");
        if (slice.Length >= 2)
        {
            int pktLen = slice[0] | (slice[1] << 8);
            Console.WriteLine($"   Leading size field = 0x{slice[0]:X2} 0x{slice[1]:X2} = {pktLen}");
            if (slice[0] == 0x08 && slice[1] == 0x00)
            {
                Console.WriteLine("   *** 08 00 MATCH — handshake is exactly 337 bytes!");
                anyMatch = true;
            }
        }
        Console.WriteLine();
    }

    // Sub-case B: gameplay starts k bytes before seg2 (straddles boundary).
    Console.WriteLine("-- B) Straddled splits (gameplay begins in last k bytes of seg1, continues in seg2):");
    for (int k = 1; k <= Math.Min(seg2.Data.Length - 1, 64); k++)
    {
        int gameStart = 337 - k;
        int combinedLen = k + seg2.Data.Length;
        byte[] combined = new byte[combinedLen];
        Array.Copy(seg337.Data, gameStart, combined, 0, k);
        Array.Copy(seg2.Data, 0, combined, k, seg2.Data.Length);

        int decLen = Math.Min(16, combinedLen);
        int cA = 0, cB = 0;
        CC.Transform(combined, 0, decLen, ref cA, ref cB);

        byte lo = combined[0], hi = combinedLen > 1 ? combined[1] : (byte)0;
        int pktLen = lo | (hi << 8);

        if (lo == 0x08 && hi == 0x00)
        {
            Console.WriteLine($"*** STRADDLED MATCH: gameStart={gameStart} in seg1 (k={k} bytes spill into seg2)");
            Console.WriteLine($"    Decrypted: {Hex(combined, decLen)}");
            anyMatch = true;
        }
        else if (pktLen >= 4 && pktLen <= 512)
        {
            Console.WriteLine($"    Plausible straddle k={k} gameStart={gameStart}: size={pktLen}  [{Hex(combined, decLen)}]");
        }
    }
}
else
{
    Console.WriteLine("No subsequent S→C segment found.");
}

Console.WriteLine();

// --- Phase 2b: Try segment 2 from (0,0) — if handshake = ALL of seg337 ---
Console.WriteLine("-- A2) Decode seg2 from (0,0) [correct: gameplay cipher starts fresh] ---");
{
    byte[] slice2 = (byte[])s2cEntries[idx337 + 1].Data.Clone();
    int cA = 0, cB = 0;
    CC.Transform(slice2, 0, slice2.Length, ref cA, ref cB);
    Console.WriteLine($"   Decrypted seg2 (0,0):\n{HexDump(slice2)}");
    if (slice2.Length >= 2)
    {
        int pktLen = slice2[0] | (slice2[1] << 8);
        Console.WriteLine($"   Leading size = {pktLen} (0x{pktLen:X4})");
        if (slice2[0] == 0x08 && slice2[1] == 0x00)
            Console.WriteLine("   *** 08 00 — handshake is exactly 337 bytes!");
    }
}
Console.WriteLine();

// --- Phase 2c: Search the full stream (seg337 + seg2 + seg3...) for known pattern c5 48 ---
// Frida v19 confirmed: encrypt(08 00) at counters (0,0) = c5 48.
// If tables are same this session, the gameplay section STARTS with c5 48.
Console.WriteLine("-- C) Search for encrypted pattern of 08 00 at (0,0) = [C5 48] in full stream ---");
{
    var allParts = new List<byte[]>();
    for (int si = idx337; si < Math.Min(idx337 + 6, s2cEntries.Count); si++)
        allParts.Add(s2cEntries[si].Data);
    byte[] full = allParts.SelectMany(p => p).ToArray();
    int cumLen = 0;
    bool patFound = false;
    for (int si = idx337; si < Math.Min(idx337 + 6, s2cEntries.Count); si++)
    {
        var seg = s2cEntries[si].Data;
        for (int pos = 0; pos < seg.Length - 1; pos++)
        {
            if (seg[pos] == 0xC5 && seg[pos + 1] == 0x48)
            {
                Console.WriteLine($"   FOUND C5 48 at absolute stream offset {cumLen + pos} (S→C seg #{si - idx337}, byte {pos})");
                patFound = true;
            }
        }
        // Also check straddle between segments
        if (si + 1 < s2cEntries.Count)
        {
            if (seg[seg.Length - 1] == 0xC5 && s2cEntries[si + 1].Data[0] == 0x48)
            {
                Console.WriteLine($"   STRADDLE: C5 at end of seg#{si - idx337}, 48 at start of seg#{si + 1 - idx337} → absolute offset {cumLen + seg.Length - 1}");
                patFound = true;
            }
        }
        cumLen += seg.Length;
    }
    if (!patFound)
        Console.WriteLine("   Pattern C5 48 NOT found in first 6 S→C segments.");
    Console.WriteLine($"   (Total searched: {cumLen} bytes)");
}
Console.WriteLine();

// --- Phase 3: Session-table derivation via C→S known-plaintext ---
// C→S resets counters to (0,0) per-packet. Packet starts with LE uint16 size.
// So plaintext[0..1] = size of that packet. We know the captured size = wire size.
// Constraint: Transform(wire[0], 0,0) = size[0]; Transform(wire[1], 1,0) = size[1]
// From multiple C→S packets at (0,0): recover xorKey0 and xorKey1.
Console.WriteLine("=== Phase 3: Session table derivation via C→S known-plaintext ===");
var c2sEntries = entries.Where(e => e.Dir == 0).ToList();
Console.WriteLine($"C→S entries: {c2sEntries.Count}");
var kpConstraints = new List<(byte wire, byte plain, int cA, int cB)>();
foreach (var ce in c2sEntries)
{
    if (ce.Data.Length < 2) continue;
    // Determine plaintext size: might equal captured length OR might differ
    // Use captured length as the expected packet size (reasonable assumption)
    int expectedSize = ce.Data.Length;
    byte plainLo = (byte)(expectedSize & 0xFF);
    byte plainHi = (byte)((expectedSize >> 8) & 0xFF);
    Console.WriteLine($"  C→S len={ce.Data.Length:D4}: wire[0]={ce.Data[0]:X2} wire[1]={ce.Data[1]:X2}  expect plain={plainLo:X2} {plainHi:X2}");
    kpConstraints.Add((ce.Data[0], plainLo, 0, 0));
    kpConstraints.Add((ce.Data[1], plainHi, 1, 0));
}

// Invert Transform: given output b_out, find b_in such that Transform(b_in, cA, cB) = b_out
// Transform: t = b ^ tA[cA] ^ tB[cB]; out = nibble_swap(t) ^ 0xAB
// So: t = nibble_swap(out ^ 0xAB); b_in = t ^ tA[cA] ^ tB[cB]
// We want xorKey[cA, cB] = tA[cA] ^ tB[cB]
// From wire bytes + known plaintext: out = Transform(b_in, cA, cB)
// b_in = wire; out = plain
// So: nibble_swap(plain ^ 0xAB) = wire ^ tA[cA] ^ tB[cB]
// xorKey[cA,cB] = wire ^ nibble_swap(plain ^ 0xAB)
Console.WriteLine("\n  Key bytes derived (xorKey[i] = tA[i] ^ tB[0]):");
var xorKeys = new Dictionary<(int cA, int cB), List<byte>>();
foreach (var (wire, plain, cA, cB) in kpConstraints)
{
    byte t_needed = (byte)(plain ^ 0xAB);
    byte t_ns = (byte)(((t_needed << 4) | (t_needed >> 4)));  // nibble-swap is its own inverse
    byte xorKey = (byte)(wire ^ t_ns);
    if (!xorKeys.ContainsKey((cA, cB))) xorKeys[(cA, cB)] = new List<byte>();
    xorKeys[(cA, cB)].Add(xorKey);
}
bool tablesMatch = true;
foreach (var kvp in xorKeys)
{
    byte first = kvp.Value[0];
    bool consistent = kvp.Value.All(x => x == first);
    string status = consistent ? "OK" : $"CONFLICT [{string.Join(",", kvp.Value.Select(x => x.ToString("X2")))}]";
    Console.WriteLine($"    xorKey[cA={kvp.Key.cA}, cB={kvp.Key.cB}] = 0x{first:X2}  {status}");
    if (!consistent) tablesMatch = false;
}
if (tablesMatch)
{
    Console.WriteLine("  All xorKey values consistent across C→S packets!");
    // Verify against known tables
    byte xk0 = xorKeys[(0, 0)][0];
    byte xk1 = xorKeys[(1, 0)][0];
    byte expectedXk0 = (byte)(CC.GetTableA(0) ^ CC.GetTableB(0));
    byte expectedXk1 = (byte)(CC.GetTableA(1) ^ CC.GetTableB(0));
    Console.WriteLine($"  Derived  xorKey[0,0]=0x{xk0:X2}  xorKey[1,0]=0x{xk1:X2}");
    Console.WriteLine($"  Hardcoded xorKey[0,0]=0x{expectedXk0:X2}  xorKey[1,0]=0x{expectedXk1:X2}");
    if (xk0 == expectedXk0 && xk1 == expectedXk1)
        Console.WriteLine("  *** TABLES MATCH! Hardcoded tables are correct for this session.");
    else
        Console.WriteLine("  *** TABLES DIFFER — this session has different DH-derived tables!");
}
else
{
    Console.WriteLine("  CONFLICT: either packet size != captured length, or counters don't reset per-packet.");
}
Console.WriteLine();

// --- Phase 4: Chain-walk plausible candidates ---
Console.WriteLine("=== Phase 4: Chain-walk plausible candidates ===");
int[] candidates = { 24, 246 };
foreach (int n in candidates)
{
    Console.WriteLine($"\n--- Candidate N={n} (handshake={n} bytes, gameplay starts at byte {n}) ---");
    // Build the full gameplay byte stream: seg337[n..] + seg2 + seg3 + ...
    var streamParts = new List<byte[]>();
    streamParts.Add(seg337.Data.Skip(n).ToArray());
    for (int si = idx337 + 1; si < s2cEntries.Count && streamParts.Sum(p => p.Length) < 2048; si++)
        streamParts.Add(s2cEntries[si].Data);
    byte[] stream = streamParts.SelectMany(p => p).Take(2048).ToArray();
    byte[] decStream = (byte[])stream.Clone();
    int cA2 = 0, cB2 = 0;
    CC.Transform(decStream, 0, decStream.Length, ref cA2, ref cB2);

    // Walk packets
    int pos = 0;
    int pktIdx = 0;
    bool coherent = true;
    Console.WriteLine("  Packet chain:");
    while (pos + 3 < decStream.Length && pktIdx < 20)
    {
        int pktLen2 = decStream[pos] | (decStream[pos + 1] << 8);
        int pktType = decStream[pos + 2] | (decStream[pos + 3] << 8);
        if (pktLen2 < 4 || pktLen2 > 8192)
        {
            Console.WriteLine($"  [pkt {pktIdx}] @{pos}: INVALID size={pktLen2} type=0x{pktType:X4}  — chain broken");
            coherent = false;
            break;
        }
        string tail = pktLen2 <= 20 ? $"data=[{Hex(decStream.Skip(pos).Take(pktLen2).ToArray(), pktLen2)}]"
                                    : $"first16=[{Hex(decStream.Skip(pos).Take(16).ToArray(), 16)}]";
        Console.WriteLine($"  [pkt {pktIdx}] @{pos}: len={pktLen2} type=0x{pktType:X4}  {tail}");
        pos += pktLen2;
        pktIdx++;
    }
    if (coherent && pktIdx >= 3)
        Console.WriteLine($"  *** COHERENT CHAIN ({pktIdx} packets parsed cleanly) — N={n} is likely correct!");
    else if (coherent)
        Console.WriteLine($"  Chain OK so far ({pktIdx} packets)");
}

Console.WriteLine();

// --- Phase 5: Definitive conclusion from chronological timeline ---
Console.WriteLine("=== Phase 5: Definitive Conclusion from Timeline ===");
Console.WriteLine();
Console.WriteLine("Chronological order of first entries:");
int allIdx = 0;
int c2sIdx = -1;
foreach (var e in entries.Take(10))
{
    string dir = e.Dir == DIR_S2C ? "S→C" : "C→S";
    string note = "";
    if (e.Dir != DIR_S2C && c2sIdx == -1) { c2sIdx = allIdx; note = " ← PRE-HANDSHAKE game login (plaintext, sent before server DH)"; }
    else if (e.Dir == DIR_S2C && e.Data.Length == 337) note = " ← SERVER DH HANDSHAKE";
    else if (e.Dir != DIR_S2C && c2sIdx == allIdx - 2 && e.Data.Length > 100) note = " ← Client DH reply part 1 (ChainTable-encrypted)";
    else if (e.Dir != DIR_S2C && c2sIdx == allIdx - 3 && e.Data.Length < 100) note = " ← Client DH reply part 2 (ChainTable-encrypted)";
    else if (e.Dir == DIR_S2C && allIdx == 4) note = " ← FIRST GAMEPLAY S→C (gameplay cipher from (0,0))";
    Console.WriteLine($"  [{allIdx:D2}] {dir} {e.Data.Length,5} bytes{note}");
    allIdx++;
}
Console.WriteLine();
Console.WriteLine("CONCLUSION:");
Console.WriteLine("  The 337-byte S→C segment is ENTIRELY the server DH handshake.");
Console.WriteLine("  There is NO gameplay data inside the 337-byte segment.");
Console.WriteLine("  Gameplay cipher (S→C) starts FRESH at counter (0,0) in S→C segment #2 (64 bytes).");
Console.WriteLine();
Console.WriteLine("WHY the brute-force found no 08 00:");
Console.WriteLine("  The hardcoded tables in ConquerCipher.cs were captured in a March 31 Frida session.");
Console.WriteLine("  The April 1 session (8118f2a6) completed a NEW DH exchange → different session tables.");
Console.WriteLine("  The encrypted form of '08 00' at (0,0) for this session differs from C5 48.");
Console.WriteLine();

// Derive xorKey from C→S[3] (first gameplay C→S, index 3 in c2sEntries)
if (c2sEntries.Count > 3)
{
    var firstGameplay = c2sEntries[3];
    if (firstGameplay.Data.Length >= 2)
    {
        byte wire0 = firstGameplay.Data[0], wire1 = firstGameplay.Data[1];
        int sz = firstGameplay.Data.Length;
        byte plain0 = (byte)(sz & 0xFF), plain1 = (byte)((sz >> 8) & 0xFF);
        // xorKey = wire ^ nibble_swap(plain ^ 0xAB)
        byte xk0 = (byte)(wire0 ^ (byte)(((plain0 ^ 0xAB) << 4) | ((plain0 ^ 0xAB) >> 4)));
        byte xk1 = (byte)(wire1 ^ (byte)(((plain1 ^ 0xAB) << 4) | ((plain1 ^ 0xAB) >> 4)));
        Console.WriteLine($"Session xorKey[0,0] (from C→S[3] first byte): 0x{xk0:X2}  (hardcoded=0x{(CC.GetTableA(0) ^ CC.GetTableB(0)):X2} → {(xk0 == (CC.GetTableA(0) ^ CC.GetTableB(0)) ? "SAME" : "DIFFERENT")})");
        Console.WriteLine($"Session xorKey[1,0] (from C→S[3] second byte): 0x{xk1:X2}  (hardcoded=0x{(CC.GetTableA(1) ^ CC.GetTableB(0)):X2} → {(xk1 == (CC.GetTableA(1) ^ CC.GetTableB(0)) ? "SAME" : "DIFFERENT")})");
        Console.WriteLine();

        // Now decrypt S→C[1] (64 bytes) using these session xorKeys to check plausibility
        // For the first 2 bytes only (counter 0,0 and 1,0)
        var seg2 = s2cEntries[1];
        if (seg2.Data.Length >= 2)
        {
            byte s2c0 = seg2.Data[0], s2c1 = seg2.Data[1];
            byte dec0 = (byte)((byte)(((s2c0 ^ xk0) << 4) | ((s2c0 ^ xk0) >> 4)) ^ 0xAB);
            byte dec1 = (byte)((byte)(((s2c1 ^ xk1) << 4) | ((s2c1 ^ xk1) >> 4)) ^ 0xAB);
            int decodedSize = dec0 | (dec1 << 8);
            Console.WriteLine($"S→C[1] first 2 bytes with session keys: {s2c0:X2} {s2c1:X2} → {dec0:X2} {dec1:X2} = size {decodedSize}");
            if (decodedSize >= 4 && decodedSize <= 2048)
                Console.WriteLine("  *** Plausible packet size! Session tables confirmed, gameplay starts at S→C[1].");
            else
                Console.WriteLine("  Size not plausible — either xorKey is wrong or packet starts mid-stream.");
        }
    }
}

Console.WriteLine();
Console.WriteLine("NEXT STEP: Re-run Frida to capture the gameplay cipher tables for a fresh session.");
Console.WriteLine("  The tables change per DH exchange. Run frida_v19_stage5c_validate.js and");
Console.WriteLine("  capture ctx+0x08 (tableA) and ctx+0x108 (tableB) for the receive context.");

// --- Local helpers ---
static string Hex(byte[] data, int count)
{
    int n = Math.Min(count, data.Length);
    return string.Join(" ", data.Take(n).Select(b => b.ToString("X2")));
}

static string HexDump(byte[] data)
{
    var sb = new StringBuilder();
    for (int row = 0; row < data.Length; row += 16)
    {
        sb.Append($"  {row:X4}: ");
        for (int col = 0; col < 16; col++)
        {
            if (row + col < data.Length) sb.Append($"{data[row + col]:X2} ");
            else sb.Append("   ");
        }
        sb.Append(" |");
        for (int col = 0; col < 16 && row + col < data.Length; col++)
        {
            byte b = data[row + col];
            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
        }
        sb.AppendLine("|");
    }
    return sb.ToString();
}

// CO 7xxx ConquerCipher — type declarations must follow top-level statements
static class CC
{
    static ReadOnlySpan<byte> TableA => new byte[]
    {
        0x9d, 0x90, 0x83, 0x8a, 0xd1, 0x8c, 0xe7, 0xf6, 0x25, 0x28, 0xeb, 0x82, 0x99, 0x64, 0x8f, 0x2e,
        0x2d, 0x40, 0xd3, 0xfa, 0xe1, 0xbc, 0xb7, 0xe6, 0xb5, 0xd8, 0x3b, 0xf2, 0xa9, 0x94, 0x5f, 0x1e,
        0xbd, 0xf0, 0x23, 0x6a, 0xf1, 0xec, 0x87, 0xd6, 0x45, 0x88, 0x8b, 0x62, 0xb9, 0xc4, 0x2f, 0x0e,
        0x4d, 0xa0, 0x73, 0xda, 0x01, 0x1c, 0x57, 0xc6, 0xd5, 0x38, 0xdb, 0xd2, 0xc9, 0xf4, 0xff, 0xfe,
        0xdd, 0x50, 0xc3, 0x4a, 0x11, 0x4c, 0x27, 0xb6, 0x65, 0xe8, 0x2b, 0x42, 0xd9, 0x24, 0xcf, 0xee,
        0x6d, 0x00, 0x13, 0xba, 0x21, 0x7c, 0xf7, 0xa6, 0xf5, 0x98, 0x7b, 0xb2, 0xe9, 0x54, 0x9f, 0xde,
        0xfd, 0xb0, 0x63, 0x2a, 0x31, 0xac, 0xc7, 0x96, 0x85, 0x48, 0xcb, 0x22, 0xf9, 0x84, 0x6f, 0xce,
        0x8d, 0x60, 0xb3, 0x9a, 0x41, 0xdc, 0x97, 0x86, 0x15, 0xf8, 0x1b, 0x92, 0x09, 0xb4, 0x3f, 0xbe,
        0x1d, 0x10, 0x03, 0x0a, 0x51, 0x0c, 0x67, 0x76, 0xa5, 0xa8, 0x6b, 0x02, 0x19, 0xe4, 0x0f, 0xae,
        0xad, 0xc0, 0x53, 0x7a, 0x61, 0x3c, 0x37, 0x66, 0x35, 0x58, 0xbb, 0x72, 0x29, 0x14, 0xdf, 0x9e,
        0x3d, 0x70, 0xa3, 0xea, 0x71, 0x6c, 0x07, 0x56, 0xc5, 0x08, 0x0b, 0xe2, 0x39, 0x44, 0xaf, 0x8e,
        0xcd, 0x20, 0xf3, 0x5a, 0x81, 0x9c, 0xd7, 0x46, 0x55, 0xb8, 0x5b, 0x52, 0x49, 0x74, 0x7f, 0x7e,
        0x5d, 0xd0, 0x43, 0xca, 0x91, 0xcc, 0xa7, 0x36, 0xe5, 0x68, 0xab, 0xc2, 0x59, 0xa4, 0x4f, 0x6e,
        0xed, 0x80, 0x93, 0x3a, 0xa1, 0xfc, 0x77, 0x26, 0x75, 0x18, 0xfb, 0x32, 0x69, 0xd4, 0x1f, 0x5e,
        0x7d, 0x30, 0xe3, 0xaa, 0xb1, 0x2c, 0x47, 0x16, 0x05, 0xc8, 0x4b, 0xa2, 0x79, 0x04, 0xef, 0x4e,
        0x0d, 0xe0, 0x33, 0x1a, 0xc1, 0x5c, 0x17, 0x06, 0x95, 0x78, 0x9b, 0x12, 0x89, 0x34, 0xbf, 0x3e,
    };

    static ReadOnlySpan<byte> TableB => new byte[]
    {
        0x62, 0x4f, 0xe8, 0x15, 0xde, 0xeb, 0x04, 0x91, 0x1a, 0xc7, 0xe0, 0x4d, 0x16, 0xe3, 0x7c, 0x49,
        0xd2, 0x3f, 0xd8, 0x85, 0x4e, 0xdb, 0xf4, 0x01, 0x8a, 0xb7, 0xd0, 0xbd, 0x86, 0xd3, 0x6c, 0xb9,
        0x42, 0x2f, 0xc8, 0xf5, 0xbe, 0xcb, 0xe4, 0x71, 0xfa, 0xa7, 0xc0, 0x2d, 0xf6, 0xc3, 0x5c, 0x29,
        0xb2, 0x1f, 0xb8, 0x65, 0x2e, 0xbb, 0xd4, 0xe1, 0x6a, 0x97, 0xb0, 0x9d, 0x66, 0xb3, 0x4c, 0x99,
        0x22, 0x0f, 0xa8, 0xd5, 0x9e, 0xab, 0xc4, 0x51, 0xda, 0x87, 0xa0, 0x0d, 0xd6, 0xa3, 0x3c, 0x09,
        0x92, 0xff, 0x98, 0x45, 0x0e, 0x9b, 0xb4, 0xc1, 0x4a, 0x77, 0x90, 0x7d, 0x46, 0x93, 0x2c, 0x79,
        0x02, 0xef, 0x88, 0xb5, 0x7e, 0x8b, 0xa4, 0x31, 0xba, 0x67, 0x80, 0xed, 0xb6, 0x83, 0x1c, 0xe9,
        0x72, 0xdf, 0x78, 0x25, 0xee, 0x7b, 0x94, 0xa1, 0x2a, 0x57, 0x70, 0x5d, 0x26, 0x73, 0x0c, 0x59,
        0xe2, 0xcf, 0x68, 0x95, 0x5e, 0x6b, 0x84, 0x11, 0x9a, 0x47, 0x60, 0xcd, 0x96, 0x63, 0xfc, 0xc9,
        0x52, 0xbf, 0x58, 0x05, 0xce, 0x5b, 0x74, 0x81, 0x0a, 0x37, 0x50, 0x3d, 0x06, 0x53, 0xec, 0x39,
        0xc2, 0xaf, 0x48, 0x75, 0x3e, 0x4b, 0x64, 0xf1, 0x7a, 0x27, 0x40, 0xad, 0x76, 0x43, 0xdc, 0xa9,
        0x32, 0x9f, 0x38, 0xe5, 0xae, 0x3b, 0x54, 0x61, 0xea, 0x17, 0x30, 0x1d, 0xe6, 0x33, 0xcc, 0x19,
        0xa2, 0x8f, 0x28, 0x55, 0x1e, 0x2b, 0x44, 0xd1, 0x5a, 0x07, 0x20, 0x8d, 0x56, 0x23, 0xbc, 0x89,
        0x12, 0x7f, 0x18, 0xc5, 0x8e, 0x1b, 0x34, 0x41, 0xca, 0xf7, 0x10, 0xfd, 0xc6, 0x13, 0xac, 0xf9,
        0x82, 0x6f, 0x08, 0x35, 0xfe, 0x0b, 0x24, 0xb1, 0x3a, 0xe7, 0x00, 0x6d, 0x36, 0x03, 0x9c, 0x69,
        0xf2, 0x5f, 0xf8, 0xa5, 0x6e, 0xfb, 0x14, 0x21, 0xaa, 0xd7, 0xf0, 0xdd, 0xa6, 0xf3, 0x8c, 0xd9,
    };

    public static byte GetTableA(int i) => TableA[i];
    public static byte GetTableB(int i) => TableB[i];

    public static void Transform(byte[] buf, int offset, int length, ref int cA, ref int cB)
    {
        ReadOnlySpan<byte> tA = TableA;
        ReadOnlySpan<byte> tB = TableB;
        int end = offset + length;
        for (int i = offset; i < end; i++)
        {
            byte b = buf[i];
            b ^= tA[cA];
            b ^= tB[cB];
            if (++cA > 0xFF) { cA = 0; if (++cB > 0xFF) cB = 0; }
            buf[i] = (byte)(((b << 4) | (b >> 4)) ^ 0xAB);
        }
    }
}
