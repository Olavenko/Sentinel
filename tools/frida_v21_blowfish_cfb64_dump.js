/* ============================================================================
 * frida_v21_blowfish_cfb64_dump.js
 *
 * PURPOSE
 *   Observe the CO 7xxx Game-connection (port 19000) Blowfish-CFB64 cipher at
 *   its function boundary and capture everything the (virtualized) DH handshake
 *   code feeds into it: the key schedule, the raw pre-expansion key, the IV /
 *   CFB stream state, and the plaintext<->ciphertext pair for every call.
 *   This unblocks game-traffic decryption WITHOUT devirtualizing the .vlizer
 *   DH code. Pure observation at the cipher boundary — it touches no DH code.
 *
 * TARGET  (Env_DX9 build of Conquer.exe; image base 0x00400000, x86, no ASLR)
 *   SHA-256 B9CDCA1E1856FC1F56E034B800935495E380691D0B698BF53B22BBD41696A2B5
 *
 *   BF_cfb64_encrypt  VA 0x012c29e0   (file offset 0x00EC29E0)   <- primary
 *   BF_set_key        VA 0x012c1b40   (file offset 0x00EC1B40)   <- raw key
 *
 *   NOTE: prior reports listed BF_cfb64_encrypt @ 0x012410f0 — that address is
 *   a floating-point routine (FUN_01241000) in THIS binary and is WRONG. The
 *   addresses above were re-verified in Ghidra: pi-init constant 0x243F6A88 ->
 *   BF_set_key (memcpy 0x1048) -> BF_encrypt (S-box offsets +0x12/+0x112/
 *   +0x212/+0x312) -> mode-function callers; the 30-byte entry signature for
 *   BF_cfb64_encrypt is unique (1 hit) in the module.
 *
 * CONFIRMED SIGNATURE  (OpenSSL standard, __cdecl — all 7 args on the stack)
 *   void BF_cfb64_encrypt(const uchar *in,   // args[0]
 *                         uchar       *out,  // args[1]
 *                         long         length,// args[2]
 *                         const BF_KEY *sched,// args[3]  4168 bytes (0x1048)
 *                         uchar       *ivec, // args[4]  8 bytes
 *                         int         *num,  // args[5]  CFB position 0..7
 *                         int          enc); // args[6]  0=decrypt(S->C) else encrypt(C->S)
 *
 *   void BF_set_key(BF_KEY *key,             // args[0]  4168-byte schedule out
 *                   int     len,             // args[1]  raw key length
 *                   const uchar *data);      // args[2]  raw key bytes
 *
 * HOW TO RUN
 *   The game is launched via play.exe -> Conquer.exe, so attach by name. To be
 *   sure you catch BF_set_key (it fires when the Game handshake derives the
 *   key), attach at the character-select screen BEFORE entering the game world:
 *
 *     frida -n Conquer.exe -l frida_v21_blowfish_cfb64_dump.js --runtime=v8 -o frida_v21_bf_<timestamp>.log
 *
 *   (ndac.dll anti-cheat is present but has not been observed to detect Frida.)
 *
 * WHAT TO LOOK FOR
 *   - "RAW KEY" lines from BF_set_key  -> the actual Blowfish key string. If it
 *     is identical across two logins, the game key is STATIC (recoverable once).
 *   - "schedule hash" per key context  -> flagged STATIC (reused) vs NEW
 *     (per-session). Settles the static-vs-per-session question directly.
 *   - DECRYPT(S->C) "out" buffers ending in ASCII "TQServer" (and ENCRYPT(C->S)
 *     "out"/in containing "TQClient") -> proof the hook is on the real game
 *     cipher and the bytes line up with the protocol framing.
 *   - "ivec(before/after)" + "num"     -> the live per-direction CFB stream
 *     state to seed the proxy's BlowfishCfb64Cipher.
 * ========================================================================== */

'use strict';

// ---- Configuration ---------------------------------------------------------
const MODULE_NAME = 'Conquer.exe';
const OFF_CFB64   = 0xEC29E0;   // BF_cfb64_encrypt
const OFF_SETKEY  = 0xEC1B40;   // BF_set_key
const KEY_SIZE    = 0x1048;     // BF_KEY: P[18] (0x48) + S0..S3 (0x1000)
const MAX_DUMP    = 512;        // cap per-buffer hexdump bytes (logs stay sane)
const DUMP_FULL_SCHEDULE = false; // true => hexdump all 4168 bytes on first sight

// Unique entry signature for BF_cfb64_encrypt (rel32 to __alloca_probe masked).
const SIG_CFB64 = 'B8 08 00 00 00 E8 ?? ?? ?? ?? 8B 44 24 20 55 8B 6C 24 18 56 8B 30 85 ED 0F 84 D9 01 00 00';

// ---- State -----------------------------------------------------------------
let   callIdx        = 0;
const scheduleByCtx  = {};  // keyPtr   -> { hash, firstTs, calls }
const seenHashes     = {};  // hash     -> keyPtr first seen with it (static detect)
const streamByIvec   = {};  // ivecPtr  -> { label, dir }
const rawKeyByCtx    = {};  // keyPtr   -> raw key hex (from BF_set_key)
const rawKeyCounts   = {};  // raw hex  -> count (static raw-key detect)
let   t0             = Date.now();

// ---- Helpers ---------------------------------------------------------------
function ts() { return ((Date.now() - t0) / 1000).toFixed(3); }
function log(s) { console.log(s); }

function toHex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += ('0' + u8[i].toString(16)).slice(-2);
  return s;
}
function toAscii(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) {
    const c = u8[i];
    s += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
  }
  return s;
}
function readU8(p, n) { try { return new Uint8Array(p.readByteArray(n)); } catch (e) { return null; } }

function djb2(p, len) {
  const b = readU8(p, len);
  if (!b) return 0;
  let h = 5381;
  for (let i = 0; i < b.length; i++) h = (((h << 5) + h) ^ b[i]) >>> 0;
  return h >>> 0;
}

function dumpBuf(label, p, len) {
  if (len <= 0) { log('  ' + label + ': <empty len=' + len + '>'); return; }
  const n = Math.min(len, MAX_DUMP);
  try {
    log('  ' + label + ' (' + len + ' bytes' + (len > n ? ', showing first ' + n : '') + '):');
    log(hexdump(p, { offset: 0, length: n, header: false, ansi: false }));
  } catch (e) { log('  ' + label + ': <read error ' + e + '>'); }
}

function findMarker(p, len) {
  const n = Math.min(len, MAX_DUMP);
  const b = readU8(p, n);
  if (!b) return null;
  const s = toAscii(b);
  if (s.indexOf('TQServer') !== -1) return 'TQServer';
  if (s.indexOf('TQClient') !== -1) return 'TQClient';
  return null;
}

function streamLabel(ivecPtr, dir) {
  const key = ivecPtr.toString();
  if (!streamByIvec[key]) {
    const idx = Object.keys(streamByIvec).length + 1;
    streamByIvec[key] = { label: 'STREAM#' + idx, dir: dir };
    log('[' + ts() + '] NEW stream ' + streamByIvec[key].label +
        '  ivecCtx=' + ivecPtr + '  dir=' + dir);
  }
  return streamByIvec[key].label;
}

// Verify N expected bytes at addr (null entries are wildcards).
function bytesMatch(addr, expected) {
  const b = readU8(addr, expected.length);
  if (!b) return false;
  for (let i = 0; i < expected.length; i++)
    if (expected[i] !== null && b[i] !== expected[i]) return false;
  return true;
}

// Resolve by fixed offset (no ASLR); sanity-gate the prologue; fall back to sig.
function resolve(label, offset, sanity, sig) {
  const m = Process.getModuleByName(MODULE_NAME);
  const addr = m.base.add(offset);
  if (bytesMatch(addr, sanity)) {
    log('[resolve] ' + label + ' -> ' + addr + '  (base ' + m.base +
        ' + 0x' + offset.toString(16) + ')  [offset+prologue OK]');
    return addr;
  }
  log('[resolve] ' + label + ' prologue mismatch at offset — trying signature scan...');
  if (sig) {
    const hits = Memory.scanSync(m.base, m.size, sig);
    if (hits.length === 1) {
      log('[resolve] ' + label + ' -> ' + hits[0].address + '  [unique signature]');
      return hits[0].address;
    }
    log('[resolve] ' + label + ' signature hits=' + hits.length + ' (ambiguous) — ABORT this hook');
  }
  return null;
}

// Shared prologue: B8 08 00 00 00 E8 (MOV EAX,8 ; CALL __alloca_probe)
const PROLOGUE = [0xB8, 0x08, 0x00, 0x00, 0x00, 0xE8];

// ---- Hooks -----------------------------------------------------------------
function installSetKey() {
  const addr = resolve('BF_set_key', OFF_SETKEY, PROLOGUE, null);
  if (!addr) { log('[!] BF_set_key not installed'); return; }

  Interceptor.attach(addr, {
    onEnter(args) {
      this.keyPtr = args[0];
      this.len    = args[2] ? args[1].toInt32() : 0; // guard
      const len   = Math.max(0, Math.min(this.len, 256));
      const raw   = readU8(args[2], len);
      this.rawHex = raw ? toHex(raw) : '<unreadable>';
      this.rawAsc = raw ? toAscii(raw) : '';
    },
    onLeave() {
      const hash = djb2(this.keyPtr, KEY_SIZE);
      const ctx  = this.keyPtr.toString();
      rawKeyByCtx[ctx] = this.rawHex;
      rawKeyCounts[this.rawHex] = (rawKeyCounts[this.rawHex] || 0) + 1;
      const seenN = rawKeyCounts[this.rawHex];

      log('');
      log('================ BF_set_key ================  [' + ts() + ']');
      log('  keyCtx     = ' + this.keyPtr + '   schedHash=0x' + hash.toString(16));
      log('  RAW KEY    = ' + this.rawHex + '   ("' + this.rawAsc + '")  len=' + this.len);
      log('  raw-key seen ' + seenN + 'x' +
          (seenN > 1 ? '  >>> STATIC raw key (identical across derivations)' : '  (first time)'));
      const p = this.keyPtr;
      log('  P[0..3]    = ' + toHex(readU8(p, 16)));
      if (DUMP_FULL_SCHEDULE) dumpBuf('schedule', p, KEY_SIZE);
      log('============================================');
    }
  });
}

function installCfb64() {
  const addr = resolve('BF_cfb64_encrypt', OFF_CFB64, PROLOGUE, SIG_CFB64);
  if (!addr) { log('[!] BF_cfb64_encrypt not installed'); return; }

  Interceptor.attach(addr, {
    onEnter(args) {
      this.in     = args[0];
      this.out    = args[1];
      this.len    = args[2].toInt32();
      this.keyPtr = args[3];
      this.ivec   = args[4];
      this.numPtr = args[5];
      this.enc    = args[6].toInt32();
      this.dir    = this.enc !== 0 ? 'ENCRYPT C->S' : 'DECRYPT S->C';
      this.idx    = ++callIdx;

      let numBefore = -1;
      try { numBefore = this.numPtr.readU32(); } catch (e) {}
      this.numBefore = numBefore;
      this.ivecBefore = readU8(this.ivec, 8);

      const label = streamLabel(this.ivec, this.dir);

      // Schedule static-vs-per-session tracking.
      const ctx  = this.keyPtr.toString();
      const hash = djb2(this.keyPtr, KEY_SIZE);
      let firstSchedule = false;
      if (!scheduleByCtx[ctx]) {
        firstSchedule = true;
        scheduleByCtx[ctx] = { hash: hash, firstTs: ts(), calls: 0 };
        if (seenHashes[hash] && seenHashes[hash] !== ctx)
          this.schedNote = '>>> STATIC schedule (identical to earlier ctx ' + seenHashes[hash] + ')';
        else
          this.schedNote = '>>> NEW schedule (possible per-session key)';
        if (!seenHashes[hash]) seenHashes[hash] = ctx;
      } else if (scheduleByCtx[ctx].hash !== hash) {
        this.schedNote = '!!! WARNING: schedule for ctx ' + ctx + ' CHANGED mid-session';
        scheduleByCtx[ctx].hash = hash;
      }
      scheduleByCtx[ctx].calls++;
      this.firstSchedule = firstSchedule;
      this.hash = hash;
      this.label = label;

      log('');
      log('---- #' + this.idx + '  [' + ts() + ']  ' + label + '  ' + this.dir + '  ----');
      log('  len=' + this.len + '  keyCtx=' + this.keyPtr + '  ivecCtx=' + this.ivec +
          '  num(before)=' + this.numBefore + '  schedHash=0x' + hash.toString(16));
      if (this.ivecBefore) log('  ivec(before)= ' + toHex(this.ivecBefore));
      if (firstSchedule) {
        log('  ' + this.schedNote);
        const rk = rawKeyByCtx[ctx];
        if (rk) log('  (raw key for this ctx from BF_set_key: ' + rk + ')');
        log('  P[0..3]= ' + toHex(readU8(this.keyPtr, 16)));
        if (DUMP_FULL_SCHEDULE) dumpBuf('schedule', this.keyPtr, KEY_SIZE);
      } else if (this.schedNote) {
        log('  ' + this.schedNote);
      }
      dumpBuf('in', this.in, this.len);
    },

    onLeave() {
      let numAfter = -1;
      try { numAfter = this.numPtr.readU32(); } catch (e) {}
      const ivecAfter = readU8(this.ivec, 8);

      dumpBuf('out', this.out, this.len);
      if (ivecAfter) log('  ivec(after) = ' + toHex(ivecAfter) + '   num(after)=' + numAfter);

      // out is plaintext on DECRYPT, ciphertext on ENCRYPT; scan both buffers
      // for the protocol framing tags as a correctness oracle.
      const marker = findMarker(this.out, this.len) || findMarker(this.in, this.len);
      if (marker) log('  >>> protocol marker "' + marker + '" present — hook is on the real game cipher');
    }
  });
}

// ---- Bootstrap -------------------------------------------------------------
function main() {
  const m = Process.getModuleByName(MODULE_NAME);
  log('==================================================================');
  log(' frida_v21 BF_cfb64_encrypt / BF_set_key dump');
  log(' module ' + MODULE_NAME + '  base=' + m.base + '  size=0x' + m.size.toString(16));
  log(' expected base 0x00400000 (no ASLR). If base differs, offsets still');
  log(' resolve relative to module base; signature fallback guards mismatches.');
  log('==================================================================');
  installSetKey();
  installCfb64();
  log('[*] Hooks installed. Enter the game world (port 19000) to trigger calls.');
}

main();
