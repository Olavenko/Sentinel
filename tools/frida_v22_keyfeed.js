/* ============================================================================
 * frida_v22_keyfeed.js
 *
 * PURPOSE
 *   PERSISTENT, per-session KEY FEED for the CO 7xxx Game connection (port
 *   19000) TQ-customized CAST5-variant CFB64 cipher. It hooks the CFB64 driver
 *   at its function boundary, reads the (un-derivable, session-specific) key
 *   schedule plus the per-direction CFB stream init (ivec, num), and writes
 *   them ATOMICALLY to a single key file that the Sentinel proxy will later
 *   watch and load.
 *
 *   The DH -> schedule KDF is virtualized (Code Virtualizer ".vlizer" section)
 *   and cannot be reproduced by the proxy, so this Frida feed is the ONLY way
 *   the proxy can obtain the live schedule. The script is observation-only at
 *   the cipher boundary; it never touches the DH / handshake code.
 *
 * TARGET  (Env_DX9 build of Conquer.exe; image base 0x00400000, x86, no ASLR)
 *   Ghidra image_base 00400000 ; live module base 0x400000 (no ASLR, verified).
 *
 *   CFB64 driver  FUN_01254810  VA 0x01254810   (module offset 0xE54810)
 *     prototype (OpenSSL-style CFB64, __cdecl, 7 stack args):
 *       void cfb64(const u8 *in,    // args[0]
 *                  u8       *out,    // args[1]
 *                  long      length, // args[2]
 *                  const K  *sched,  // args[3]  CAST5 schedule (33 dwords used)
 *                  u8       *ivec,   // args[4]  8-byte CFB feedback block
 *                  int      *num,    // args[5]  CFB byte position 0..7 (in/out)
 *                  int       enc);   // args[6]  0 = decrypt S->C ; !=0 = encrypt C->S
 *     Verified to CALL the CAST5-variant block FUN_01266300 @ 0x01266300, and
 *     to write *num back as (ESI & 7) on exit. That CALL is what proves the
 *     hook is on the real game cipher (the disproven Blowfish hypothesis is
 *     dead -- see CLONE WARNING).
 *
 *   CLONE WARNING -- do NOT hook 0x012c29e0.
 *     A byte-identical-prologue twin lives at 0x012c29e0 (offset 0xEC29E0, the
 *     address the old v21 "Blowfish" script hooked). It is a genuine OpenSSL
 *     BF_cfb64_encrypt but it calls the *Blowfish* block FUN_012c2610, NOT the
 *     CAST5 block, and the port-19000 game never calls it (frida_v21_bf_login1
 *     captured nothing). Because the two drivers share the same 30-byte entry
 *     signature, a bare signature scan is AMBIGUOUS. We resolve by the no-ASLR
 *     fixed OFFSET (0xE54810) and use the prologue only as a sanity gate; the
 *     signature scan is a guarded last resort that ABORTS on ambiguity and is
 *     explicitly blacklisted from ever returning the 0xEC29E0 clone.
 *
 * KEY FILE  (atomic: temp file + MoveFileExA REPLACE_EXISTING|WRITE_THROUGH)
 *   D:\Projects\Sentinel\keys\game-session-<pid>.key.json   (KEY_DIR below; <pid>
 *   is Process.id -- ONE file PER Conquer.exe so several simultaneous clients
 *   never clobber a single shared file. The Sentinel proxy watches the keys\
 *   directory for game-session-*.key.json, treats each as a candidate, and binds
 *   a connection to its key by CONTENT (length->seal), not by the PID.)
 *   {
 *     "schema": 1,
 *     "pid":             <target Conquer.exe PID -- a label / file discriminator>,
 *     "session_id":      "<djb2 hash of the 33-dword schedule, hex8 -- a label>",
 *     "schedule_hex":    "<132 bytes = 33 dwords; the AUTHORITATIVE session key>",
 *     "send_ivec_hex":   "<8 bytes, C->S, or null until first encrypt call>",
 *     "recv_ivec_hex":   "<8 bytes, S->C, or null until first decrypt call>",
 *     "send_num":        <0..7 or null>,
 *     "recv_num":        <0..7 or null>,
 *     "send_switch_offset": <C->S wire byte offset where the DH stream begins, or null>,
 *     "recv_switch_offset": <S->C wire byte offset where the DH stream begins, or null>,
 *     "captured_at":     <epoch ms>,
 *     "captured_at_iso": "<ISO 8601>"
 *   }
 *   The file is OVERWRITTEN in place on every new session and again when the
 *   second direction's ivec arrives. The proxy should treat schedule_hex as the
 *   authoritative session discriminator (session_id is a 32-bit convenience
 *   tag). The atomic rename is the race guard for the proxy's file-watch.
 *
 * NEW-SESSION DETECTION & RETRY
 *   A fresh login runs a fresh DH handshake -> a brand-new schedule. We compare
 *   the full 33-dword (132-byte) schedule each call (raw byte compare, no
 *   per-call allocation); when it differs we treat it as a new session, reset
 *   the captured ivecs, and write a new key file. Only the 132 used bytes are
 *   read, so volatile neighbour memory can never cause a false "new session".
 *   Capture state is persisted via a "dirty" flag: if a write ever fails it is
 *   retried on the next cipher call until the file is on disk (no permanent
 *   miss). ASSUMES a single port-19000 game connection per process (one client
 *   per Conquer.exe); multi-account is supported by running one instance of this
 *   script per game process, each writing its own per-PID key file.
 *
 * STREAM-START GUARD (rejects the static handshake cipher)
 *   The game routes TWO cipher contexts through this same driver: a STATIC
 *   pre-handshake context (a fixed key that recurs identically every login,
 *   seeded from a ZERO ivec) used for the initial port-19000 exchange, and the
 *   real per-session DH context used for all gameplay. To capture ONLY the real
 *   session, we write a direction's ivec only on a clean stream start: num == 0
 *   AND a non-zero ivec. The static context's num==0 calls have a zero ivec, and
 *   its only non-zero-ivec call is mid-stream (num != 0), so it is fully rejected
 *   -- a zero-ivec key file is never written even momentarily. (Verified live:
 *   captures the DH session's send/recv starts, rejects all static-context calls.)
 *
 * SWITCH OFFSET (where the proxy must start decrypting)
 *   Per direction we also emit the cumulative wire byte offset at which the DH
 *   stream begins -- i.e. the total number of STATIC-context (handshake) bytes
 *   that precede it in that direction. We count every cipher-processed byte per
 *   direction from the connection's first call (the static stream start, marked by
 *   num==0 AND a zero ivec, which resets the counter) and latch the count at the
 *   first DH call (num==0 AND non-zero ivec). Because CFB64 is 1:1 plaintext/
 *   ciphertext, this equals the proxy's per-direction forwarded-byte count, so the
 *   proxy can buffer to this offset, seed the cipher (ivec, num=0), and start
 *   decrypting exactly at the static->DH boundary. Measured live: C->S=181, S->C=345.
 *
 * CAPTURE FIDELITY
 *   For a faithful stream start, ATTACH BEFORE logging in so the real session's
 *   first call per direction (num == 0) is observed. If you attach mid-session
 *   that first call is missed and that direction stays uncaptured until the next
 *   fresh login -- a safe fail (no wrong/mid-stream state is ever written).
 *
 * HOW TO RUN
 *   frida -n Conquer.exe -l frida_v22_keyfeed.js --runtime=v8 -o frida_v22_keyfeed.log
 *   then log in once. Watch the console / log for:
 *     [keyfeed] NEW SESSION id=... sched=8e7457db1300...
 *     [keyfeed] WROTE D:\Projects\Sentinel\keys\game-session-<pid>.key.json (...)
 * ========================================================================== */
'use strict';

// ---- Configuration ---------------------------------------------------------
var MODULE_NAME    = 'Conquer.exe';
var OFF_CFB64      = 0xE54810;   // FUN_01254810 = base + 0xE54810 (no-ASLR fixed offset)
var KNOWN_CLONE_OFF = 0xEC29E0;  // 0x012c29e0 Blowfish BF_cfb64_encrypt -- must NEVER hook
var SCHED_BYTES    = 0x84;       // 132 = 33 dwords (K[0..32], K[32]=round flag) -- the exact
                                 // CAST5 schedule the cipher consumes; immutable per session.

var KEY_DIR  = 'D:\\Projects\\Sentinel\\keys';
// PER-PID key file: each Conquer.exe process this script attaches to writes its
// OWN file, so running several clients at once never clobbers a single shared
// file (multi-account). Process.id is the target PID. The proxy watches the
// directory for game-session-*.key.json and matches connections by content.
var PID      = Process.id;
var KEY_FILE = KEY_DIR + '\\game-session-' + PID + '.key.json';
var KEY_TMP  = KEY_FILE + '.tmp';

// 30-byte entry signature. SHARED with the 0x012c29e0 Blowfish clone -> NOT
// unique; used only as a guarded fallback (see resolve()).
var SIG_CFB64 = 'B8 08 00 00 00 E8 ?? ?? ?? ?? 8B 44 24 20 55 8B 6C 24 18 56 8B 30 85 ED 0F 84 D9 01 00 00';
// 6-byte prologue sanity gate: MOV EAX,8 ; CALL rel32 (__alloca_probe).
var PROLOGUE = [0xB8, 0x08, 0x00, 0x00, 0x00, 0xE8];

// ---- Win32 export resolution (robust across Frida 16/17 Module API) ---------
// Pin the lookup to the requested module first; fall back to global search.
function findExport(mod, name) {
  try { var m = Process.getModuleByName(mod); if (m && m.getExportByName) { var a = m.getExportByName(name); if (a) return a; } } catch (e) {}
  try { if (Module.getExportByName) return Module.getExportByName(mod, name); } catch (e) {}
  try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) {}
  try { if (Module.findExportByName) return Module.findExportByName(mod, name); } catch (e) {}
  return null;
}

var pMoveFileExA = findExport('kernel32.dll', 'MoveFileExA');
var pCreateDirA  = findExport('kernel32.dll', 'CreateDirectoryA');
// __stdcall (WINAPI) on x86 -> declare the ABI explicitly (callee cleans the stack).
// SystemFunction returns { value, lastError } for reliable Win32 error reporting.
var MoveFileExA      = pMoveFileExA ? new SystemFunction(pMoveFileExA, 'int', ['pointer', 'pointer', 'uint32'], 'stdcall') : null;
var CreateDirectoryA = pCreateDirA  ? new NativeFunction(pCreateDirA, 'int', ['pointer', 'pointer'], 'stdcall') : null;
var MOVEFILE_REPLACE_EXISTING = 0x1;
var MOVEFILE_WRITE_THROUGH    = 0x8;

// ---- Byte / hash helpers ----------------------------------------------------
// Returns a Uint8Array of EXACTLY n bytes, or null. Guards the new Uint8Array(null)
// trap: a null/short readByteArray must NOT become a truthy length-0 array.
function readBytes(p, n) {
  try {
    var ab = p.readByteArray(n);
    if (!ab || ab.byteLength !== n) return null;
    return new Uint8Array(ab);
  } catch (e) { return null; }
}

function toHex(u8) {
  if (!u8) return null;
  var s = '';
  for (var i = 0; i < u8.length; i++) s += ('0' + u8[i].toString(16)).slice(-2);
  return s;
}

function djb2Hex(u8) {
  var h = 5381;
  for (var i = 0; i < u8.length; i++) h = (((h << 5) + h) ^ u8[i]) >>> 0;
  return ('0000000' + (h >>> 0).toString(16)).slice(-8);
}

function sameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function allZero(u8) {
  if (!u8) return true;
  for (var i = 0; i < u8.length; i++) if (u8[i] !== 0) return false;
  return true;
}

function bytesMatch(addr, expected) {
  var b = readBytes(addr, expected.length);
  if (!b) return false;
  for (var i = 0; i < expected.length; i++)
    if (expected[i] !== null && b[i] !== expected[i]) return false;
  return true;
}

// ---- File output (atomic) ---------------------------------------------------
// Create KEY_DIR and any missing parents (CreateDirectoryA is non-recursive).
function ensureDir(dir) {
  if (!CreateDirectoryA) return;
  var parts = dir.split('\\');
  var cur = '';
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === '') continue;
    cur += (cur === '' ? '' : '\\') + parts[i];
    if (cur.charAt(cur.length - 1) === ':') continue;          // skip bare drive letter "D:"
    try { CreateDirectoryA(Memory.allocUtf8String(cur), NULL); } catch (e) {} // ignore "already exists"
  }
}

// Replace KEY_FILE with `text`. Throws on hard failure so the caller can retry.
function atomicWrite(text) {
  ensureDir(KEY_DIR);
  var f = new File(KEY_TMP, 'wb');
  f.write(text);
  f.flush();
  f.close();
  if (MoveFileExA) {
    var r = MoveFileExA(
      Memory.allocUtf8String(KEY_TMP),
      Memory.allocUtf8String(KEY_FILE),
      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (r.value !== 0) return;  // success: atomic rename committed to disk
    console.log('[keyfeed] WARN MoveFileExA failed (lastError=' + r.lastError +
                ') -- falling back to a direct (best-effort, non-atomic) write.');
  }
  // Best-effort fallback (only if MoveFileExA is unavailable or failed): a watcher
  // could briefly observe this mid-write, so the proxy should validate JSON length.
  var g = new File(KEY_FILE, 'wb');
  g.write(text);
  g.flush();
  g.close();
}

// ---- Resolution -------------------------------------------------------------
function resolve() {
  var m = Process.getModuleByName(MODULE_NAME);
  var addr = m.base.add(OFF_CFB64);
  var cloneAddr = m.base.add(KNOWN_CLONE_OFF);

  if (bytesMatch(addr, PROLOGUE)) {
    console.log('[keyfeed] CFB64 driver -> ' + addr +
                '  (base ' + m.base + ' + 0x' + OFF_CFB64.toString(16) + ')  [offset+prologue OK]');
    return addr;
  }
  console.log('[keyfeed] prologue mismatch at fixed offset -- trying guarded signature scan...');
  var hits = Memory.scanSync(m.base, m.size, SIG_CFB64);

  for (var i = 0; i < hits.length; i++)
    if (hits[i].address.equals(addr)) {
      console.log('[keyfeed] signature confirms expected offset -> ' + addr);
      return addr;
    }

  if (hits.length === 1) {
    if (hits[0].address.equals(cloneAddr)) {
      console.log('[keyfeed] ABORT: the sole signature hit is the Blowfish CLONE (' +
                  cloneAddr + ') -- refusing to hook it. Re-derive OFF_CFB64 in Ghidra.');
      return null;
    }
    console.log('[keyfeed] resolved via UNIQUE signature -> ' + hits[0].address);
    return hits[0].address;
  }

  var list = hits.map(function (h) { return h.address.toString(); }).join(', ');
  console.log('[keyfeed] ABORT: signature ' +
              (hits.length === 0 ? 'not found' : 'AMBIGUOUS (' + hits.length + ' hits: ' + list + ')') +
              ' -- the 0x012c29e0 Blowfish clone shares this prologue. ' +
              'Re-derive OFF_CFB64 in Ghidra and update the constant.');
  return null;
}

// ---- Capture state ----------------------------------------------------------
var state = {
  scheduleBytes: null,  // Uint8Array(132) of the current session schedule (cheap compare)
  scheduleHex:   null,  // hex of the above (built once per session)
  sessionId:     null,  // djb2(schedule) hex8 -- a label only
  sendIvecHex:   null, recvIvecHex: null,
  sendNum:       null, recvNum:     null,
  sendBytes:     0,    recvBytes:   0,    // cumulative cipher-processed bytes per direction
  sendSwitchOffset: null, recvSwitchOffset: null, // wire offset where the DH stream starts
  dirty:         false, // key material changed but not yet persisted
  dirtyReason:   ''
};

// Returns true on a confirmed write, false on failure (caller keeps dirty=true to retry).
function writeKeyFile(reason) {
  var now = Date.now();
  var obj = {
    schema:          1,
    pid:             PID,
    session_id:      state.sessionId,
    schedule_hex:    state.scheduleHex,
    send_ivec_hex:   state.sendIvecHex,
    recv_ivec_hex:   state.recvIvecHex,
    send_num:        state.sendNum,
    recv_num:        state.recvNum,
    send_switch_offset: state.sendSwitchOffset,
    recv_switch_offset: state.recvSwitchOffset,
    captured_at:     now,
    captured_at_iso: new Date(now).toISOString()
  };
  try {
    atomicWrite(JSON.stringify(obj, null, 2) + '\n');
    console.log('[keyfeed] WROTE ' + KEY_FILE + '  (' + reason + ')' +
                '  session=' + state.sessionId +
                '  send_ivec=' + (state.sendIvecHex || '-') +
                '  recv_ivec=' + (state.recvIvecHex || '-'));
    return true;
  } catch (e) {
    console.log('[keyfeed] write error (will retry next call): ' + e);
    return false;
  }
}

function onCfbCall(args) {
  var schedPtr = args[3];
  var ivecPtr  = args[4];
  var numPtr   = args[5];
  var enc      = args[6].toInt32();
  var len      = 0; try { len = args[2].toInt32(); } catch (e) {}

  var ivU8 = readBytes(ivecPtr, 8);
  var num = null;
  try { num = numPtr.readU32(); } catch (e) {}

  var isSend      = (enc !== 0);              // enc != 0 => encrypt, C->S
  var dirBytesKey = isSend ? 'sendBytes' : 'recvBytes';
  var isZeroIv    = allZero(ivU8);

  // CONNECTION-START reset for SWITCH-OFFSET tracking.
  // A CFB64 stream always begins at num==0 from its seed ivec. The static
  // pre-handshake context seeds from a ZERO ivec, so (num==0 && zero ivec) marks
  // this direction's CONNECTION start -- reset its byte counter so the switch
  // offset is measured from the very first static byte the proxy forwards.
  if (num === 0 && isZeroIv) state[dirBytesKey] = 0;

  // Wire offset where THIS call's bytes begin = bytes already counted this dir.
  var offsetOfThisCall = state[dirBytesKey];

  var schedU8 = readBytes(schedPtr, SCHED_BYTES);

  // GUARD: capture only on a clean DH stream-start (num == 0 && non-zero ivec) with
  // a readable schedule. This rejects the static pre-handshake context (zero-ivec
  // starts) and every mid-stream call (num != 0), so the key file only ever
  // reflects the real per-session game stream -- never the static handshake
  // context. Every other call still advances the per-direction byte counter below.
  if (schedU8 && num === 0 && !isZeroIv) {
    var ivHex = toHex(ivU8);
    if (ivHex !== null) {
      if (!sameBytes(schedU8, state.scheduleBytes)) {
        state.scheduleBytes = schedU8;
        state.scheduleHex   = toHex(schedU8);
        state.sessionId     = djb2Hex(schedU8);
        state.sendIvecHex = null; state.recvIvecHex = null;
        state.sendNum     = null; state.recvNum     = null;
        state.sendSwitchOffset = null; state.recvSwitchOffset = null;
        state.dirty = true; state.dirtyReason = 'new session';
        console.log('');
        console.log('[keyfeed] NEW SESSION id=' + state.sessionId +
                    ' sched=' + state.scheduleHex.slice(0, 16) + '...');
      }

      // num==0 && non-zero ivec here -> the true per-direction stream start.
      // offsetOfThisCall = total static bytes already passed this direction = the
      // switch offset the proxy must buffer to before it starts decrypting.
      if (isSend) {                            // ENCRYPT, C->S (client send)
        if (state.sendIvecHex === null) {
          state.sendIvecHex = ivHex; state.sendNum = 0;
          state.sendSwitchOffset = offsetOfThisCall;
          state.dirty = true; state.dirtyReason = 'send start';
        }
      } else {                                 // DECRYPT, S->C (client recv)
        if (state.recvIvecHex === null) {
          state.recvIvecHex = ivHex; state.recvNum = 0;
          state.recvSwitchOffset = offsetOfThisCall;
          state.dirty = true; state.dirtyReason = 'recv start';
        }
      }

      if (state.dirty && writeKeyFile(state.dirtyReason))
        state.dirty = false;                  // cleared only on a confirmed write
    }
  }

  // ALWAYS advance this direction's cumulative byte counter (static AND DH bytes
  // count -- the switch offset is relative to the connection's first byte).
  if (len > 0) state[dirBytesKey] += len;
}

// ---- Bootstrap --------------------------------------------------------------
function main() {
  var m = Process.getModuleByName(MODULE_NAME);
  console.log('==================================================================');
  console.log(' frida_v22 CAST5-variant key feed (port 19000)');
  console.log(' module ' + MODULE_NAME + '  base=' + m.base + '  size=0x' + m.size.toString(16));
  console.log(' key file: ' + KEY_FILE);
  console.log('==================================================================');
  if (!MoveFileExA)
    console.log('[keyfeed] WARN: MoveFileExA unavailable -- writes will be non-atomic.');

  var addr = resolve();
  if (!addr) { console.log('[keyfeed] FATAL: driver not resolved; no hook installed.'); return; }

  Interceptor.attach(addr, {
    onEnter: function (args) {
      try { onCfbCall(args); } catch (e) { console.log('[keyfeed] onEnter error: ' + e); }
    }
  });
  console.log('[keyfeed] hook installed. Log in (enter the game world, port 19000) to capture.');
}

main();
