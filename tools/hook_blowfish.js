// Frida v10 — Generate full keystream dump for S-box reconstruction
// Strategy: Call BF_cfb64_encrypt to produce long keystream,
// then use it to validate/find S-boxes

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');
var logPath = "F:\\Sentinel\\tools\\frida_v10_" + ts + ".log";
var logFile = new File(logPath, "w");

function log(msg) {
    logFile.write(msg + "\n");
    logFile.flush();
}

function logBoth(msg) {
    console.log(msg);
    log(msg);
}

logBoth("[*] Frida v10 — Full keystream + S-box probe — " + now.toISOString());

var bfCfb64Addr = ptr("0x012410f0");
var done = false;

Interceptor.attach(bfCfb64Addr, {
    onEnter: function (args) {
        if (done) return;
        var bfKeyPtr = args[3];
        var p0 = bfKeyPtr.readU32();
        if (p0 !== 0xdb298a75) return;
        done = true;

        logBoth("[*] Got BF_KEY: " + bfKeyPtr);

        var bfCfb64 = new NativeFunction(bfCfb64Addr, 'void', [
            'pointer', 'pointer', 'int32', 'pointer', 'pointer', 'pointer', 'int32'
        ]);

        // ============================================
        // PART 1: Generate 4KB of keystream via CFB encrypt
        // by encrypting 4096 zero bytes in one call
        // This gives us: keystream[0..4095] where
        // keystream comes from chained BF_encrypt calls
        // ============================================
        var streamLen = 4096;
        var inBuf = Memory.alloc(streamLen);
        var outBuf = Memory.alloc(streamLen);
        var ivBuf = Memory.alloc(8);
        var numBuf = Memory.alloc(4);

        // Zero input
        for (var i = 0; i < streamLen; i++) inBuf.add(i).writeU8(0);
        // Zero IV
        for (var j = 0; j < 8; j++) ivBuf.add(j).writeU8(0);
        numBuf.writeU32(0);

        bfCfb64(inBuf, outBuf, streamLen, bfKeyPtr, ivBuf, numBuf, 1);

        // Read output = keystream (since input is zeros, output = keystream XOR 0 = keystream)
        // Actually in CFB ENCRYPT: output = BF_encrypt(IV) XOR plaintext
        // Then IV becomes OUTPUT for next block
        // So output IS the keystream when plaintext is zero
        // Each 8-byte block: output[n] = BF_encrypt(output[n-1])
        // output[0] = BF_encrypt(zeros)

        logBoth("[*] Generated " + streamLen + " bytes of keystream");
        log("[STREAM] KEYSTREAM_START");

        var streamBytes = outBuf.readByteArray(streamLen);
        var stream = new Uint8Array(streamBytes);

        // Output as hex lines
        for (var k = 0; k < streamLen; k += 64) {
            var line = "";
            for (var m = k; m < Math.min(k+64, streamLen); m++) {
                line += ('0' + stream[m].toString(16)).slice(-2);
            }
            log("[STREAM] " + ('0000' + k.toString(16)).slice(-4) + " " + line);
        }
        log("[STREAM] KEYSTREAM_END");

        // ============================================
        // PART 2: Verify first block
        // ============================================
        logBoth("[*] Block 0 (BF_encrypt(zeros)): " + 
            Array.from(stream.slice(0, 8)).map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' '));
        logBoth("[*] Expected: bc 8a 80 e5 bf b0 14 1d");

        // Block 1 = BF_encrypt(block0_cipher)
        logBoth("[*] Block 1 (BF_encrypt(block0)): " +
            Array.from(stream.slice(8, 16)).map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' '));

        // ============================================
        // PART 3: Extract individual BF_encrypt results
        // Each 8-byte block in the keystream is BF_encrypt(previous_block)
        // So we get a chain: BF_encrypt(0) -> BF_encrypt(r0) -> BF_encrypt(r1) -> ...
        // ============================================
        log("[CHAIN] BF_ENCRYPT_CHAIN_START");
        log("[CHAIN] # input -> output");
        
        var prev = "0000000000000000";
        for (var c = 0; c < streamLen / 8; c++) {
            var curr = "";
            for (var b = c*8; b < c*8+8; b++) {
                curr += ('0' + stream[b].toString(16)).slice(-2);
            }
            log("[CHAIN] " + c + " " + prev + " -> " + curr);
            prev = curr;
        }
        log("[CHAIN] BF_ENCRYPT_CHAIN_END");

        // ============================================
        // PART 4: Now the IMPORTANT part
        // Dump the cipher object S-box region with UINT32 interpretation
        // We know S-boxes are in the cipher object at ECX+0xCC
        // Let's dump it differently: as pairs of bytes
        // ============================================
        var ecx = this.context.ecx;
        logBoth("[*] ECX = " + ecx);

        // Read the region at ECX+0xCC as uint32 values at BOTH 4-byte and 2-byte strides
        log("[SBOX4] S-box as uint32 at 4-byte stride from ECX+0xCC:");
        try {
            for (var s = 0; s < 256; s++) {
                var val = ecx.add(0xCC + s*4).readU32();
                log("[SBOX4] [" + s + "] 0x" + val.toString(16).padStart(8, '0'));
            }
        } catch(e) { log("[SBOX4] Error at index " + s + ": " + e); }

        log("[SBOX2] S-box as uint16 at 2-byte stride from ECX+0xCC:");
        try {
            for (var t = 0; t < 512; t++) {
                var val16 = ecx.add(0xCC + t*2).readU16();
                log("[SBOX2] [" + t + "] 0x" + val16.toString(16).padStart(4, '0'));
            }
        } catch(e) { log("[SBOX2] Error: " + e); }

        logBoth("[*] Done!");
    }
});

logBoth("[*] Hooked. Login now.\n");