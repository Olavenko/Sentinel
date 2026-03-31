// Frida v12 — Handshake IV dump + 128KB chain capture from zero/server/client IV
// Based directly on the working v11 script.

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');
var logPath = "F:\\Sentinel\\tools\\frida_v12_" + ts + ".log";
var logFile = new File(logPath, "w");

function log(msg) {
    logFile.write(msg + "\n");
    logFile.flush();
}

function logBoth(msg) {
    console.log(msg);
    log(msg);
}

function hex8(ptrValue) {
    var out = "";
    for (var i = 0; i < 8; i++) {
        out += ('0' + ptrValue.add(i).readU8().toString(16)).slice(-2);
    }
    return out;
}

function bytesToHex(arr) {
    var out = "";
    for (var i = 0; i < arr.length; i++) {
        out += ('0' + arr[i].toString(16)).slice(-2);
    }
    return out;
}

function hexToBytes(hexStr) {
    if (!hexStr || hexStr.length !== 16) {
        throw new Error("hexToBytes expected 16 hex chars, got: " + hexStr);
    }

    var out = [];
    for (var i = 0; i < 16; i += 2) {
        out.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return out;
}

function writeHex8ToPtr(hexStr, dstPtr) {
    var bytes = hexToBytes(hexStr);
    for (var i = 0; i < 8; i++) {
        dstPtr.add(i).writeU8(bytes[i]);
    }
}

function readHex8FromArray(arr, offset) {
    var out = "";
    for (var i = 0; i < 8; i++) {
        out += ('0' + arr[offset + i].toString(16)).slice(-2);
    }
    return out;
}

function safeReadU32(p) {
    try {
        return p.readU32();
    } catch (e) {
        return null;
    }
}

function generateAndLogChain(bfCfb64, bfKeyPtr, ivHex, label, streamLen) {
    var inBuf = Memory.alloc(streamLen);
    var outBuf = Memory.alloc(streamLen);
    var ivBuf = Memory.alloc(8);
    var numBuf = Memory.alloc(4);

    for (var i = 0; i < streamLen; i++) {
        inBuf.add(i).writeU8(0);
    }

    writeHex8ToPtr(ivHex, ivBuf);
    numBuf.writeU32(0);

    bfCfb64(inBuf, outBuf, streamLen, bfKeyPtr, ivBuf, numBuf, 1);

    var streamBytes = outBuf.readByteArray(streamLen);
    var stream = new Uint8Array(streamBytes);

    logBoth("[*] Generated " + streamLen + " bytes / " + (streamLen / 8) + " entries for " + label + " start IV=" + ivHex);
    logBoth("[*] " + label + " block 0: " + readHex8FromArray(stream, 0));
    logBoth("[*] " + label + " block 1: " + readHex8FromArray(stream, 8));

    log("[CHAIN][" + label + "] START iv=" + ivHex);

    var prev = ivHex;
    for (var c = 0; c < streamLen / 8; c++) {
        var curr = readHex8FromArray(stream, c * 8);
        log("[CHAIN][" + label + "] " + prev + " -> " + curr);
        prev = curr;
    }

    log("[CHAIN][" + label + "] END");
}

logBoth("[*] Frida v12 — handshake IV dump + zero/server/client 128KB chain capture — " + now.toISOString());

var doReceiveShakeHandAddr = ptr("0x00feeb6c");
var bfCfb64Addr = ptr("0x012410f0");
var TARGET_P0 = 0xdb298a75;
var STREAM_LEN = 131072; // 128KB = 16384 entries

var streamCaptured = false;

// These are captured from the handshake candidate that looks real.
// We no longer rely on candidate p0 here because it did not match BF_KEY p0.
var lastServerIvec = null;
var lastClientIvec = null;
var handshakeSeen = false;

Interceptor.attach(doReceiveShakeHandAddr, {
    onEnter: function (args) {
        this.thisPtr = this.context.ecx;
        this.arg0 = args[0];
        this.arg1 = args[1];
        this.arg2 = args[2];
        log("[HANDSHAKE] ENTER ecx=" + this.thisPtr + " arg0=" + this.arg0 + " arg1=" + this.arg1 + " arg2=" + this.arg2);
    },

    onLeave: function (retval) {
        var candidates = [];
        if (this.thisPtr) candidates.push({ name: "ecx", base: this.thisPtr });
        if (this.arg0) candidates.push({ name: "arg0", base: this.arg0 });

        log("[HANDSHAKE] LEAVE retval=" + retval);

        for (var i = 0; i < candidates.length; i++) {
            var cand = candidates[i];

            try {
                var socketObj = cand.base;
                var cipherCtx = socketObj.add(0x1008);
                var pArray = cipherCtx.add(0x40);

                var p0 = safeReadU32(pArray);
                var decNum = safeReadU32(cipherCtx.add(0x04));
                var encNum = safeReadU32(cipherCtx.add(0x08));

                var enabled = null;
                try {
                    enabled = cipherCtx.add(0x0c).readU8();
                } catch (e) {
                    enabled = null;
                }

                var serverIvec = null;
                var clientIvec = null;

                try {
                    serverIvec = hex8(cipherCtx.add(0x0d));
                } catch (e) {
                    serverIvec = "<read-failed:" + e + ">";
                }

                try {
                    clientIvec = hex8(cipherCtx.add(0x15));
                } catch (e) {
                    clientIvec = "<read-failed:" + e + ">";
                }

                log("[HANDSHAKE] candidate=" + cand.name
                    + " socket=" + socketObj
                    + " cipher_ctx=" + cipherCtx
                    + " p_array=" + pArray
                    + " p0=" + (p0 === null ? "<read-failed>" : "0x" + p0.toString(16).padStart(8, '0'))
                    + " enabled=" + (enabled === null ? "<read-failed>" : "0x" + ('0' + enabled.toString(16)).slice(-2))
                    + " dec_num=" + (decNum === null ? "<read-failed>" : decNum)
                    + " enc_num=" + (encNum === null ? "<read-failed>" : encNum)
                    + " server_ivec=" + serverIvec
                    + " client_ivec=" + clientIvec);

                // Keep the ecx candidate IVs only if they are non-zero and readable.
                if (cand.name === "ecx"
                    && serverIvec !== null
                    && clientIvec !== null
                    && serverIvec.indexOf("<read-failed:") !== 0
                    && clientIvec.indexOf("<read-failed:") !== 0
                    && serverIvec !== "0000000000000000"
                    && clientIvec !== "0000000000000000") {

                    lastServerIvec = serverIvec;
                    lastClientIvec = clientIvec;
                    handshakeSeen = true;

                    log("[HANDSHAKE] selected ecx IVs server_ivec=" + lastServerIvec + " client_ivec=" + lastClientIvec);
                }
            } catch (e) {
                log("[HANDSHAKE] candidate=" + cand.name + " read failed: " + e);
            }
        }
    }
});

Interceptor.attach(bfCfb64Addr, {
    onEnter: function (args) {
        if (streamCaptured) {
            return;
        }

        var bfKeyPtr = args[3];
        var p0;

        try {
            p0 = bfKeyPtr.readU32();
        } catch (e) {
            return;
        }

        if (p0 !== TARGET_P0) {
            return;
        }

        streamCaptured = true;

        logBoth("[*] Got BF_KEY: " + bfKeyPtr + " P0=0x" + p0.toString(16).padStart(8, '0'));
        log("[BF] in=" + args[0]
            + " out=" + args[1]
            + " len=" + args[2].toInt32()
            + " ivec=" + args[4]
            + " num=" + args[5]
            + " enc=" + args[6].toInt32());

        if (handshakeSeen) {
            logBoth("[*] Handshake IVs captured: server=" + lastServerIvec + " client=" + lastClientIvec);
        } else {
            logBoth("[!] Handshake IVs were not captured before BF_KEY. Only zero-start chain will be generated.");
        }

        var bfCfb64 = new NativeFunction(bfCfb64Addr, 'void', [
            'pointer', 'pointer', 'int32', 'pointer', 'pointer', 'pointer', 'int32'
        ]);

        // Reference chain from zero.
        generateAndLogChain(bfCfb64, bfKeyPtr, "0000000000000000", "ZERO", STREAM_LEN);

        // Actual session chains.
        if (handshakeSeen && lastServerIvec !== null) {
            generateAndLogChain(bfCfb64, bfKeyPtr, lastServerIvec, "SERVER_IV", STREAM_LEN);
        }

        if (handshakeSeen && lastClientIvec !== null) {
            generateAndLogChain(bfCfb64, bfKeyPtr, lastClientIvec, "CLIENT_IV", STREAM_LEN);
        }

        logBoth("[*] Done!");
    }
});

logBoth("[*] All hooks installed! Login to capture the key and handshake IVs.\n");