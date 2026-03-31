// Frida v13 — Direction mapping for BF_cfb64_encrypt
// Goal: determine which session IV is used for which direction.

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');

var logPath = "F:\\Sentinel\\tools\\frida_v13_" + ts + ".log";
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

function hexN(ptrValue, n) {
    var out = "";
    for (var i = 0; i < n; i++) {
        out += ('0' + ptrValue.add(i).readU8().toString(16)).slice(-2);
    }
    return out;
}

function safeHexN(ptrValue, n) {
    try {
        return hexN(ptrValue, n);
    } catch (e) {
        return "<read-failed:" + e + ">";
    }
}

function safeHex8(ptrValue) {
    try {
        return hex8(ptrValue);
    } catch (e) {
        return "<read-failed:" + e + ">";
    }
}

function safeReadU32(ptrValue) {
    try {
        return ptrValue.readU32();
    } catch (e) {
        return null;
    }
}

logBoth("[*] Frida v13 — direction mapping for BF_cfb64_encrypt — " + now.toISOString());

var doReceiveShakeHandAddr = ptr("0x00feeb6c");
var bfCfb64Addr = ptr("0x012410f0");
var TARGET_P0 = 0xdb298a75;

var lastServerIvec = null;
var lastClientIvec = null;
var handshakeSeen = false;

var bfKeyCaptured = false;
var bfKeyPtrSaved = ptr("0");
var bfCallCount = 0;
var MAX_LOGGED_CALLS = 40;

Interceptor.attach(doReceiveShakeHandAddr, {
    onEnter: function (args) {
        this.thisPtr = this.context.ecx;
        this.arg0 = args[0];
        this.arg1 = args[1];
        this.arg2 = args[2];

        log("[HANDSHAKE] ENTER ecx=" + this.thisPtr
            + " arg0=" + this.arg0
            + " arg1=" + this.arg1
            + " arg2=" + this.arg2);
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

                var serverIvec = safeHex8(cipherCtx.add(0x0d));
                var clientIvec = safeHex8(cipherCtx.add(0x15));

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

                if (cand.name === "ecx"
                    && serverIvec.indexOf("<read-failed:") !== 0
                    && clientIvec.indexOf("<read-failed:") !== 0
                    && serverIvec !== "0000000000000000"
                    && clientIvec !== "0000000000000000") {

                    lastServerIvec = serverIvec;
                    lastClientIvec = clientIvec;
                    handshakeSeen = true;

                    logBoth("[HANDSHAKE] selected ecx IVs server_ivec=" + lastServerIvec
                        + " client_ivec=" + lastClientIvec);
                }
            } catch (e) {
                log("[HANDSHAKE] candidate=" + cand.name + " read failed: " + e);
            }
        }
    }
});

Interceptor.attach(bfCfb64Addr, {
    onEnter: function (args) {
        var inPtr = args[0];
        var outPtr = args[1];
        var len = args[2].toInt32();
        var bfKeyPtr = args[3];
        var ivecPtr = args[4];
        var numPtr = args[5];
        var enc = args[6].toInt32();

        var p0;
        try {
            p0 = bfKeyPtr.readU32();
        } catch (e) {
            return;
        }

        if (p0 !== TARGET_P0) {
            return;
        }

        if (!bfKeyCaptured) {
            bfKeyCaptured = true;
            bfKeyPtrSaved = bfKeyPtr;

            logBoth("[*] Got BF_KEY: " + bfKeyPtr + " P0=0x" + p0.toString(16).padStart(8, '0'));

            if (handshakeSeen) {
                logBoth("[*] Handshake IVs captured: server=" + lastServerIvec + " client=" + lastClientIvec);
            } else {
                logBoth("[!] Handshake IVs not captured yet.");
            }
        }

        if (bfCallCount >= MAX_LOGGED_CALLS) {
            return;
        }

        var ivecNow = safeHex8(ivecPtr);

        var numBefore = null;
        try {
            numBefore = numPtr.readU32();
        } catch (e) {
            numBefore = null;
        }

        var inPreviewLen = len >= 8 ? 8 : len;
        if (inPreviewLen < 0) inPreviewLen = 0;

        var inPreview = inPreviewLen > 0 ? safeHexN(inPtr, inPreviewLen) : "";
        var outPreviewBefore = inPreviewLen > 0 ? safeHexN(outPtr, inPreviewLen) : "";

        var match = "UNKNOWN";
        if (handshakeSeen) {
            if (ivecNow === lastServerIvec) {
                match = "SERVER_IV";
            } else if (ivecNow === lastClientIvec) {
                match = "CLIENT_IV";
            } else {
                match = "NEITHER";
            }
        }

        this.shouldLog = true;
        this.callIndex = bfCallCount;
        this.enc = enc;
        this.len = len;
        this.ivecNow = ivecNow;
        this.numBefore = numBefore;
        this.inPreview = inPreview;
        this.outPreviewBefore = outPreviewBefore;
        this.match = match;
        this.outPtr = outPtr;
        this.previewLen = inPreviewLen;

        bfCallCount++;

        log("[BF_CALL] #" + this.callIndex
            + " ENTER"
            + " enc=" + enc
            + " len=" + len
            + " num_before=" + (numBefore === null ? "<read-failed>" : numBefore)
            + " ivec_now=" + ivecNow
            + " match=" + match
            + " in[0:" + inPreviewLen + "]=" + inPreview
            + " out_before[0:" + inPreviewLen + "]=" + outPreviewBefore);
    },

    onLeave: function (retval) {
        if (!this.shouldLog) {
            return;
        }

        var outPreviewAfter = this.previewLen > 0 ? safeHexN(this.outPtr, this.previewLen) : "";

        log("[BF_CALL] #" + this.callIndex
            + " LEAVE"
            + " enc=" + this.enc
            + " len=" + this.len
            + " ivec_now=" + this.ivecNow
            + " match=" + this.match
            + " out_after[0:" + this.previewLen + "]=" + outPreviewAfter);
    }
});

logBoth("[*] All hooks installed! Login and play briefly to map enc direction to session IVs.\n");