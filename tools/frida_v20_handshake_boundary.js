// frida_v20_handshake_boundary.js — v4
"use strict";

var GAME_CIPHER_ADDR = ptr("0x00fef18a");
var HANDSHAKE_ADDR   = ptr("0x00feeb6c");
var PRE_HS_SEND_ADDR = ptr("0x00ff7183");

var callLog = [];
var callIndex = 0;

function ts() {
    return (Date.now() / 1000).toFixed(3);
}

function safeHex(addr, len) {
    try {
        var p = new NativePointer(addr);
        var n = Math.min(len, 32);
        var b = [];
        for (var i = 0; i < n; i++) {
            b.push(("0" + new NativePointer(p.add(i)).readU8().toString(16)).slice(-2));
        }
        var r = b.join(" ");
        if (len > n) r += " ...(" + len + " total)";
        return r;
    } catch(e) {
        return "(unreadable: " + e.message + ")";
    }
}

function ri32(addr) { return new NativePointer(addr).readS32(); }
function ru8(addr)  { return new NativePointer(addr).readU8(); }

Interceptor.attach(GAME_CIPHER_ADDR, {
    onEnter: function(args) {
        try {
            this.ctx = new NativePointer(this.context.ecx);
            this.buf = args[0];
            this.len = parseInt(args[1]);
            this.commit = parseInt(args[2]);

            this.cA_before = ri32(this.ctx);
            this.cB_before = ri32(this.ctx.add(4));
            this.beforeHex = safeHex(this.buf, this.len);
            this.idx = callIndex++;
        } catch(e) {
            send("[CIPHER onEnter ERROR] " + e.message);
        }
    },
    onLeave: function(retval) {
        try {
            var cA_after = ri32(this.ctx);
            var cB_after = ri32(this.ctx.add(4));
            var afterHex = safeHex(this.buf, this.len);

            var entry = {
                idx: this.idx, time: ts(), func: "CIPHER",
                ctx: this.ctx.toString(), len: this.len,
                commit: this.commit,
                cA_before: this.cA_before, cB_before: this.cB_before,
                cA_after: cA_after, cB_after: cB_after,
                before: this.beforeHex, after: afterHex
            };
            callLog.push(entry);

            send("[CIPHER #" + entry.idx + "] t=" + entry.time +
                 " ctx=" + entry.ctx + " len=" + entry.len +
                 " commit=" + entry.commit +
                 " (" + entry.cA_before + "," + entry.cB_before +
                 ")>(" + cA_after + "," + cB_after + ")" +
                 "\n  before: " + entry.before +
                 "\n  after:  " + entry.after);
        } catch(e) {
            send("[CIPHER onLeave ERROR] " + e.message);
        }
    }
});

Interceptor.attach(HANDSHAKE_ADDR, {
    onEnter: function(args) {
        try {
            this.thisPtr = new NativePointer(this.context.ecx);
            this.idx = callIndex++;

            var hsFlag = ru8(this.thisPtr.add(0x1c0e));
            var preSendFlag = ru8(this.thisPtr.add(0x1c0d));
            var mode = ri32(this.thisPtr.add(0x1c08));

            callLog.push({
                idx: this.idx, time: ts(), func: "HANDSHAKE",
                hsFlag: hsFlag, preSendFlag: preSendFlag, mode: mode
            });

            send("[HANDSHAKE #" + this.idx + "] t=" + ts() +
                 " ENTER hsFlag=0x" + hsFlag.toString(16) +
                 " preSendFlag=0x" + preSendFlag.toString(16) +
                 " mode=" + mode);
        } catch(e) {
            send("[HANDSHAKE onEnter ERROR] " + e.message);
        }
    },
    onLeave: function(retval) {
        try {
            var hsFlag = ru8(this.thisPtr.add(0x1c0e));
            var mode = ri32(this.thisPtr.add(0x1c08));
            send("[HANDSHAKE #" + this.idx + "] t=" + ts() +
                 " LEAVE hsFlag=0x" + hsFlag.toString(16) +
                 " mode=" + mode);
        } catch(e) {
            send("[HANDSHAKE onLeave ERROR] " + e.message);
        }
    }
});

Interceptor.attach(PRE_HS_SEND_ADDR, {
    onEnter: function(args) {
        try {
            this.thisPtr = new NativePointer(this.context.ecx);
            this.idx = callIndex++;
            send("[PRE_HS_SEND #" + this.idx + "] t=" + ts() +
                 " — encrypts first 12 bytes, buffers packet");
        } catch(e) {
            send("[PRE_HS_SEND onEnter ERROR] " + e.message);
        }
    },
    onLeave: function(retval) {
        try {
            var flag = ru8(this.thisPtr.add(0x1c0d));
            send("[PRE_HS_SEND #" + this.idx + "] t=" + ts() +
                 " — done, preSendFlag=" + flag);
        } catch(e) {
            send("[PRE_HS_SEND onLeave ERROR] " + e.message);
        }
    }
});

send("[*] Frida v20 — Handshake Boundary Detection v4");
send("[*] Login to the game. Type printLog() for summary.");

globalThis.printLog = function() {
    send("\n=== FULL CALL LOG (" + callLog.length + " entries) ===");
    for (var i = 0; i < callLog.length; i++) {
        var e = callLog[i];
        if (e.func === "CIPHER") {
            send("#" + e.idx + " [" + e.time + "] CIPHER ctx=" + e.ctx +
                 " len=" + e.len + " commit=" + e.commit +
                 " (" + e.cA_before + "," + e.cB_before +
                 ")>(" + e.cA_after + "," + e.cB_after + ")");
        } else {
            send("#" + e.idx + " [" + e.time + "] " + e.func +
                 " hsFlag=" + e.hsFlag + " preSend=" + e.preSendFlag +
                 " mode=" + e.mode);
        }
    }
    send("=== END LOG ===");
};