// Frida v18 — Stage 5b: Send Counter Investigation
// Goal: Track send context counter resets

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');

var logPath = "F:\\Sentinel\\tools\\frida_v18_stage5b_" + ts + ".log";
var logFile = new File(logPath, "w");

function log(msg) {
    logFile.write(msg + "\n");
    logFile.flush();
}

function logBoth(msg) {
    console.log(msg);
    log(msg);
}

function safeReadU32(ptrValue) {
    try {
        return ptrValue.readU32();
    } catch (e) {
        return null;
    }
}

function safeHexN(ptrValue, n) {
    try {
        var out = "";
        for (var i = 0; i < n; i++) {
            out += ('0' + ptrValue.add(i).readU8().toString(16)).slice(-2);
        }
        return out;
    } catch (e) {
        return "<read-failed>";
    }
}

var customCipherAddr = ptr("0x00fef18a");
var callCount = 0;
var MAX_CALLS = 20;

// Track ALL contexts and their counter history
var ctxHistory = {};  // ctx_addr -> [{ callIndex, cA_before, cB_before, cA_after, cB_after, len, commit }]

logBoth("[*] Frida v18 — Stage 5b: Send Counter Investigation");
logBoth("[*] Started: " + now.toISOString());
logBoth("[*] Log file: " + logPath);
logBoth("---");

Interceptor.attach(customCipherAddr, {
    onEnter: function (args) {
        if (callCount >= MAX_CALLS) return;

        var ctx = this.context.ecx;
        var buf = args[0];
        var len = args[1].toInt32();
        var commit = args[2].toInt32();

        this.shouldLog = true;
        this.callIndex = callCount;
        this.ctx = ctx;
        this.len = len;
        this.commit = commit;

        var cA = safeReadU32(ctx);
        var cB = safeReadU32(ctx.add(0x04));

        this.cA_before = cA;
        this.cB_before = cB;

        var previewLen = len >= 16 ? 16 : (len > 0 ? len : 0);
        var bufPreview = previewLen > 0 ? safeHexN(buf, previewLen) : "";

        logBoth("[CALL #" + callCount + "] ENTER"
            + " ctx=" + ctx
            + " len=" + len
            + " commit=" + commit
            + " cA=" + cA + " cB=" + cB
            + " buf[0:" + previewLen + "]=" + bufPreview);

        callCount++;
    },

    onLeave: function (retval) {
        if (!this.shouldLog) return;

        var ctx = this.ctx;
        var cA = safeReadU32(ctx);
        var cB = safeReadU32(ctx.add(0x04));

        var ctxKey = ctx.toString();
        if (!ctxHistory[ctxKey]) {
            ctxHistory[ctxKey] = [];
        }

        ctxHistory[ctxKey].push({
            callIndex: this.callIndex,
            cA_before: this.cA_before,
            cB_before: this.cB_before,
            cA_after: cA,
            cB_after: cB,
            len: this.len,
            commit: this.commit
        });

        var counterChanged = (cA !== this.cA_before || cB !== this.cB_before);
        var expectedCA = this.cA_before;
        var expectedCB = this.cB_before;
        if (this.commit === 1) {
            for (var i = 0; i < this.len; i++) {
                if (++expectedCA > 0xFF) {
                    expectedCA = 0;
                    if (++expectedCB > 0xFF) expectedCB = 0;
                }
            }
        }
        var countersAsExpected = (cA === expectedCA && cB === expectedCB);

        logBoth("[CALL #" + this.callIndex + "] LEAVE"
            + " ctx=" + ctx
            + " cA=" + this.cA_before + "->" + cA
            + " cB=" + this.cB_before + "->" + cB
            + " changed=" + counterChanged
            + " expected=(" + expectedCA + "," + expectedCB + ")"
            + " match=" + countersAsExpected);

        // Detect reset
        if (this.cA_before > 0 && cA === 0 && this.cB_before > 0 && cB === 0) {
            logBoth("[!] COUNTER RESET DETECTED on " + ctx);
        }
    }
});

function printSummary() {
    logBoth("\n=== STAGE 5b SUMMARY ===");

    var keys = Object.keys(ctxHistory);
    logBoth("Unique contexts: " + keys.length);

    for (var i = 0; i < keys.length; i++) {
        var history = ctxHistory[keys[i]];
        logBoth("\nContext " + keys[i] + " (" + history.length + " calls):");
        for (var j = 0; j < history.length; j++) {
            var h = history[j];
            logBoth("  #" + h.callIndex
                + " len=" + h.len
                + " commit=" + h.commit
                + " counters: (" + h.cA_before + "," + h.cB_before
                + ") -> (" + h.cA_after + "," + h.cB_after + ")");
        }
    }

    logBoth("\n=== END SUMMARY ===");
    logFile.close();
}

rpc.exports = {
    summary: printSummary
};

logBoth("[*] Hook installed! Login and play ~30 seconds.");
logBoth("[*] Type printSummary() before detaching.\n");