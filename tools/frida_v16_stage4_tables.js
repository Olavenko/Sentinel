// Frida v16 — Stage 4: Gameplay Cipher Table Extraction
// Goal: Hook FUN_00fef18a, find cipher context, dump tableA[256] + tableB[256]
// Usage: frida -p <PID> -l frida_v15_stage4_tables.js

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');

var logPath = "F:\\Sentinel\\tools\\frida_v16_stage4_" + ts + ".log";
var logFile = new File(logPath, "w");

function log(msg) {
    logFile.write(msg + "\n");
    logFile.flush();
}

function logBoth(msg) {
    console.log(msg);
    log(msg);
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
        return "<read-failed>";
    }
}

function safeReadU32(ptrValue) {
    try {
        return ptrValue.readU32();
    } catch (e) {
        return null;
    }
}

// --- Config ---
var customCipherAddr = ptr("0x00fef18a");

// --- State ---
var callCount = 0;
var MAX_DETAILED_CALLS = 15;
var knownContexts = {};  // address -> { tableA, tableB, callCount, firstEnc }

logBoth("[*] Frida v16 — Stage 4b: Multi-Context Table Comparison");
logBoth("[*] Started: " + now.toISOString());
logBoth("[*] Log file: " + logPath);
logBoth("---");

Interceptor.attach(customCipherAddr, {
    onEnter: function (args) {
        var ctx = this.context.ecx;
        var buf = args[0];
        var len = args[1].toInt32();
        var commit = args[2].toInt32();

        this.ctx = ctx;
        this.buf = buf;
        this.len = len;
        this.commit = commit;
        this.callIndex = callCount;

        var ctxKey = ctx.toString();

        // Dump tables for each NEW context
        if (!knownContexts[ctxKey]) {
            var counterA = safeReadU32(ctx);
            var counterB = safeReadU32(ctx.add(0x04));
            var tableA = safeHexN(ctx.add(0x08), 256);
            var tableB = safeHexN(ctx.add(0x108), 256);

            knownContexts[ctxKey] = {
                tableA: tableA,
                tableB: tableB,
                callCount: 0,
                firstCallIndex: callCount,
                counterA_first: counterA,
                counterB_first: counterB
            };

            logBoth("\n=== NEW CIPHER CONTEXT: " + ctx + " ===");
            logBoth("[*] counterA: " + counterA + " counterB: " + counterB);
            log("[TABLE_A_FULL] " + tableA);
            log("[TABLE_B_FULL] " + tableB);

            // Check if tables match any previous context
            var keys = Object.keys(knownContexts);
            for (var i = 0; i < keys.length; i++) {
                if (keys[i] === ctxKey) continue;
                var other = knownContexts[keys[i]];
                var aMatch = (tableA === other.tableA);
                var bMatch = (tableB === other.tableB);
                logBoth("[*] vs " + keys[i] + ": tableA=" + (aMatch ? "MATCH" : "DIFFERENT")
                    + " tableB=" + (bMatch ? "MATCH" : "DIFFERENT"));
            }
            logBoth("=== END CONTEXT DUMP ===\n");
        }

        knownContexts[ctxKey].callCount++;

        // Detailed logging
        if (callCount < MAX_DETAILED_CALLS) {
            var cA = safeReadU32(ctx);
            var cB = safeReadU32(ctx.add(0x04));
            var previewLen = len >= 16 ? 16 : (len > 0 ? len : 0);
            var bufPreview = previewLen > 0 ? safeHexN(buf, previewLen) : "";

            log("[CIPHER #" + callCount + "] ENTER"
                + " ctx=" + ctx
                + " len=" + len
                + " commit=" + commit
                + " cA=" + cA + " cB=" + cB
                + " buf[0:" + previewLen + "]=" + bufPreview);
        }

        callCount++;
    },

    onLeave: function (retval) {
        if (this.callIndex < MAX_DETAILED_CALLS) {
            var previewLen = this.len >= 16 ? 16 : (this.len > 0 ? this.len : 0);
            var bufAfter = previewLen > 0 ? safeHexN(this.buf, previewLen) : "";
            log("[CIPHER #" + this.callIndex + "] LEAVE"
                + " ctx=" + this.ctx
                + " len=" + this.len
                + " commit=" + this.commit
                + " buf_after[0:" + previewLen + "]=" + bufAfter);
        }
    }
});

function printSummary() {
    logBoth("\n=== STAGE 4b SUMMARY ===");
    logBoth("Total custom_cipher calls: " + callCount);

    var keys = Object.keys(knownContexts);
    logBoth("Unique contexts: " + keys.length);

    for (var i = 0; i < keys.length; i++) {
        var info = knownContexts[keys[i]];
        logBoth("  Context " + keys[i]
            + " — calls=" + info.callCount
            + " firstCall=#" + info.firstCallIndex
            + " initialCounters=(" + info.counterA_first + "," + info.counterB_first + ")");
    }

    // Compare all tables
    if (keys.length >= 2) {
        logBoth("\nTable comparison:");
        for (var i = 0; i < keys.length; i++) {
            for (var j = i + 1; j < keys.length; j++) {
                var a = knownContexts[keys[i]];
                var b = knownContexts[keys[j]];
                logBoth("  " + keys[i] + " vs " + keys[j] + ":"
                    + " tableA=" + (a.tableA === b.tableA ? "IDENTICAL" : "DIFFERENT")
                    + " tableB=" + (a.tableB === b.tableB ? "IDENTICAL" : "DIFFERENT"));
            }
        }
    }

    logBoth("=== END SUMMARY ===");
    logFile.close();
}

rpc.exports = {
    summary: printSummary
};

logBoth("[*] Hook installed! Login, play ~30 seconds, then printSummary() + Ctrl+D.\n");
logBoth("[*] Tables will be dumped on first custom_cipher call.");
logBoth("[*] Type printSummary() before detaching.\n");