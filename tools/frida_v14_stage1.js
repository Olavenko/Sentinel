// Frida v14 — Stage 1: Runtime Observation of BF_cfb64_encrypt
// Goal: Log caller, return addr, ctx ptr, ivec, num, len, enc, backtrace
// Usage: frida -p <PID> -l frida_v14_stage1.js

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');

var logPath = "F:\\Sentinel\\tools\\frida_v14_stage1_" + ts + ".log";
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
var bfCfb64Addr = ptr("0x012410f0");
var TARGET_P0 = 0xdb298a75;
var MAX_DETAILED_CALLS = 20;
var BACKTRACE_DEPTH = 6;

// --- State ---
var callCount = 0;
var callerStats = {};  // caller_addr -> { count, enc0: n, enc1: n }
var firstCallTime = null;

logBoth("[*] Frida v14 — Stage 1: BF_cfb64_encrypt observation");
logBoth("[*] Started: " + now.toISOString());
logBoth("[*] Log file: " + logPath);
logBoth("[*] Target: BF_cfb64_encrypt @ " + bfCfb64Addr);
logBoth("[*] Detailed logging for first " + MAX_DETAILED_CALLS + " calls");
logBoth("---");

Interceptor.attach(bfCfb64Addr, {
    onEnter: function (args) {
        var bfKeyPtr = args[3];

        // Filter: only our target cipher context
        var p0;
        try {
            p0 = bfKeyPtr.readU32();
        } catch (e) {
            return;
        }
        if (p0 !== TARGET_P0) return;

        this.shouldLog = true;

        if (firstCallTime === null) {
            firstCallTime = Date.now();
        }

        var inPtr    = args[0];
        var outPtr   = args[1];
        var len      = args[2].toInt32();
        var ivecPtr  = args[4];
        var numPtr   = args[5];
        var enc      = args[6].toInt32();

        // Backtrace
        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        var callerAddr = bt.length > 0 ? bt[0] : ptr("0x0");
        var callerStr = callerAddr.toString();

        // Track caller stats
        if (!callerStats[callerStr]) {
            callerStats[callerStr] = { count: 0, enc0: 0, enc1: 0 };
        }
        callerStats[callerStr].count++;
        if (enc === 0) callerStats[callerStr].enc0++;
        if (enc === 1) callerStats[callerStr].enc1++;

        // Save for onLeave
        this.callIndex = callCount;
        this.outPtr = outPtr;
        this.len = len;
        this.enc = enc;

        // Detailed log for first N calls
        if (callCount < MAX_DETAILED_CALLS) {
            var ivecNow = safeHexN(ivecPtr, 8);
            var numVal = safeReadU32(numPtr);
            var elapsed = Date.now() - firstCallTime;

            var previewLen = len >= 16 ? 16 : (len > 0 ? len : 0);
            var inPreview = previewLen > 0 ? safeHexN(inPtr, previewLen) : "";

            // Format backtrace (all frames)
            var btStr = "";
            for (var i = 0; i < bt.length && i < BACKTRACE_DEPTH; i++) {
                var mod = Process.findModuleByAddress(bt[i]);
                var modName = mod ? mod.name : "???";
                var modOff = mod ? "+" + ptr(bt[i]).sub(mod.base).toString(16) : "";
                btStr += "\n    [" + i + "] " + bt[i] + " " + modName + modOff;
            }

            log("[CALL #" + callCount + "] +=" + elapsed + "ms"
                + " enc=" + enc
                + " len=" + len
                + " num=" + (numVal === null ? "<fail>" : numVal)
                + " ivec=" + ivecNow
                + " ctx=" + bfKeyPtr
                + " caller=" + callerAddr
                + " in[0:" + previewLen + "]=" + inPreview
                + " backtrace:" + btStr);
        }

        callCount++;
    },

    onLeave: function (retval) {
        if (!this.shouldLog) return;

        // Log output for detailed calls only
        if (this.callIndex < MAX_DETAILED_CALLS) {
            var outLen = this.len >= 16 ? 16 : (this.len > 0 ? this.len : 0);
            var outPreview = outLen > 0 ? safeHexN(this.outPtr, outLen) : "";
            log("[CALL #" + this.callIndex + "] LEAVE"
                + " enc=" + this.enc
                + " out[0:" + outLen + "]=" + outPreview);
        }
    }
});

// Print summary on detach
function printSummary() {
    logBoth("\n=== STAGE 1 SUMMARY ===");
    logBoth("Total BF_cfb64_encrypt calls (P0 match): " + callCount);

    var callers = Object.keys(callerStats);
    logBoth("Unique callers: " + callers.length);
    logBoth("");

    for (var i = 0; i < callers.length; i++) {
        var addr = callers[i];
        var s = callerStats[addr];

        var mod = Process.findModuleByAddress(ptr(addr));
        var modInfo = mod ? (mod.name + "+" + ptr(addr).sub(mod.base).toString(16)) : "unknown";

        logBoth("  Caller: " + addr + " (" + modInfo + ")"
            + " — total=" + s.count
            + " enc=1(encrypt)=" + s.enc1
            + " enc=0(decrypt)=" + s.enc0);
    }

    logBoth("\n=== END SUMMARY ===");
    logFile.close();
}

// Replace everything from "Script.bindExitHandler" to end of file with this:

// Manual summary — type printSummary() in Frida console before detaching
rpc.exports = {
    summary: printSummary
};

logBoth("[*] Hook installed! Login now and play for ~30 seconds.");
logBoth("[*] Before detaching, type: rpc.exports.summary() or just call printSummary()");
logBoth("[*] Or paste printSummary() in console, then Ctrl+D.\n");

logBoth("[*] Hook installed! Login now and play for ~30 seconds, then detach (Ctrl+D).");
logBoth("[*] Summary will print on detach.\n");