// Frida v14 — Module Map & Address Resolver
// Goal: See the full memory map and find where BF_cfb64_encrypt actually lives

var now = new Date();
var ts = now.getFullYear()
    + "-" + String(now.getMonth() + 1).padStart(2, '0')
    + "-" + String(now.getDate()).padStart(2, '0')
    + "_" + String(now.getHours()).padStart(2, '0')
    + "-" + String(now.getMinutes()).padStart(2, '0')
    + "-" + String(now.getSeconds()).padStart(2, '0');
var logPath = "F:\\Sentinel\\tools\\frida_v14_modules_" + ts + ".log";
var logFile = new File(logPath, "w");

function log(msg) {
    logFile.write(msg + "\n");
    logFile.flush();
}

function logBoth(msg) {
    console.log(msg);
    log(msg);
}

logBoth("[*] Frida v14 — Module Map & Address Resolver — " + now.toISOString());
logBoth("=".repeat(80));

// ---- Step 1: List ALL loaded modules ----
logBoth("\n[MODULES] All loaded modules:");
logBoth("-".repeat(80));

var modules = Process.enumerateModules();

// Sort by base address
modules.sort(function(a, b) {
    return a.base.compare(b.base);
});

for (var i = 0; i < modules.length; i++) {
    var m = modules[i];
    var end = m.base.add(m.size);
    logBoth("[MODULE] " + String(i + 1).padStart(3, ' ')
        + "  base=" + m.base
        + "  end=" + end
        + "  size=" + ("0x" + m.size.toString(16).padStart(8, '0'))
        + "  name=" + m.name
        + "  path=" + m.path);
}

logBoth("\n[MODULES] Total: " + modules.length + " modules loaded");

// ---- Step 2: Resolve known addresses ----
logBoth("\n" + "=".repeat(80));
logBoth("[RESOLVE] Checking known addresses against module map:");
logBoth("-".repeat(80));

var knownAddresses = [
    { name: "BF_cfb64_encrypt",    addr: ptr("0x012410f0") },
    { name: "DoReceiveShakeHand",  addr: ptr("0x00feeb6c") }
];

for (var k = 0; k < knownAddresses.length; k++) {
    var entry = knownAddresses[k];
    var found = false;

    for (var j = 0; j < modules.length; j++) {
        var m = modules[j];
        var end = m.base.add(m.size);

        if (entry.addr.compare(m.base) >= 0 && entry.addr.compare(end) < 0) {
            var offset = entry.addr.sub(m.base);
            logBoth("[RESOLVE] " + entry.name
                + " @ " + entry.addr
                + " => INSIDE [" + m.name + "]"
                + "  offset=0x" + offset.toString(16)
                + "  path=" + m.path);
            found = true;
            break;
        }
    }

    if (!found) {
        logBoth("[RESOLVE] " + entry.name
            + " @ " + entry.addr
            + " => NOT FOUND in any module!");
    }
}

// ---- Step 3: Show RW memory regions (data, not code) ----
logBoth("\n" + "=".repeat(80));
logBoth("[MEMORY] Writable memory regions (rw-):");
logBoth("-".repeat(80));

var rwRanges = Process.enumerateRanges('rw-');
var totalRW = 0;

for (var r = 0; r < rwRanges.length; r++) {
    var range = rwRanges[r];
    var rangeEnd = range.base.add(range.size);
    var owner = "unknown";

    // Find which module owns this range
    for (var m2 = 0; m2 < modules.length; m2++) {
        var mod = modules[m2];
        var modEnd = mod.base.add(mod.size);
        if (range.base.compare(mod.base) >= 0 && range.base.compare(modEnd) < 0) {
            owner = mod.name;
            break;
        }
    }

    var sizeKB = (range.size / 1024).toFixed(1);
    logBoth("[RW] base=" + range.base
        + "  end=" + rangeEnd
        + "  size=" + sizeKB + "KB"
        + "  prot=" + range.protection
        + "  owner=" + owner);

    totalRW += range.size;
}

logBoth("\n[MEMORY] Total RW regions: " + rwRanges.length
    + "  Total size: " + (totalRW / 1024 / 1024).toFixed(1) + " MB");

logBoth("\n" + "=".repeat(80));
logBoth("[*] Done! Check the log at: " + logPath);