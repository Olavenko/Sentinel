namespace Sentinel.Core.Models;

/// <summary>
/// Configuration for a single proxy listener (auth or game).
/// </summary>
public sealed class ProxyEndpointConfig
{
    /// <summary>Local port to listen on for client connections.</summary>
    public int ListenPort { get; set; }

    /// <summary>Remote server hostname or IP to forward traffic to.</summary>
    public string RemoteHost { get; set; } = "127.0.0.1";

    /// <summary>Remote server port to forward traffic to.</summary>
    public int RemotePort { get; set; }

    /// <summary>Human-readable name for logging (e.g. "Auth", "Game").</summary>
    public string Name { get; set; } = "";

    /// <summary>Whether to perform DH MITM on this endpoint to decrypt traffic.</summary>
    public bool EnableMitm { get; set; }

    /// <summary>
    /// Whether to apply the CO 7xxx gameplay cipher to server→client packets for
    /// read-only decryption logging. The original encrypted bytes are always forwarded
    /// unchanged — only the logged copy is decrypted. Mutually exclusive with
    /// <see cref="EnableMitm"/>; if both are set, MITM takes precedence.
    /// </summary>
    public bool EnableGameplayDecrypt { get; set; }

    /// <summary>
    /// When <see cref="EnableGameplayDecrypt"/> is set, indicates the connection's cipher is
    /// active from the very first byte, with no DH handshake to skip. This is the case for the
    /// CO 7xxx Auth connection (port 80), where the dual-table cipher starts immediately at
    /// counters (0, 0). When <see langword="false"/>, the session passes the handshake messages
    /// through unchanged and only begins decrypting once the handshake completes.
    /// </summary>
    public bool CipherActiveFromStart { get; set; }

    /// <summary>
    /// Whether to apply the port-19000 TQ-customized CAST5-variant CFB64 cipher to gameplay
    /// packets for read-only decryption logging, seeded from the live Frida keyfeed file
    /// (see <see cref="ProxyConfiguration.GameSessionKeyPath"/>). The original encrypted bytes
    /// are always forwarded unchanged — only the logged copy is decrypted. Independent of, and
    /// not to be combined with, <see cref="EnableGameplayDecrypt"/> (the dual-table port-80
    /// cipher) or <see cref="EnableMitm"/>; if MITM is also set, MITM takes precedence.
    /// The session buffers each direction until the keyfeed key lands, then begins decrypting
    /// at the captured static→DH switch offset.
    /// </summary>
    public bool EnableCast5GameplayDecrypt { get; set; }
}

/// <summary>
/// Top-level proxy configuration, bound from appsettings.json.
/// </summary>
public sealed class ProxyConfiguration
{
    public const string SectionName = "Proxy";

    /// <summary>All proxy endpoints to listen on.</summary>
    public List<ProxyEndpointConfig> Endpoints { get; set; } = [];

    /// <summary>Directory to save packet log files.</summary>
    public string LogDirectory { get; set; } = "logs";

    /// <summary>Whether to output packet hex to console.</summary>
    public bool LogToConsole { get; set; } = true;

    /// <summary>
    /// Path to the BF_encrypt chain table JSON file used for handshake decryption.
    /// Relative to the application working directory.
    /// Extend the table by running tools/frida/capture-keystream.js against the game process.
    /// </summary>
    public string HandshakeChainTablePath { get; set; } = "resources/handshake-chain-table.json";

    /// <summary>
    /// Path used to locate the <c>keys\</c> directory for the port-19000 CAST5-variant
    /// gameplay cipher keyfeed files (written per-PID as <c>game-session-&lt;pid&gt;.key.json</c>
    /// by <c>tools/frida_v22_keyfeed.js</c>). Consumed by endpoints with
    /// <see cref="ProxyEndpointConfig.EnableCast5GameplayDecrypt"/> set. Absolute, or relative
    /// to the application base directory. Only the DIRECTORY of this path is used: the whole
    /// directory is watched for <c>game-session-*.key.json</c> files (one per game client), and
    /// each is reloaded on change so several accounts can be active at once.
    /// </summary>
    public string GameSessionKeyPath { get; set; } = "keys/game-session.key.json";

    /// <summary>
    /// Console output verbosity: "minimal", "normal", or "verbose".
    /// minimal = session start/end + periodic summary only.
    /// normal  = session start/end + per-packet one-liner (direction, size, no hex).
    /// verbose = everything including hex dumps (for debugging).
    /// </summary>
    public string ConsoleVerbosity { get; set; } = "minimal";

    /// <summary>
    /// Settings for the proxy-only Frida keyfeed supervisor, which (when enabled) auto-attaches
    /// the CAST5 keyfeed script to every live game client so the operator only has to start the
    /// proxy. Only consulted when at least one endpoint sets
    /// <see cref="ProxyEndpointConfig.EnableCast5GameplayDecrypt"/>.
    /// </summary>
    public KeyfeedConfig Keyfeed { get; set; } = new();
}

/// <summary>
/// Configuration for the proxy-only Frida keyfeed supervisor. When <see cref="AutoSpawn"/> is set
/// (and any endpoint enables CAST5 gameplay decrypt), the proxy launches one Frida child per live
/// game process to feed per-PID session keys — no separate tool needs to be run by hand. The
/// supervisor deletes a client's <c>game-session-&lt;pid&gt;.key.json</c> ONLY when that game
/// process exits; a bare Frida-child crash with the game still alive is respawned without touching
/// the live key.
/// </summary>
public sealed class KeyfeedConfig
{
    /// <summary>
    /// Whether the proxy auto-spawns the Frida keyfeed per game client. Default <see langword="true"/>:
    /// starting the proxy with CAST5 gameplay decrypt enabled also arms the keyfeed supervisor, so the
    /// operator runs the proxy and nothing else. Set to <see langword="false"/> to instead produce
    /// <c>game-session-&lt;pid&gt;.key.json</c> files manually (via <c>tools/frida_v22_keyfeed.js</c>);
    /// the proxy then warns loudly at startup if none are present.
    /// </summary>
    public bool AutoSpawn { get; set; } = true;

    /// <summary>Path to the Frida CLI executable. May be a bare name resolved via PATH (e.g. "frida")
    /// or an absolute path. Default "frida".</summary>
    public string FridaPath { get; set; } = "frida";

    /// <summary>Path to the keyfeed Frida script to inject. Relative paths are resolved against the
    /// current working directory. Default "tools/frida_v22_keyfeed.js".</summary>
    public string ScriptPath { get; set; } = "tools/frida_v22_keyfeed.js";

    /// <summary>Process name (with or without ".exe") whose instances are the game clients to attach
    /// to. Default "Conquer.exe".</summary>
    public string ProcessName { get; set; } = "Conquer.exe";

    /// <summary>How often (milliseconds) the supervisor reconciles game processes against running
    /// Frida children. Default 2000.</summary>
    public int PollIntervalMs { get; set; } = 2000;

    /// <summary>Seconds a Frida child must stay alive before its crash counter resets — a child that
    /// ran healthily for this long and then dies is treated as a fresh restart, not a rapid crash.
    /// Default 20.</summary>
    public int HealthyUptimeSeconds { get; set; } = 20;

    /// <summary>How many rapid (sub-<see cref="HealthyUptimeSeconds"/>) crashes for one PID are
    /// tolerated before the supervisor gives up auto-respawning that PID. Default 5.</summary>
    public int MaxRapidRespawns { get; set; } = 5;

    /// <summary>Directory for per-PID Frida child stdout/stderr logs (one
    /// <c>keyfeed-&lt;pid&gt;.log</c> per client). Relative paths are resolved against the current
    /// working directory. Default "logs/keyfeed".</summary>
    public string OutputLogPath { get; set; } = "logs/keyfeed";
}
