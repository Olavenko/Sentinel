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
}
