using System.Text.Json;

namespace Sentinel.Crypto;

/// <summary>
/// Loads a Blowfish chain table from a JSON resource file.
///
/// The JSON format is a flat object whose keys and values are 16-character
/// lowercase hex strings representing 8-byte big-endian uint64 values:
/// <code>
/// {
///   "0000000000000000": "bc8a80e5bfb0141d",
///   "bc8a80e5bfb0141d": "694d6035a12e9daf"
/// }
/// </code>
/// Lines beginning with underscore (e.g. "_comment") are silently ignored.
/// </summary>
public static class ChainTableLoader
{
    /// <summary>Default path relative to the application working directory.</summary>
    public const string DefaultPath = "resources/handshake-chain-table.json";

    /// <summary>
    /// Load the chain table from <paramref name="path"/>.
    /// Throws if the file does not exist or cannot be parsed.
    /// </summary>
    public static Dictionary<ulong, ulong> LoadFromFile(string path)
    {
        var json = File.ReadAllText(path);
        var raw = JsonSerializer.Deserialize<Dictionary<string, string>>(json)
            ?? throw new InvalidDataException($"Chain table file is empty or invalid: {path}");

        var table = new Dictionary<ulong, ulong>(raw.Count);
        foreach (var (k, v) in raw)
        {
            // Skip metadata keys (e.g. "_comment")
            if (k.StartsWith('_')) continue;
            table[Convert.ToUInt64(k, 16)] = Convert.ToUInt64(v, 16);
        }
        return table;
    }

    /// <summary>
    /// Load the chain table from <paramref name="path"/> if it exists,
    /// otherwise return an empty table without throwing.
    /// </summary>
    public static Dictionary<ulong, ulong> TryLoadFromFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return [];
        return LoadFromFile(path);
    }
}
