using System.Buffers;
using System.IO.Pipelines;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Enums;
using Sentinel.Core.Interfaces;
using Sentinel.Crypto;
using Sentinel.Crypto.Interfaces;
using Sentinel.Network.Handshake;

namespace Sentinel.Network.Proxy;

/// <summary>
/// A single proxied connection between a game client and the remote server.
/// Forwards all bytes bidirectionally using System.IO.Pipelines.
/// When MITM is enabled, intercepts the DH handshake, performs key exchange
/// with both sides, and decrypts/re-encrypts all traffic transparently.
/// </summary>
public sealed class ProxySession : IProxySession
{
    private readonly TcpClient _client;
    private readonly TcpClient _server;
    private readonly IPacketLogger _packetLogger;
    private readonly ILogger<ProxySession> _logger;
    private readonly string _endpointName;
    private readonly bool _enableMitm;
    private readonly bool _enableGameplayDecrypt;
    private readonly Func<bool, ICipher>? _handshakeCipherFactory;

    // Read-only gameplay decryption state (null when not in this mode)
    private GameplaySessionState? _gameplayState;

    private long _bytesToServer;
    private long _bytesToClient;
    private long _packetsToServer;
    private long _packetsToClient;
    private bool _isActive;

    // Post-handshake cipher instances (null = transparent mode)
    private BlowfishCfb64Cipher? _clientDecrypt; // Decrypt data FROM client
    private BlowfishCfb64Cipher? _clientEncrypt; // Encrypt data TO client
    private BlowfishCfb64Cipher? _serverDecrypt; // Decrypt data FROM server
    private BlowfishCfb64Cipher? _serverEncrypt; // Encrypt data TO server

    public Guid Id { get; } = Guid.NewGuid();
    public DateTimeOffset ConnectedAt { get; } = DateTimeOffset.UtcNow;
    public bool IsActive => _isActive;
    public long BytesSentToServer => Interlocked.Read(ref _bytesToServer);
    public long BytesSentToClient => Interlocked.Read(ref _bytesToClient);
    public long PacketsSentToServer => Interlocked.Read(ref _packetsToServer);
    public long PacketsSentToClient => Interlocked.Read(ref _packetsToClient);
    public string EndpointName => _endpointName;

    public event Action<IProxySession, Exception?>? Disconnected;

    public ProxySession(
        TcpClient client,
        TcpClient server,
        IPacketLogger packetLogger,
        ILogger<ProxySession> logger,
        string endpointName,
        bool enableMitm = false,
        Func<bool, ICipher>? handshakeCipherFactory = null,
        bool enableGameplayDecrypt = false)
    {
        _client = client;
        _server = server;
        _packetLogger = packetLogger;
        _logger = logger;
        _endpointName = endpointName;
        _enableMitm = enableMitm;
        _handshakeCipherFactory = handshakeCipherFactory;
        _enableGameplayDecrypt = enableGameplayDecrypt;
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        _isActive = true;
        Exception? disconnectReason = null;

        try
        {
            var clientStream = _client.GetStream();
            var serverStream = _server.GetStream();

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            // Perform DH MITM handshake if enabled for this endpoint
            if (_enableMitm)
            {
                try
                {
                    await PerformHandshakeAsync(clientStream, serverStream, linkedCts.Token);
                    _logger.LogInformation("[{Endpoint}] Session {Id:N8} — DH MITM handshake complete, traffic is now decryptable",
                        _endpointName, Id.ToString()[..8]);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[{Endpoint}] Session {Id:N8} — DH MITM handshake failed, falling back to transparent forwarding",
                        _endpointName, Id.ToString()[..8]);
                    DisposeCiphers();
                }
            }

            // Initialise read-only gameplay decryption (only when MITM is not active)
            if (_enableGameplayDecrypt && !_enableMitm)
                _gameplayState = new GameplaySessionState();

            var clientToServer = ForwardAsync(
                clientStream, serverStream,
                PacketDirection.ClientToServer,
                linkedCts.Token);

            var serverToClient = ForwardAsync(
                serverStream, clientStream,
                PacketDirection.ServerToClient,
                linkedCts.Token);

            // Wait for the first direction to finish (one side stopped sending).
            var first = await Task.WhenAny(clientToServer, serverToClient);

            // TCP half-close: signal the other side that no more data is coming
            if (first == clientToServer)
                try { _server.Client.Shutdown(SocketShutdown.Send); } catch { }
            else
                try { _client.Client.Shutdown(SocketShutdown.Send); } catch { }

            // Now wait for the remaining direction to complete naturally
            try { await clientToServer; } catch (OperationCanceledException) { }
            try { await serverToClient; } catch (OperationCanceledException) { }

            if (clientToServer.IsFaulted)
                disconnectReason = clientToServer.Exception?.InnerException;
            else if (serverToClient.IsFaulted)
                disconnectReason = serverToClient.Exception?.InnerException;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            disconnectReason = ex;
        }
        finally
        {
            _isActive = false;
            DisposeCiphers();
            await _packetLogger.FlushAsync();
            Disconnected?.Invoke(this, disconnectReason);
        }
    }

    /// <summary>
    /// Perform the CO 7xxx DH MITM handshake by delegating to <see cref="HandshakeMitm"/>.
    /// The client sends the DH init first; the server replies.
    /// On success, four BF-CFB64 session ciphers are assigned to the session fields.
    /// </summary>
    private async Task PerformHandshakeAsync(
        NetworkStream clientStream,
        NetworkStream serverStream,
        CancellationToken ct)
    {
        if (_handshakeCipherFactory is null)
            throw new InvalidOperationException(
                "MITM is enabled but no handshake cipher factory was provided. " +
                "Ensure HandshakeChainTablePath is set and the chain table file exists.");

        var mitm = new HandshakeMitm(_handshakeCipherFactory, _logger);
        var result = await mitm.PerformAsync(clientStream, serverStream, ct);

        // Transfer cipher ownership from HandshakeResult to the session fields.
        _clientDecrypt = result.ClientDecrypt;
        _clientEncrypt = result.ClientEncrypt;
        _serverDecrypt = result.ServerDecrypt;
        _serverEncrypt = result.ServerEncrypt;
    }

    /// <summary>
    /// Forward all data from source to destination, logging each chunk.
    /// When MITM ciphers are active, decrypts for logging and re-encrypts for forwarding.
    /// </summary>
    private async Task ForwardAsync(
        NetworkStream source,
        NetworkStream destination,
        PacketDirection direction,
        CancellationToken ct)
    {
        var dirLabel = direction == PacketDirection.ClientToServer ? "C→S" : "S→C";
        _logger.LogDebug("[{Endpoint}] {Dir} relay started", _endpointName, dirLabel);

        var decryptCipher = direction == PacketDirection.ClientToServer ? _clientDecrypt : _serverDecrypt;
        var encryptCipher = direction == PacketDirection.ClientToServer ? _serverEncrypt : _clientEncrypt;

        var reader = PipeReader.Create(source, new StreamPipeReaderOptions(
            bufferSize: 8192,
            leaveOpen: true));

        try
        {
            while (true)
            {
                var result = await reader.ReadAsync(ct);
                var buffer = result.Buffer;

                if (buffer.Length > 0)
                {
                    var timestamp = DateTimeOffset.UtcNow;

                    foreach (var segment in buffer)
                    {
                        if (direction == PacketDirection.ClientToServer)
                        {
                            Interlocked.Add(ref _bytesToServer, segment.Length);
                            Interlocked.Increment(ref _packetsToServer);
                        }
                        else
                        {
                            Interlocked.Add(ref _bytesToClient, segment.Length);
                            Interlocked.Increment(ref _packetsToClient);
                        }

                        if (decryptCipher is not null && encryptCipher is not null)
                        {
                            // MITM mode: decrypt → log plaintext → re-encrypt → forward
                            var mutable = segment.ToArray();
                            decryptCipher.Decrypt(mutable);

                            try
                            {
                                await _packetLogger.LogPacketAsync(Id, direction, mutable, timestamp);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex,
                                    "[{Endpoint}] {Dir} packet logging failed ({Bytes} bytes)",
                                    _endpointName, dirLabel, segment.Length);
                            }

                            encryptCipher.Encrypt(mutable);
                            await destination.WriteAsync(mutable, ct);
                        }
                        else if (_gameplayState is not null)
                        {
                            // Read-only gameplay decrypt mode:
                            // always forward the original encrypted bytes; log a decrypted copy.
                            if (_gameplayState.Phase == SessionPhase.Handshake)
                            {
                                bool switched = _gameplayState.OnHandshakeMessage(direction, segment.Length);
                                _logger.LogInformation(
                                    "[{Endpoint}] Session {Id:N8} — Handshake msg: {Dir} {Size} bytes (C2S={C2S}, S2C={S2C})",
                                    _endpointName, Id.ToString()[..8], dirLabel, segment.Length,
                                    _gameplayState.ClientToServerCount, _gameplayState.ServerToClientCount);
                                if (switched)
                                    _logger.LogInformation(
                                        "[{Endpoint}] Session {Id:N8} — Handshake complete, switching to gameplay decryption (total handshake: C2S={C2SBytes} bytes, S2C={S2CBytes} bytes)",
                                        _endpointName, Id.ToString()[..8],
                                        _gameplayState.TotalClientToServerBytes,
                                        _gameplayState.TotalServerToClientBytes);

                                // Handshake messages pass through as-is (log raw bytes)
                                try
                                {
                                    await _packetLogger.LogPacketAsync(Id, direction, segment, timestamp);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogWarning(ex,
                                        "[{Endpoint}] {Dir} packet logging failed ({Bytes} bytes)",
                                        _endpointName, dirLabel, segment.Length);
                                }
                            }
                            else
                            {
                                // Gameplay phase: decrypt a copy for the log, forward the original
                                var copy = segment.ToArray();
                                if (direction == PacketDirection.ServerToClient)
                                {
                                    int cA = _gameplayState.RecvCounterA;
                                    int cB = _gameplayState.RecvCounterB;
                                    ConquerCipher.Transform(copy, 0, copy.Length, ref cA, ref cB);
                                    _gameplayState.RecvCounterA = cA;
                                    _gameplayState.RecvCounterB = cB;
                                }
                                else
                                {
                                    int cA = 0, cB = 0;
                                    ConquerCipher.Transform(copy, 0, copy.Length, ref cA, ref cB);
                                }

                                // DEBUG: show first 8 bytes of original vs decrypted
                                if (copy.Length >= 8)
                                {
                                    _logger.LogDebug(
                                        "[{Endpoint}] {Dir} DECRYPT CHECK — original: {Orig} → decrypted: {Dec}",
                                        _endpointName, dirLabel,
                                        BitConverter.ToString(segment.ToArray(), 0, Math.Min(8, segment.Length)),
                                        BitConverter.ToString(copy, 0, Math.Min(8, copy.Length)));
                                }

                                try
                                {
                                    await _packetLogger.LogPacketAsync(Id, direction, copy, timestamp);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogWarning(ex,
                                        "[{Endpoint}] {Dir} packet logging failed ({Bytes} bytes)",
                                        _endpointName, dirLabel, segment.Length);
                                }
                            }

                            // Always forward the original encrypted segment
                            await destination.WriteAsync(segment, ct);
                        }
                        else
                        {
                            // Transparent mode: log raw → forward
                            try
                            {
                                await _packetLogger.LogPacketAsync(Id, direction, segment, timestamp);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex,
                                    "[{Endpoint}] {Dir} packet logging failed ({Bytes} bytes)",
                                    _endpointName, dirLabel, segment.Length);
                            }

                            await destination.WriteAsync(segment, ct);
                        }
                    }
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                {
                    _logger.LogDebug("[{Endpoint}] {Dir} stream completed (remote closed)",
                        _endpointName, dirLabel);
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("[{Endpoint}] {Dir} relay cancelled", _endpointName, dirLabel);
            throw;
        }
        catch (IOException ex)
        {
            _logger.LogDebug("[{Endpoint}] {Dir} relay ended — IOException: {Message}",
                _endpointName, dirLabel, ex.Message);
        }
        catch (SocketException ex)
        {
            _logger.LogDebug("[{Endpoint}] {Dir} relay ended — SocketException: {Message}",
                _endpointName, dirLabel, ex.Message);
        }
        finally
        {
            await reader.CompleteAsync();
        }
    }

    private void DisposeCiphers()
    {
        _clientDecrypt?.Dispose();
        _clientEncrypt?.Dispose();
        _serverDecrypt?.Dispose();
        _serverEncrypt?.Dispose();
        _clientDecrypt = null;
        _clientEncrypt = null;
        _serverDecrypt = null;
        _serverEncrypt = null;
    }

    public async ValueTask DisposeAsync()
    {
        _isActive = false;

        try { _client.Close(); } catch { }
        try { _server.Close(); } catch { }

        _client.Dispose();
        _server.Dispose();

        DisposeCiphers();
        await _packetLogger.FlushAsync();
    }
}
