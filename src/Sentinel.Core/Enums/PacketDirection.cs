namespace Sentinel.Core.Enums;

/// <summary>
/// Direction of a packet relative to the proxy.
/// </summary>
public enum PacketDirection : byte
{
    ClientToServer,
    ServerToClient
}
