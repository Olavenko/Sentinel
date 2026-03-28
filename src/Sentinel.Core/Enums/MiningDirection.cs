namespace Sentinel.Core.Enums;

/// <summary>
/// Directions for the mining action.
/// Values match the CO protocol direction encoding.
/// </summary>
public enum MiningDirection : byte
{
    SouthWest = 0,
    West = 1,
    NorthWest = 2,
    North = 3,
    NorthEast = 4,
    East = 5,
    SouthEast = 6,
    South = 7
}
