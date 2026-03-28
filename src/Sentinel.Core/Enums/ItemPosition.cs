namespace Sentinel.Core.Enums;

/// <summary>
/// Equipment slot and inventory positions.
/// </summary>
public enum ItemPosition : byte
{
    Inventory = 0,
    Head = 1,
    Necklace = 2,
    Armor = 3,
    RightHand = 4,
    LeftHand = 5,
    Ring = 6,
    Bottle = 7,
    Boots = 8,
    Garment = 9,
    Fan = 10,
    Tower = 11,
    Steed = 12,

    // Alternative gear set
    AlternativeHead = 21,
    AlternativeNecklace = 22,
    AlternativeArmor = 23,
    AlternativeRightHand = 24,
    AlternativeLeftHand = 25,
    AlternativeRing = 26,
    AlternativeBottle = 27,
    AlternativeBoots = 28,
    AlternativeGarment = 29
}
