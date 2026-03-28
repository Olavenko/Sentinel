namespace Sentinel.Core.Enums;

/// <summary>
/// Conquer Online character classes and promotion tiers.
/// Values from patch 5xxx — extend as new classes are discovered in 7xxx.
/// </summary>
public enum CharacterClass : byte
{
    // Trojan line
    InternTrojan = 10,
    Trojan = 11,
    VeteranTrojan = 12,
    TigerTrojan = 13,
    DragonTrojan = 14,
    TrojanMaster = 15,

    // Warrior line
    InternWarrior = 20,
    Warrior = 21,
    BrassWarrior = 22,
    SilverWarrior = 23,
    GoldWarrior = 24,
    WarriorMaster = 25,

    // Archer line
    InternArcher = 40,
    Archer = 41,
    EagleArcher = 42,
    TigerArcher = 43,
    DragonArcher = 44,
    ArcherMaster = 45,

    // Ninja line
    InternNinja = 50,
    Ninja = 51,
    MiddleNinja = 52,
    DarkNinja = 53,
    MysticNinja = 54,
    NinjaMaster = 55,

    // Monk line
    InternMonk = 60,
    Monk = 61,
    DhyanaMonk = 62,
    DharmaMonk = 63,
    PrajnaMonk = 64,
    NirvanaMonk = 65,

    // Taoist base
    InternTaoist = 100,
    Taoist = 101,

    // Water Taoist line
    WaterTaoist = 132,
    WaterWizard = 133,
    WaterMaster = 134,
    WaterSaint = 135,

    // Fire Taoist line
    FireTaoist = 142,
    FireWizard = 143,
    FireMaster = 144,
    FireSaint = 145
}
