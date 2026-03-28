namespace Sentinel.Core.Enums;

/// <summary>
/// Known spell IDs from patch 5xxx.
/// Extend as new spells are discovered in 7xxx.
/// </summary>
public enum SpellId : ushort
{
    // Taoist — offensive
    Thunder = 1000,
    Fire = 1001,
    Tornado = 1002,
    Lightning = 1010,
    FireCircle = 1120,
    Volcano = 1125,
    FireRing = 1150,
    Bomb = 1160,
    FireofHell = 1165,
    FireMeteor = 1180,

    // Taoist — support
    Cure = 1005,
    Accuracy = 1015,
    Shield = 1020,
    Superman = 1025,
    Revive = 1050,
    HealingRain = 1055,
    AdvancedCure = 1175,
    Nectar = 1170,
    SpiritHealing = 1190,
    Pray = 1100,
    StarOfAccuracy = 1085,
    MagicShield = 1090,
    Stigma = 1095,
    Meditation = 1195,
    Invisibility = 1075,

    // Trojan
    FastBlade = 1045,
    ScentSword = 1046,
    Cyclone = 1110,
    Hercules = 1115,
    Roar = 1040,
    Dash = 1051,

    // Warrior
    FlyingMoon = 1320,

    // Ninja
    TwofoldBlades = 6000,
    ToxicFog = 6001,
    PoisonStar = 6002,
    ArcherBane = 6004,
    ShurikenVortex = 6010,
    FatalStrike = 6011,

    // Archer
    RapidFire = 8000,
    Scatter = 8001,
    Fly = 8003,
    ArrowRain = 8030,
    Intensify = 9000,
    Guard = 8311,

    // Summons
    SummonGuard = 4000,
    SummonBat = 4010,
    SummonBatBoss = 4020,
    BloodyBat = 4040,
    FireEvil = 4060,
    Skeleton = 4070,
    CruelShade = 3050,

    // Pets / companions
    Golem = 1270,
    WaterElf = 1280,
    DivineHare = 1350,
    NightDevil = 1360,
    Phoenix = 5030,

    // Dances
    Dance2 = 1380,
    Dance3 = 1385,
    Dance4 = 1390,
    Dance5 = 1395,
    Dance6 = 1400,
    Dance7 = 1405,
    Dance8 = 1410
}
