namespace Sentinel.Core.Enums;

/// <summary>
/// Chat channel types for in-game messaging.
/// </summary>
public enum ChatType : ushort
{
    Talk = 2000,
    Whisper = 2001,
    Action = 2002,
    Team = 2003,
    Guild = 2004,
    Top = 2005,
    Clan = 2006,
    Friend = 2009,
    Center = 2011,
    Service = 2014,
    World = 2021,
    Qualifier = 2022,
    MiniMap = 2108,
    DisplayScores = 2109
}
