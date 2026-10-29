"""Curated names for extracting threat actors and malware families from report text.

Matching is literal (whole words, case-insensitive): a name is recorded only when
the report itself mentions it. Aliases map to one canonical name. Ambiguous
everyday words (e.g. "Play", "Royal", "Medusa") are deliberately excluded.
"""

import re

# Explicit actor designations used by vendors (e.g. Storm-0940, UAT-11473, APT29, TA505).
# "TA" requires a non-zero first digit: TA0001-TA0043 are MITRE ATT&CK tactics, not actors.
ACTOR_DESIGNATION = re.compile(
    r"\b(?:APT\d{1,3}|FIN\d{1,2}|UNC\d{3,5}|TA[1-9]\d{2,3}|Storm-\d{4}|UAT-\d{3,5}|DEV-\d{4})\b"
)

THREAT_ACTORS: dict[str, tuple[str, ...]] = {
    "Lazarus Group": ("Lazarus Group", "Lazarus"),
    "Kimsuky": ("Kimsuky",),
    "Andariel": ("Andariel",),
    "Sandworm": ("Sandworm", "Seashell Blizzard"),
    "Turla": ("Turla", "Secret Blizzard"),
    "APT28": ("Fancy Bear", "Forest Blizzard"),
    "APT29": ("Cozy Bear", "Midnight Blizzard", "NOBELIUM"),
    "Gamaredon": ("Gamaredon",),
    "Volt Typhoon": ("Volt Typhoon",),
    "Salt Typhoon": ("Salt Typhoon",),
    "Flax Typhoon": ("Flax Typhoon",),
    "Silk Typhoon": ("Silk Typhoon", "HAFNIUM"),
    "Linen Typhoon": ("Linen Typhoon",),
    "Charming Kitten": ("Charming Kitten", "Mint Sandstorm"),
    "MuddyWater": ("MuddyWater", "Mango Sandstorm"),
    "OilRig": ("OilRig",),
    "Scattered Spider": ("Scattered Spider", "Octo Tempest"),
    "LAPSUS$": ("LAPSUS$", "Strawberry Tempest"),
    "Wizard Spider": ("Wizard Spider",),
    "Evil Corp": ("Evil Corp",),
    "TA505": ("Lace Tempest",),
    "Mustang Panda": ("Mustang Panda",),
    "Earth Lusca": ("Earth Lusca",),
    "BlueNoroff": ("BlueNoroff", "Sapphire Sleet"),
}

MALWARE_FAMILIES: dict[str, tuple[str, ...]] = {
    "LockBit": ("LockBit",),
    "BlackCat": ("BlackCat", "ALPHV"),
    "Akira": ("Akira ransomware", "Akira"),
    "Black Basta": ("Black Basta", "BlackBasta"),
    "Rhysida": ("Rhysida",),
    "Clop": ("Cl0p", "Clop"),
    "Conti": ("Conti",),
    "Ryuk": ("Ryuk",),
    "Qilin": ("Qilin",),
    "BianLian": ("BianLian",),
    "SafePay": ("SafePay",),
    "Interlock": ("Interlock ransomware",),
    "8Base": ("8Base",),
    "QakBot": ("QakBot", "Qbot"),
    "Emotet": ("Emotet",),
    "IcedID": ("IcedID",),
    "TrickBot": ("TrickBot",),
    "Latrodectus": ("Latrodectus",),
    "Pikabot": ("Pikabot",),
    "Bumblebee": ("Bumblebee loader",),
    "DarkGate": ("DarkGate",),
    "SmokeLoader": ("SmokeLoader",),
    "GootLoader": ("GootLoader",),
    "SocGholish": ("SocGholish",),
    "Cobalt Strike": ("Cobalt Strike",),
    "Sliver": ("Sliver C2",),
    "Brute Ratel": ("Brute Ratel",),
    "Mimikatz": ("Mimikatz",),
    "AsyncRAT": ("AsyncRAT",),
    "Remcos": ("Remcos",),
    "njRAT": ("njRAT",),
    "Agent Tesla": ("Agent Tesla", "AgentTesla"),
    "RedLine": ("RedLine Stealer",),
    "Lumma": ("LummaC2", "Lumma Stealer", "Lumma"),
    "Vidar": ("Vidar",),
    "PlugX": ("PlugX",),
    "ShadowPad": ("ShadowPad",),
    "Mirai": ("Mirai",),
}


def _compile(catalog: dict[str, tuple[str, ...]]) -> list[tuple[str, re.Pattern[str]]]:
    return [
        (
            canonical,
            re.compile(
                # Hyphens count as word characters: "conti-nued" must not match "Conti".
                r"(?<![\w$-])(?:" + "|".join(re.escape(a) for a in aliases) + r")(?![\w$-])",
                re.IGNORECASE,
            ),
        )
        for canonical, aliases in catalog.items()
    ]


ACTOR_PATTERNS = _compile(THREAT_ACTORS)
MALWARE_PATTERNS = _compile(MALWARE_FAMILIES)
