#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "vip.cpp").read_text(encoding="utf-8")


def main():
    required = (
        "std::map<uint64, VipPlayer>",
        "BIGINT UNSIGNED NOT NULL",
        "ALTER TABLE `vip_users` MODIFY `account_id` BIGINT UNSIGNED NOT NULL",
        "uint32 legacySteamID = static_cast<uint32>(m_steamID)",
        "account_id` IN (%llu, %u)",
        "NormalizeSteamID64",
        "MigrateLegacyClientData",
        "FOR_EACH_VALUE(legacyData, pValue)",
    )
    missing = [item for item in required if item not in SOURCE]
    forbidden = [
        "uint32 m_steamID",
        "GetStaticAccountKey()",
    ]
    present_forbidden = [item for item in forbidden if item in SOURCE]
    if missing or present_forbidden:
        if missing:
            print("Missing SteamID64 migration items:", *missing, sep="\n- ")
        if present_forbidden:
            print("Legacy SteamID items:", *present_forbidden, sep="\n- ")
        return 1
    print("SteamID64 persistence contract check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
