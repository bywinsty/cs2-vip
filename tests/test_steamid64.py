#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "vip.cpp").read_text(encoding="utf-8")
MIGRATION = (ROOT / "include/vip_database_migration.h").read_text(encoding="utf-8")


def main():
    required = (
        "std::map<uint64, VipPlayer>",
        "BIGINT UNSIGNED NOT NULL",
        "ALTER TABLE `vip_users` MODIFY `account_id` BIGINT UNSIGNED NOT NULL",
        "uint32 legacySteamID = static_cast<uint32>(m_steamID)",
        "account_id` IN (%llu, %u)",
        "MigrateLegacyClientData",
        "FOR_EACH_VALUE(legacyData, pValue)",
        "enum class DatabaseState",
        "DatabaseReady()",
        "StartDatabaseMigration()",
        "ExecuteTransaction",
        "SetReady(false)",
        "std::from_chars",
    )
    missing = [item for item in required if item not in SOURCE and item not in MIGRATION]
    migration_required = (
        "GET_LOCK", "vip_schema_migrations", "vip_users_migration_conflicts",
        "4294967296", "steamid64-v2", "BIGINT SIGNED NOT NULL",
    )
    missing.extend(item for item in migration_required if item not in MIGRATION)
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
