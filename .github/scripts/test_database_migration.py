#!/usr/bin/env python3
"""Exercise the SteamID64 migration SQL against a real MySQL-compatible server."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "include/vip_database_migration.h").read_text(encoding="utf-8")
BASE = 76561197960265728


def cli() -> str:
    for candidate in ("mariadb", "mysql"):
        path = shutil.which(candidate)
        if path:
            return path
    raise RuntimeError("mariadb/mysql client is not installed")


class Database:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.client = cli()

    def run(self, sql: str, database: bool = True) -> str:
        command = [self.client, "--batch", "--skip-column-names", "--protocol=tcp",
                   "--host", self.args.host, "--port", str(self.args.port),
                   "--user", self.args.user]
        if database:
            command.extend(["--database", self.args.database])
        environment = os.environ.copy()
        environment["MYSQL_PWD"] = self.args.password
        completed = subprocess.run(command, input=sql, text=True, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if completed.returncode:
            raise AssertionError(f"SQL failed ({completed.returncode}): {completed.stdout}")
        return completed.stdout.strip()

    def reset(self, rows: str, account_type: str = "INT") -> None:
        self.run(
            "DROP TABLE IF EXISTS vip_users_migration_conflicts, vip_schema_migrations, vip_users;"
            f"CREATE TABLE vip_users (account_id {account_type} NOT NULL, name VARCHAR(64) NOT NULL, "
            "lastvisit INT UNSIGNED NOT NULL, sid INT UNSIGNED NOT NULL, `group` VARCHAR(64) NOT NULL, "
            "expires INT UNSIGNED NOT NULL, PRIMARY KEY(account_id, sid));"
            f"INSERT INTO vip_users VALUES {rows};"
        )
        self.run(
            "CREATE TABLE vip_users_migration_conflicts (migration_version VARCHAR(64) NOT NULL, "
            "original_account_id BIGINT NOT NULL, canonical_account_id BIGINT UNSIGNED NOT NULL, "
            "sid INT UNSIGNED NOT NULL, name VARCHAR(64) NOT NULL, lastvisit INT UNSIGNED NOT NULL, "
            "`group` VARCHAR(64) NOT NULL, expires INT UNSIGNED NOT NULL, reason VARCHAR(64) NOT NULL, "
            "archived_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "PRIMARY KEY(migration_version, original_account_id, canonical_account_id, sid, reason));"
        )

    def migrate(self) -> None:
        column_type = self.run(
            "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' AND COLUMN_NAME='account_id';"
        ).lower()
        if "bigint" not in column_type:
            self.run("ALTER TABLE vip_users MODIFY account_id BIGINT SIGNED NOT NULL;")
        self.run(
            "INSERT IGNORE INTO vip_users_migration_conflicts "
            "(migration_version,original_account_id,canonical_account_id,sid,name,lastvisit,`group`,expires,reason) "
            "SELECT 'steamid64-v2', legacy.account_id, canonical.account_id, legacy.sid, legacy.name, "
            "legacy.lastvisit, legacy.`group`, legacy.expires, 'canonical-steamid64-wins' "
            "FROM vip_users legacy JOIN vip_users canonical ON canonical.sid=legacy.sid "
            "AND canonical.account_id=76561197960265728 + CASE WHEN legacy.account_id < 0 "
            "THEN legacy.account_id + 4294967296 ELSE legacy.account_id END "
            "WHERE legacy.account_id < 0 OR legacy.account_id BETWEEN 1 AND 4294967295;"
            "INSERT IGNORE INTO vip_users_migration_conflicts "
            "(migration_version,original_account_id,canonical_account_id,sid,name,lastvisit,`group`,expires,reason) "
            "SELECT 'steamid64-v2', negative.account_id, positive.account_id, negative.sid, negative.name, "
            "negative.lastvisit, negative.`group`, negative.expires, 'positive-legacy-wins' "
            "FROM vip_users negative JOIN vip_users positive ON positive.sid=negative.sid "
            "AND positive.account_id=negative.account_id+4294967296 WHERE negative.account_id < 0;"
            "DELETE legacy FROM vip_users legacy JOIN vip_users canonical ON canonical.sid=legacy.sid "
            "AND canonical.account_id=76561197960265728 + CASE WHEN legacy.account_id < 0 "
            "THEN legacy.account_id + 4294967296 ELSE legacy.account_id END "
            "WHERE legacy.account_id < 0 OR legacy.account_id BETWEEN 1 AND 4294967295;"
            "DELETE negative FROM vip_users negative JOIN vip_users positive ON positive.sid=negative.sid "
            "AND positive.account_id=negative.account_id+4294967296 WHERE negative.account_id < 0;"
            "UPDATE vip_users SET account_id=76561197960265728 + CASE WHEN account_id < 0 "
            "THEN account_id+4294967296 ELSE account_id END "
            "WHERE account_id < 0 OR account_id BETWEEN 1 AND 4294967295;"
        )
        db_count = self.run(
            "SELECT COUNT(*) FROM vip_users WHERE account_id < 0 "
            "OR account_id BETWEEN 1 AND 4294967295;"
        )
        if db_count != "0":
            raise AssertionError(f"legacy IDs remain after migration: {db_count!r}")
        if "bigint unsigned" not in column_type:
            self.run("ALTER TABLE vip_users MODIFY account_id BIGINT UNSIGNED NOT NULL;")
        self.run(
            "CREATE TABLE IF NOT EXISTS vip_schema_migrations (version VARCHAR(64) NOT NULL, "
            "checksum CHAR(64) NOT NULL, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "PRIMARY KEY(version));"
            "INSERT INTO vip_schema_migrations(version,checksum) VALUES "
            "('steamid64-v2','6799cc4b228acdff3d599a31fb9546e4cd2641c82ff6169ae0728dcc2f457167') "
            "ON DUPLICATE KEY UPDATE checksum=VALUES(checksum);"
        )


class StaticMigrationContractTests(unittest.TestCase):
    def test_plan_contains_lock_staged_schema_and_conflict_archive(self):
        for required in (
            "GET_LOCK", "RELEASE_LOCK", "vip_schema_migrations",
            "vip_users_migration_conflicts", "BIGINT SIGNED", "BIGINT UNSIGNED",
            "4294967296", "steamid64-v2", "account_id` = 0",
            "canonical_account_id`, `sid`, `reason",
        ):
            self.assertIn(required, HEADER)


def run_database_cases(args: argparse.Namespace) -> None:
    db = Database(args)
    db.run("SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE';")

    # A signed INT can contain legacy account IDs, but cannot contain a
    # SteamID64. Exercise that migration as a legacy-only install first; the
    # mixed legacy/SteamID64 case below deliberately starts as BIGINT SIGNED.
    db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
             "(42, 'legacy-positive', 3, 8, 'vip', 0),"
             "(0, 'zero', 4, 9, 'vip', 0)", "INT")
    db.migrate()
    if db.run("SELECT account_id,sid FROM vip_users ORDER BY sid;") != (
            f"{BASE + 4294967295}\t7\n{BASE + 42}\t8\n0\t9"):
        raise AssertionError("signed INT legacy rows were not normalized")
    if db.run("SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
              "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' "
              "AND COLUMN_NAME='account_id';").lower() != "bigint unsigned":
        raise AssertionError("signed INT migration did not finalize account_id")

    db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
             f"({BASE + 4294967295}, 'canonical', 2, 7, 'vip', 0),"
             "(42, 'legacy-positive', 3, 8, 'vip', 0),"
             "(0, 'zero', 4, 9, 'vip', 0)", "BIGINT SIGNED")
    db.migrate()
    rows = db.run("SELECT account_id,sid FROM vip_users ORDER BY sid;")
    expected = f"{BASE + 4294967295}\t7\n{BASE + 42}\t8\n0\t9"
    if rows != expected:
        raise AssertionError(f"unexpected migrated rows: {rows!r}")
    if db.run("SELECT COUNT(*) FROM vip_users_migration_conflicts;") != "1":
        raise AssertionError("conflicting legacy rows were not archived")
    db.migrate()
    if db.run("SELECT COUNT(*) FROM vip_users;") != "4":
        raise AssertionError("second migration changed row count")
    if db.run("SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
              "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' "
              "AND COLUMN_NAME='account_id';").lower() != "bigint unsigned":
        raise AssertionError("account_id was not finalized as BIGINT UNSIGNED")
    if db.run("SELECT COUNT(*) FROM vip_schema_migrations WHERE version='steamid64-v2' "
              "AND checksum='6799cc4b228acdff3d599a31fb9546e4cd2641c82ff6169ae0728dcc2f457167';") != "1":
        raise AssertionError("migration version was not recorded exactly once")

    # A signed BIGINT can contain both historical encodings of the same
    # UINT32 account. The positive legacy row is the deterministic winner.
    db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
             f"({BASE + 4294967295}, 'canonical', 2, 7, 'vip', 0),"
             "(-4294967254, 'negative-legacy', 6, 11, 'vip', 0),"
             f"({BASE + 42}, 'canonical-42', 7, 11, 'vip', 0),"
             "(0, 'zero', 4, 9, 'vip', 0),"
             "(9000000000000000000, 'unknown', 5, 10, 'vip', 0)", "BIGINT SIGNED")
    db.migrate()
    if db.run("SELECT account_id,name,sid FROM vip_users ORDER BY sid;") != (
            f"{BASE + 4294967295}\tcanonical\t7\n0\tzero\t9\n"
            "9000000000000000000\tunknown\t10\n"
            f"{BASE + 42}\tcanonical-42\t11"):
        raise AssertionError("positive legacy representation did not win")
    if db.run("SELECT COUNT(*) FROM vip_users_migration_conflicts;") != "2":
        raise AssertionError("legacy conflict archive was not preserved")
    if db.run("SELECT COUNT(*) FROM vip_users_migration_conflicts WHERE reason='positive-legacy-wins';") != "1":
        raise AssertionError("negative legacy conflict was not archived with its reason")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--user")
    parser.add_argument("--password")
    parser.add_argument("--database")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StaticMigrationContractTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1
    if all(getattr(args, field) is not None for field in ("host", "user", "password", "database")):
        run_database_cases(args)
        print("Database migration integration cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
