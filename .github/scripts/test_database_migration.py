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
import json


ROOT = Path(__file__).resolve().parents[2]
BASE = 76561197960265728


def is_unsigned_bigint(column_type: str) -> bool:
    normalized = " ".join(column_type.lower().split())
    return normalized.startswith("bigint") and "unsigned" in normalized


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
        # Every connection explicitly enables the same strict mode.  Migration
        # scenarios themselves use run_script() so the lock and all statements
        # share one persistent client session.
        session_sql = "SET SESSION sql_mode='STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE';\n"
        completed = subprocess.run(command, input=session_sql + sql, text=True, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if completed.returncode:
            raise AssertionError(f"SQL failed ({completed.returncode}): {completed.stdout}")
        return completed.stdout.strip()

    def run_script(self, statements: list[str]) -> str:
        return self.run("\n".join(statements), database=True)

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

    def migrate(self, plan: dict, stop_after: str | None = None) -> None:
        steps = {item["name"]: item["sql"] for item in plan["ordered_steps"]}
        column_type = self.run(
            "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' AND COLUMN_NAME='account_id';"
        ).lower()
        statements: list[str] = []
        names: list[str] = []
        def append(name: str) -> None:
            names.append(name)
            statements.append(steps[name])
        for name in ("acquire-lock", "create-users-table", "create-migration-history", "create-conflict-archive"):
            append(name)
        if "bigint" not in column_type:
            append("widen-signed-column")
        for name in (
            "archive-canonical-conflicts", "archive-legacy-conflicts",
            "remove-canonical-conflicts", "remove-legacy-conflicts",
            "normalize-legacy", "verify-legacy", "warn-unmapped",
        ):
            append(name)
        if not is_unsigned_bigint(column_type):
            append("finalize-unsigned-column")
        for name in ("record-version", "verify-version", "release-lock"):
            append(name)
        if stop_after is not None:
            if stop_after not in names:
                raise AssertionError(f"unknown migration fault checkpoint: {stop_after}")
            self.run_script(statements[:names.index(stop_after) + 1])
            return
        self.run_script(statements)
        db_count = self.run(
            "SELECT COUNT(*) FROM vip_users WHERE account_id < 0 "
            "OR account_id BETWEEN 1 AND 4294967295;"
        )
        if db_count != "0":
            raise AssertionError(f"legacy IDs remain after migration: {db_count!r}")


def load_plan() -> dict:
    emitter = os.environ.get("MIGRATION_PLAN_EMITTER")
    if not emitter or not Path(emitter).is_file():
        raise RuntimeError("MIGRATION_PLAN_EMITTER must point to the compiled production migration emitter")
    completed = subprocess.run([emitter], check=True, text=True, stdout=subprocess.PIPE)
    plan = json.loads(completed.stdout)
    if plan.get("migration_version") != "steamid64-v2" or not plan.get("ordered_steps"):
        raise AssertionError("migration emitter returned an invalid production plan")
    return plan


class StaticMigrationContractTests(unittest.TestCase):
    def test_plan_contains_lock_staged_schema_and_conflict_archive(self):
        try:
            plan = load_plan()
        except RuntimeError as exc:
            self.skipTest(str(exc))
        self.assertEqual(plan["migration_version"], "steamid64-v2")
        names = [item["name"] for item in plan["ordered_steps"]]
        self.assertEqual(names[0], "acquire-lock")
        self.assertEqual(names[-1], "release-lock")
        self.assertIn("verify-version", names)
        self.assertIn("SHA2", plan["lock_expression"])


def run_database_cases(args: argparse.Namespace) -> None:
    db = Database(args)
    plan = load_plan()

    # A signed INT can contain legacy account IDs, but cannot contain a
    # SteamID64. Exercise that migration as a legacy-only install first; the
    # mixed legacy/SteamID64 case below deliberately starts as BIGINT SIGNED.
    db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
             "(42, 'legacy-positive', 3, 8, 'vip', 0),"
             "(0, 'zero', 4, 9, 'vip', 0)", "INT")
    db.migrate(plan)
    if db.run("SELECT account_id,sid FROM vip_users ORDER BY sid;") != (
            f"{BASE + 4294967295}\t7\n{BASE + 42}\t8\n0\t9"):
        raise AssertionError("signed INT legacy rows were not normalized")
    first_column_type = db.run(
        "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' "
        "AND COLUMN_NAME='account_id';"
    )
    if not is_unsigned_bigint(first_column_type):
        raise AssertionError("signed INT migration did not finalize account_id")

    db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
             f"({BASE + 4294967295}, 'canonical', 2, 7, 'vip', 0),"
             "(42, 'legacy-positive', 3, 8, 'vip', 0),"
             "(0, 'zero', 4, 9, 'vip', 0)", "BIGINT SIGNED")
    db.migrate(plan)
    rows = db.run("SELECT account_id,sid FROM vip_users ORDER BY sid;")
    expected = f"{BASE + 4294967295}\t7\n{BASE + 42}\t8\n0\t9"
    if rows != expected:
        raise AssertionError(f"unexpected migrated rows: {rows!r}")
    if db.run("SELECT COUNT(*) FROM vip_users_migration_conflicts;") != "1":
        raise AssertionError("conflicting legacy rows were not archived")
    db.migrate(plan)
    if db.run("SELECT COUNT(*) FROM vip_users;") != "3":
        raise AssertionError("second migration changed row count")
    if not is_unsigned_bigint(db.run("SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
                                     "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' "
                                     "AND COLUMN_NAME='account_id';")):
        raise AssertionError("account_id was not finalized as BIGINT UNSIGNED")
    if db.run("SELECT COUNT(*) FROM vip_schema_migrations WHERE version='steamid64-v2' "
              "AND checksum='6799cc4b228acdff3d599a31fb9546e4cd2641c82ff6169ae0728dcc2f457167';") != "1":
        raise AssertionError("migration version was not recorded exactly once")

    # A signed BIGINT can contain both historical encodings of the same
    # UINT32 account. The positive legacy row is the deterministic winner.
    db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
             f"({BASE + 4294967295}, 'canonical', 2, 7, 'vip', 0),"
             "(-4294967254, 'negative-legacy', 6, 11, 'vip', 0),"
             "(42, 'positive-legacy', 7, 11, 'vip', 0),"
             "(0, 'zero', 4, 9, 'vip', 0),"
             "(9000000000000000000, 'unknown', 5, 10, 'vip', 0)", "BIGINT SIGNED")
    db.migrate(plan)
    if db.run("SELECT account_id,name,sid FROM vip_users ORDER BY sid;") != (
            f"{BASE + 4294967295}\tcanonical\t7\n0\tzero\t9\n"
            "9000000000000000000\tunknown\t10\n"
            f"{BASE + 42}\tpositive-legacy\t11"):
        raise AssertionError("positive legacy representation did not win")
    if db.run("SELECT COUNT(*) FROM vip_users_migration_conflicts;") != "2":
        raise AssertionError("legacy conflict archive was not preserved")
    if db.run("SELECT COUNT(*) FROM vip_users_migration_conflicts WHERE reason='positive-legacy-wins';") != "1":
        raise AssertionError("negative legacy conflict was not archived with its reason")

    if os.environ.get("MIGRATION_FAULT_INJECTION") == "1":
        checkpoints = [item["name"] for item in plan["ordered_steps"]
                       if item["name"] != "acquire-lock"]
        for checkpoint in checkpoints:
            db.reset("(-1, 'legacy-negative', 1, 7, 'vip', 0),"
                     "(42, 'legacy-positive', 3, 8, 'vip', 0)", "INT")
            db.migrate(plan, stop_after=checkpoint)
            db.migrate(plan)
            if not is_unsigned_bigint(db.run(
                    "SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='vip_users' "
                    "AND COLUMN_NAME='account_id';")):
                raise AssertionError(f"migration did not recover after checkpoint {checkpoint}")


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
