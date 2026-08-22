#!/usr/bin/env python3
"""Tests for runtime-validation-v3 promotion policy."""

from __future__ import annotations

import copy
import datetime as dt
import unittest

import verify_runtime_validation as verify


COMMIT = "a" * 40
ARCHIVE = "b" * 64
BINARY = "c" * 64
ORIGINAL = "d" * 64
NOW = dt.datetime(2026, 8, 22, 12, 0, tzinfo=dt.timezone.utc)


def report() -> dict:
    dependencies = [
        {
            "capability": capability,
            "status": "verified",
            "sha256": f"{index:x}" * 64,
            "actual_sha256": f"{index:x}" * 64,
        }
        for index, capability in enumerate(("metamod", "utils", "menus", "players", "sqlmm"), 1)
    ]
    return {
        "schema": verify.REPORT_SCHEMA,
        "repository": "bywinsty/cs2-vip",
        "commit": COMMIT,
        "build_run_id": "123",
        "validation_run_id": "456",
        "nonce": "e" * 32,
        "stage_id": "f" * 64,
        "generated_at": "2026-08-22T11:55:00Z",
        "completed_at": "2026-08-22T11:59:00Z",
        "result": "success",
        "artifact": {"archive_sha256": ARCHIVE, "binary_sha256": BINARY},
        "rollback": {
            "result": "success",
            "state_restored": True,
            "restored_binary_sha256": ORIGINAL,
        },
        "stages": [{"name": name, "status": "success"} for name in verify.REQUIRED_STAGES],
        "probe": {
            "nonce": "e" * 32,
            "build_commit": COMMIT,
            "ready": True,
            "interfaces": {"IVIPApi001": True, "IVIPApi002": True},
            "migration": {"status": "ready", "account_id_type": "bigint unsigned"},
        },
        "a2s": {"app_id": 730, "version": "1.40.8.2"},
        "cs2_build": "1.40.8.2",
        "dependencies": dependencies,
    }


def expected() -> dict:
    return {
        "expected_commit": COMMIT,
        "expected_build_run_id": "123",
        "archive_sha256": ARCHIVE,
        "binary_sha256": BINARY,
        "max_age_hours": 24,
        "now": NOW,
    }


class RuntimeValidationPolicyTests(unittest.TestCase):
    def test_valid_report_and_attestation(self):
        predicate = report()
        self.assertEqual(verify.verify_report(predicate, **expected()), predicate)
        attestation = [{
            "verificationResult": {
                "statement": {
                    "predicateType": verify.PREDICATE_TYPE,
                    "subject": [{"name": "validated/vip.zip", "digest": {"sha256": ARCHIVE}}],
                    "predicate": predicate,
                }
            }
        }]
        self.assertEqual(verify.verify_attestation(attestation, **expected()), predicate)

    def test_stale_mismatched_or_failed_report_is_rejected(self):
        stale = report()
        stale["completed_at"] = "2026-08-21T11:00:00Z"
        with self.assertRaisesRegex(verify.VerificationError, "stale"):
            verify.verify_report(stale, **expected())
        for path, value in (
            (("commit",), "0" * 40),
            (("artifact", "archive_sha256"), "0" * 64),
            (("rollback", "result"), "failure"),
            (("probe", "ready"), False),
        ):
            invalid = copy.deepcopy(report())
            target = invalid
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(verify.VerificationError):
                verify.verify_report(invalid, **expected())

    def test_missing_stage_or_dependency_is_rejected(self):
        invalid = report()
        invalid["stages"] = invalid["stages"][1:]
        with self.assertRaisesRegex(verify.VerificationError, "stages"):
            verify.verify_report(invalid, **expected())
        invalid = report()
        invalid["dependencies"] = invalid["dependencies"][:-1]
        with self.assertRaisesRegex(verify.VerificationError, "dependencies"):
            verify.verify_report(invalid, **expected())

    def test_attestation_subject_and_predicate_are_exact(self):
        entry = {
            "verificationResult": {
                "statement": {
                    "predicateType": "https://example.invalid/type",
                    "subject": [{"name": "validated/vip.zip", "digest": {"sha256": ARCHIVE}}],
                    "predicate": report(),
                }
            }
        }
        with self.assertRaises(verify.VerificationError):
            verify.verify_attestation([entry], **expected())
        entry["verificationResult"]["statement"]["predicateType"] = verify.PREDICATE_TYPE
        entry["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
        with self.assertRaises(verify.VerificationError):
            verify.verify_attestation([entry], **expected())


if __name__ == "__main__":
    unittest.main()
