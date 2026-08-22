#!/usr/bin/env python3
"""Verify runtime-validation-v3 reports and GitHub CLI attestation JSON."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path, PurePosixPath
import re


REPORT_SCHEMA = "https://github.com/bywinsty/cs2-vip/runtime-validation/v3"
PREDICATE_TYPE = REPORT_SCHEMA
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
REQUIRED_STAGES = frozenset({
    "sentinel", "players-preflight", "players-before-overlay", "dependencies", "journal", "stop-original",
    "backup-original", "install-candidate", "start-candidate", "a2s", "runtime-probe", "rollback",
})
REQUIRED_CAPABILITIES = frozenset({"metamod", "utils", "menus", "players", "sqlmm"})


class VerificationError(ValueError):
    pass


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load JSON from {path}: {exc}") from exc


def parse_timestamp(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationError(f"{field} must be a UTC RFC3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise VerificationError(f"{field} is invalid") from exc
    return parsed


def require_sha(value: object, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise VerificationError(f"{field} has an invalid digest")
    return value


def verify_report(
    report: object, *, expected_commit: str, expected_build_run_id: str,
    archive_sha256: str, binary_sha256: str, max_age_hours: int,
    now: dt.datetime | None = None,
) -> dict:
    if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
        raise VerificationError("runtime report schema is not v3")
    if report.get("repository") != "bywinsty/cs2-vip":
        raise VerificationError("runtime report repository mismatch")
    if report.get("commit") != expected_commit or str(report.get("build_run_id")) != expected_build_run_id:
        raise VerificationError("runtime report commit or build run mismatch")
    if not str(report.get("validation_run_id", "")).isdigit():
        raise VerificationError("runtime report validation run ID is missing")
    if report.get("result") != "success":
        raise VerificationError("runtime report result is not success")
    artifact = report.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("archive_sha256") != archive_sha256:
        raise VerificationError("runtime report archive SHA-256 mismatch")
    if artifact.get("binary_sha256") != binary_sha256:
        raise VerificationError("runtime report binary SHA-256 mismatch")
    if not isinstance(report.get("stage_id"), str) or not SHA256_RE.fullmatch(report["stage_id"]):
        raise VerificationError("runtime report stage identifier is not anonymized")
    rollback = report.get("rollback")
    if not isinstance(rollback, dict) or rollback.get("result") != "success":
        raise VerificationError("runtime rollback result is not success")
    if rollback.get("state_restored") is not True or rollback.get("restored_binary_sha256") is None:
        raise VerificationError("runtime rollback did not prove restored state and binary")
    require_sha(rollback["restored_binary_sha256"], "rollback.restored_binary_sha256", SHA256_RE)

    stages = report.get("stages")
    if not isinstance(stages, list):
        raise VerificationError("runtime stages are missing")
    successful = {stage.get("name") for stage in stages if isinstance(stage, dict) and stage.get("status") == "success"}
    missing_stages = REQUIRED_STAGES - successful
    if missing_stages:
        raise VerificationError(f"runtime report is missing successful stages: {sorted(missing_stages)}")

    probe = report.get("probe")
    if not isinstance(probe, dict) or probe.get("build_commit") != expected_commit or probe.get("ready") is not True:
        raise VerificationError("runtime probe did not prove the candidate commit and readiness")
    if not isinstance(report.get("nonce"), str) or not NONCE_RE.fullmatch(report["nonce"]):
        raise VerificationError("runtime report nonce is invalid")
    if probe.get("nonce") != report["nonce"]:
        raise VerificationError("runtime probe nonce is not bound to the report")
    interfaces = probe.get("interfaces")
    if not isinstance(interfaces, dict) or interfaces.get("IVIPApi001") is not True or interfaces.get("IVIPApi002") is not True:
        raise VerificationError("runtime probe did not prove both VIP ABI factories")
    migration = probe.get("migration")
    if not isinstance(migration, dict) or migration.get("status") != "ready":
        raise VerificationError("runtime probe migration status is not ready")
    if migration.get("account_id_type") != "bigint unsigned":
        raise VerificationError("runtime probe account_id type is not BIGINT UNSIGNED")

    a2s = report.get("a2s")
    if not isinstance(a2s, dict) or a2s.get("app_id") != 730 or not report.get("cs2_build"):
        raise VerificationError("runtime report has no valid CS2 A2S evidence")
    if a2s.get("version") != report.get("cs2_build"):
        raise VerificationError("runtime report CS2 build does not match A2S")
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        raise VerificationError("runtime dependency evidence is missing")
    verified_capabilities = {
        item.get("capability") for item in dependencies
        if isinstance(item, dict) and item.get("status") == "verified"
        and item.get("actual_sha256") == item.get("sha256")
    }
    missing_dependencies = REQUIRED_CAPABILITIES - verified_capabilities
    if missing_dependencies:
        raise VerificationError(f"runtime dependencies are not verified: {sorted(missing_dependencies)}")

    current = now or dt.datetime.now(tz=dt.timezone.utc)
    completed = parse_timestamp(report.get("completed_at"), "completed_at")
    if completed > current + dt.timedelta(minutes=5):
        raise VerificationError("runtime report timestamp is in the future")
    if current - completed > dt.timedelta(hours=max_age_hours):
        raise VerificationError("runtime report is stale")
    return report


def _attestation_entries(value: object) -> list[dict]:
    if isinstance(value, list):
        entries = value
    elif isinstance(value, dict) and isinstance(value.get("attestations"), list):
        entries = value["attestations"]
    else:
        raise VerificationError("GitHub CLI attestation output is not an array")
    if not all(isinstance(entry, dict) for entry in entries):
        raise VerificationError("GitHub CLI attestation output contains a non-object entry")
    return entries


def verify_attestation(value: object, **expected: object) -> dict:
    valid: list[dict] = []
    errors: list[str] = []
    archive_sha256 = str(expected["archive_sha256"])
    for entry in _attestation_entries(value):
        verification = entry.get("verificationResult")
        statement = verification.get("statement") if isinstance(verification, dict) else None
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE_TYPE:
            errors.append("predicate type mismatch")
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1:
            errors.append("attestation must have exactly one subject")
            continue
        subject_name = subjects[0].get("name") if isinstance(subjects[0], dict) else None
        if not isinstance(subject_name, str) or "\\" in subject_name or PurePosixPath(subject_name).name != "vip.zip":
            errors.append("attestation subject name mismatch")
            continue
        digest = subjects[0].get("digest") if isinstance(subjects[0], dict) else None
        if not isinstance(digest, dict) or digest.get("sha256") != archive_sha256:
            errors.append("attestation subject digest mismatch")
            continue
        try:
            valid.append(verify_report(statement.get("predicate"), **expected))
        except VerificationError as exc:
            errors.append(str(exc))
    if len(valid) != 1:
        raise VerificationError(f"expected exactly one valid runtime attestation, got {len(valid)}: {errors}")
    return valid[0]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", type=Path)
    source.add_argument("--attestation-json", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-build-run-id", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--max-age-hours", type=int, default=24)
    parser.add_argument("--output-predicate", type=Path)
    args = parser.parse_args()
    require_sha(args.expected_commit, "expected commit", COMMIT_RE)
    if not args.expected_build_run_id.isdigit():
        parser.error("--expected-build-run-id must be numeric")
    require_sha(args.archive_sha256, "archive SHA-256", SHA256_RE)
    require_sha(args.binary_sha256, "binary SHA-256", SHA256_RE)
    if not 1 <= args.max_age_hours <= 24:
        parser.error("--max-age-hours must be between 1 and 24")
    return args


def main() -> int:
    args = parse_args()
    expected = {
        "expected_commit": args.expected_commit,
        "expected_build_run_id": args.expected_build_run_id,
        "archive_sha256": args.archive_sha256,
        "binary_sha256": args.binary_sha256,
        "max_age_hours": args.max_age_hours,
    }
    source = load_json(args.report or args.attestation_json)
    report = verify_report(source, **expected) if args.report else verify_attestation(source, **expected)
    if args.output_predicate:
        args.output_predicate.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("runtime validation evidence verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
