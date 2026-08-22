#!/usr/bin/env python3
"""Validate and optionally apply canonical Core/PR/dev branch protections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


EXPECTED_BRANCHES = ["Core", "PR", "dev"]
EXPECTED_CHECKS = [
    "Build VIP Core",
    "Unit and contract tests",
    "Compile migration helper contract",
    "MariaDB 10.3.38",
    "MariaDB 10.11.18",
    "MySQL 8.4.8",
]


def load_policy(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("branch protection schema_version must be 1")
    expected_fields = {
        "schema_version", "branches", "required_status_checks", "strict",
        "enforce_admins", "required_approving_review_count", "dismiss_stale_reviews",
        "require_last_push_approval", "required_conversation_resolution",
        "allow_force_pushes", "allow_deletions",
    }
    unknown_fields = set(value) - expected_fields
    if unknown_fields:
        raise ValueError(f"branch protection has unknown fields: {sorted(unknown_fields)}")
    if value.get("branches") != EXPECTED_BRANCHES:
        raise ValueError("branch protection must target exactly Core, PR and dev")
    if value.get("required_status_checks") != EXPECTED_CHECKS:
        raise ValueError("branch protection required checks do not match the canonical policy")
    exact_booleans = {
        "strict": True,
        "enforce_admins": True,
        "dismiss_stale_reviews": True,
        "require_last_push_approval": True,
        "required_conversation_resolution": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
    }
    for field, expected in exact_booleans.items():
        if value.get(field) is not expected:
            raise ValueError(f"branch protection {field} must be {str(expected).lower()}")
    if value.get("required_approving_review_count") != 1:
        raise ValueError("branch protection must require exactly one approval")
    return value


def api_payload(policy: dict) -> dict:
    return {
        "required_status_checks": {
            "strict": policy["strict"],
            "contexts": policy["required_status_checks"],
        },
        "enforce_admins": policy["enforce_admins"],
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": policy["dismiss_stale_reviews"],
            "require_code_owner_reviews": False,
            "required_approving_review_count": policy["required_approving_review_count"],
            "require_last_push_approval": policy["require_last_push_approval"],
        },
        "restrictions": None,
        "required_conversation_resolution": policy["required_conversation_resolution"],
        "allow_force_pushes": policy["allow_force_pushes"],
        "allow_deletions": policy["allow_deletions"],
        "required_linear_history": False,
        "block_creations": False,
        "lock_branch": False,
        "allow_fork_syncing": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=Path(".github/branch-protection.json"))
    parser.add_argument("--repository", default="bywinsty/cs2-vip")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise SystemExit("repository must use owner/name syntax")
    try:
        policy = load_policy(args.policy)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"branch protection policy rejected: {exc}") from exc
    payload = api_payload(policy)
    if not args.apply:
        print(json.dumps({"repository": args.repository, "branches": policy["branches"], "payload": payload}, indent=2))
        return 0
    encoded = json.dumps(payload)
    for branch in policy["branches"]:
        subprocess.run(
            ["gh", "api", "--method", "PUT",
             f"repos/{args.repository}/branches/{branch}/protection", "--input", "-"],
            input=encoded,
            text=True,
            check=True,
        )
        print(f"Applied branch protection: {args.repository}:{branch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
