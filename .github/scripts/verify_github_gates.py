#!/usr/bin/env python3
"""Read-only verification of the GitHub gates required for Core promotion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / ".github" / "branch-protection.json"
ENVIRONMENT = "cshost-runtime-test"


class GateError(RuntimeError):
    pass


def gh_json(repository: str, endpoint: str) -> dict:
    completed = subprocess.run(
        ["gh", "api", f"repos/{repository}/{endpoint}"],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode:
        raise GateError(f"GitHub API failed for {endpoint}: {completed.stdout.strip()}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"GitHub API returned invalid JSON for {endpoint}") from exc
    if not isinstance(value, dict):
        raise GateError(f"GitHub API returned a non-object for {endpoint}")
    return value


def verify_branch(repository: str, branch: str, policy: dict) -> None:
    protection = gh_json(repository, f"branches/{branch}/protection")
    required = protection.get("required_status_checks") or {}
    contexts = set(required.get("contexts") or [])
    if not required.get("strict") or contexts != set(policy["required_status_checks"]):
        raise GateError(f"{branch}: required status checks do not match policy")
    if not (protection.get("enforce_admins") or {}).get("enabled"):
        raise GateError(f"{branch}: administrators can bypass protection")
    reviews = protection.get("required_pull_request_reviews") or {}
    for key, expected in (
        ("dismiss_stale_reviews", True),
        ("require_last_push_approval", True),
    ):
        if reviews.get(key) is not expected:
            raise GateError(f"{branch}: review setting {key} is not enabled")
    if reviews.get("required_approving_review_count") != policy["required_approving_review_count"]:
        raise GateError(f"{branch}: approval count is not {policy['required_approving_review_count']}")
    if not (protection.get("required_conversation_resolution") or {}).get("enabled"):
        raise GateError(f"{branch}: conversation resolution is not required")
    if (protection.get("allow_force_pushes") or {}).get("enabled"):
        raise GateError(f"{branch}: force pushes are allowed")
    if (protection.get("allow_deletions") or {}).get("enabled"):
        raise GateError(f"{branch}: deletions are allowed")


def verify_environment(repository: str) -> None:
    environment = gh_json(repository, f"environments/{ENVIRONMENT}")
    if environment.get("can_admins_bypass") is not False:
        raise GateError("runtime environment permits administrator bypass")
    rules = [rule for rule in environment.get("protection_rules", [])
             if isinstance(rule, dict) and rule.get("type") == "required_reviewers"]
    if len(rules) != 1:
        raise GateError("runtime environment must have exactly one required-reviewer rule")
    rule = rules[0]
    if rule.get("prevent_self_review") is not True or not rule.get("reviewers"):
        raise GateError("runtime environment reviewer policy is incomplete")


def verify(repository: str, policy_path: Path = POLICY) -> None:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    for branch in policy["branches"]:
        verify_branch(repository, branch, policy)
    verify_environment(repository)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default="bywinsty/cs2-vip")
    parser.add_argument("--policy", type=Path, default=POLICY)
    args = parser.parse_args()
    try:
        verify(args.repository, args.policy)
    except (OSError, json.JSONDecodeError, GateError) as exc:
        raise SystemExit(f"GitHub gate verification failed: {exc}") from exc
    print(f"GitHub branch protection and {ENVIRONMENT} verified for {args.repository}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
