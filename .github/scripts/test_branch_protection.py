#!/usr/bin/env python3
"""Contract tests for PR checks and the canonical branch-protection policy."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "configure_branch_protection.py"
POLICY = ROOT / ".github" / "branch-protection.json"


def load_module():
    spec = importlib.util.spec_from_file_location("configure_branch_protection", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load configure_branch_protection.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load_module()


class BranchProtectionTests(unittest.TestCase):
    def test_policy_and_dry_run_payload(self) -> None:
        policy = MODULE.load_policy(POLICY)
        self.assertEqual(policy["branches"], ["Core", "PR", "dev"])
        payload = MODULE.api_payload(policy)
        self.assertTrue(payload["required_status_checks"]["strict"])
        self.assertTrue(payload["enforce_admins"])
        self.assertTrue(
            payload["required_pull_request_reviews"]["dismiss_stale_reviews"]
        )
        self.assertTrue(
            payload["required_pull_request_reviews"]["require_last_push_approval"]
        )
        self.assertFalse(payload["allow_force_pushes"])
        self.assertFalse(payload["allow_deletions"])

        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--policy", str(POLICY)],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        rendered = json.loads(result.stdout)
        self.assertEqual(rendered["payload"], payload)

    def test_policy_rejects_missing_unknown_and_misconfigured_fields(self) -> None:
        original = json.loads(POLICY.read_text(encoding="utf-8"))
        mutations = []

        missing_branch = dict(original)
        missing_branch["branches"] = ["Core", "PR"]
        mutations.append(missing_branch)

        missing = dict(original)
        missing["required_status_checks"] = missing["required_status_checks"][:-1]
        mutations.append(missing)

        unknown = dict(original)
        unknown["required_status_checks"] = [
            *unknown["required_status_checks"],
            "Unknown check",
        ]
        mutations.append(unknown)

        bypass = dict(original)
        bypass["enforce_admins"] = False
        mutations.append(bypass)

        stale = dict(original)
        stale["dismiss_stale_reviews"] = False
        mutations.append(stale)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temp_dir:
                    path = Path(temp_dir) / "policy.json"
                    path.write_text(json.dumps(mutation), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        MODULE.load_policy(path)

    def test_workflows_expose_every_required_context_on_all_three_pr_targets(self) -> None:
        workflows = [
            ROOT / ".github" / "workflows" / "build.yml",
            ROOT / ".github" / "workflows" / "quality-gates.yml",
            ROOT / ".github" / "workflows" / "database-migration.yml",
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in workflows)
        policy = MODULE.load_policy(POLICY)

        for path in workflows:
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                "pull_request:\n    branches:\n      - Core\n      - PR\n      - dev",
                text,
                path.name,
            )
            self.assertNotIn("pull_request_target:", text, path.name)
            self.assertNotIn("[skip ci]", text.lower(), path.name)

        for context in policy["required_status_checks"]:
            self.assertIn(context, combined, context)

        quality = workflows[1].read_text(encoding="utf-8")
        self.assertIn('"$RUNNER_TEMP/database-migration-test"', quality)
        self.assertNotIn("-o database-migration-test", quality)


if __name__ == "__main__":
    unittest.main()
