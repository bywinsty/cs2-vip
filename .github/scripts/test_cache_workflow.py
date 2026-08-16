"""Static contract tests for dependency cache behavior in build.yml."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

SDK_REFS = ("AMBUILD_REF", "MMS_REF", "HL2SDK_REF", "SCHEMAENTITY_REF", "MANIFEST_REF")


def sdk_cache_key(refs: dict[str, str], version: str = "v1") -> str:
    return "-".join(
        [
            version,
            "Linux",
            "ubuntu24.04",
            *(refs[name] for name in SDK_REFS),
        ]
    )


def pip_cache_key(workflow: str, version: str = "v1") -> str:
    workflow_hash = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
    return f"pip-{version}-ubuntu24.04-py312-{workflow_hash}"


def cache_match_type(value: str | None) -> str:
    if value == "true":
        return "exact"
    if value == "false":
        return "partial"
    return "miss"


class CacheWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_cache_actions_are_split_between_restore_and_save(self):
        self.assertEqual(self.workflow.count("uses: actions/cache/restore@"), 4)
        self.assertEqual(self.workflow.count("uses: actions/cache/save@"), 2)
        self.assertNotIn("uses: actions/cache@", self.workflow)

    def test_sdk_key_contains_all_pinned_dependency_refs(self):
        key_lines = [
            line for line in self.workflow.splitlines() if line.strip().startswith("key:")
        ]
        sdk_lines = [line for line in key_lines if "MANIFEST_REF" in line]
        self.assertEqual(len(sdk_lines), 3)
        for name in SDK_REFS:
            self.assertTrue(all(name in line for line in sdk_lines), name)

    def test_sdk_key_changes_when_any_pinned_ref_changes(self):
        refs = {name: name.lower() for name in SDK_REFS}
        original = sdk_cache_key(refs)
        changed = dict(refs)
        changed["HL2SDK_REF"] = "changed-ref"
        self.assertNotEqual(original, sdk_cache_key(changed))

    def test_pip_key_changes_when_workflow_content_changes(self):
        original = pip_cache_key(self.workflow)
        changed = pip_cache_key(self.workflow + "\n# cache contract change\n")
        self.assertNotEqual(original, changed)
        self.assertIn("hashFiles('.github/workflows/build.yml')", self.workflow)

    def test_restore_status_contract_distinguishes_exact_partial_and_miss(self):
        self.assertEqual(cache_match_type("true"), "exact")
        self.assertEqual(cache_match_type("false"), "partial")
        self.assertEqual(cache_match_type(""), "miss")
        self.assertEqual(self.workflow.count("$(cache_match_type"), 4)
        self.assertIn("cache-matched-key", self.workflow)
        self.assertIn("cache-primary-key", self.workflow)

    def test_restore_and_save_failures_are_observable(self):
        self.assertGreaterEqual(self.workflow.count("continue-on-error: true"), 6)
        self.assertIn("steps.restore-dependencies.outcome", self.workflow)
        self.assertIn("steps.restore-pip.outcome", self.workflow)
        self.assertIn("steps.save-dependencies.outcome", self.workflow)
        self.assertIn("steps.save-pip.outcome", self.workflow)
        self.assertIn("CACHE_RESTORE_STARTED_AT", self.workflow)
        self.assertIn("CACHE_RESTORE_FINISHED_AT", self.workflow)
        self.assertIn("Restore window (SDK + pip)", self.workflow)

    def test_pull_requests_never_save_dependency_caches(self):
        save_blocks = re.findall(
            r"      - name: Save .*?\n(?P<body>.*?)(?=\n      - name:|\n  build-module:)",
            self.workflow,
            flags=re.DOTALL,
        )
        self.assertEqual(len(save_blocks), 2)
        for block in save_blocks:
            self.assertIn("github.event_name != 'pull_request'", block)
            self.assertIn("continue-on-error: true", block)

        self.assertIn("if [[ \"$DEPENDENCY_CACHE_HIT\" != \"true\" ]]", self.workflow)
        self.assertIn("Cache writes from pull requests: disabled", self.workflow)

    def test_fallback_is_kept_when_sdk_restore_misses(self):
        self.assertIn("if [[ \"$DEPENDENCY_CACHE_HIT\" != \"true\" ]]", self.workflow)
        self.assertIn('echo "fallback-used=true" >> "$GITHUB_OUTPUT"', self.workflow)
        self.assertIn('echo "fallback-used=false" >> "$GITHUB_OUTPUT"', self.workflow)
        self.assertIn("Fallback clone used:", self.workflow)

    def test_summary_uses_shell_variables_instead_of_escaped_literals(self):
        self.assertNotIn(r"\${DEPENDENCY_CACHE_HIT", self.workflow)
        self.assertNotIn(r"\${PIP_CACHE_HIT", self.workflow)
        self.assertNotIn(r"\${FALLBACK_USED", self.workflow)
        self.assertIn("SDK matched key:", self.workflow)
        self.assertIn("pip matched key:", self.workflow)


if __name__ == "__main__":
    unittest.main()
