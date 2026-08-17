"""Static contract tests for the automated GitHub Release workflow."""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "build.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        marker = "  create-release:\n"
        if marker not in cls.workflow:
            raise AssertionError("create-release job is missing")
        cls.release_job = cls.workflow.split(marker, 1)[1]

    def test_push_and_pull_request_branches(self):
        self.assertIn(
            "push:\n    branches:\n      - Modules\n      - dev-modules",
            self.workflow,
        )
        self.assertIn(
            "pull_request:\n    branches:\n      - Modules",
            self.workflow,
        )
        self.assertNotIn("      - main", self.workflow)
        self.assertNotIn("      - PR", self.workflow)
        self.assertNotIn("      - dev\n", self.workflow)

    def test_release_runs_only_after_successful_pair_branch_push(self):
        self.assertIn("needs: [discover, build-summary]", self.release_job)
        self.assertIn("github.event_name == 'push'", self.release_job)
        self.assertIn("github.ref_name == 'Modules'", self.release_job)
        self.assertIn("github.ref_name == 'dev-modules'", self.release_job)
        self.assertIn("needs.discover.result == 'success'", self.release_job)
        self.assertIn("needs.build-summary.result == 'success'", self.release_job)
        self.assertNotIn("github.event_name == 'pull_request'", self.release_job)
        self.assertNotIn("refs/heads/main", self.release_job)
        self.assertNotIn("workflow_dispatch", self.release_job)

    def test_release_permissions_and_serialization(self):
        self.assertEqual(self.workflow.count("contents: write"), 1)
        self.assertIn("permissions:\n      contents: write", self.release_job)
        self.assertIn("GH_TOKEN:", self.release_job)
        self.assertIn("github.token", self.release_job)
        self.assertIn("concurrency:", self.release_job)
        self.assertIn("group: release-", self.release_job)
        self.assertIn("github.ref_name", self.release_job)
        self.assertIn("cancel-in-progress: false", self.release_job)

    def test_tag_release_and_branch_tip_guard(self):
        self.assertIn("RELEASE_TAG:", self.release_job)
        self.assertIn("RELEASE_TITLE:", self.release_job)
        self.assertIn("git/ref/heads/$GITHUB_REF_NAME", self.release_job)
        self.assertIn("update_release_tag.sh", self.release_job)
        self.assertIn('gh release delete "$RELEASE_TAG"', self.release_job)
        self.assertNotIn('--target "$GITHUB_SHA"', self.release_job)
        self.assertNotIn("--cleanup-tag", self.release_job)
        self.assertIn("gh release create", self.release_job)
        self.assertIn("test_update_release_tag.py", self.workflow)
        self.assertIn("--draft", self.release_job)
        self.assertIn("gh release edit", self.release_job)
        self.assertIn("--draft=false", self.release_job)
        self.assertIn("IS_PRERELEASE:", self.release_job)
        self.assertIn("dev-modules", self.release_job)
        self.assertIn("--prerelease", self.release_job)
        self.assertNotIn("1.0-bywinsty", self.workflow)

    def test_release_notes_follow_current_commit(self):
        self.assertIn("Automated release from $RELEASE_TAG.", self.release_job)
        self.assertIn("$GITHUB_SHA", self.release_job)
        self.assertIn("$GITHUB_RUN_ID", self.release_job)

    def test_release_contains_exact_expected_assets(self):
        self.assertIn("actions/download-artifact@", self.release_job)
        self.assertIn("pattern: VIP_*.tar.gz", self.release_job)
        self.assertIn('expected.add("VIP_All_Modules.tar.gz")', self.release_job)
        self.assertIn('expected.add("VIP_Modules.tar.gz")', self.release_job)
        self.assertIn("if len(actual) != 37", self.release_job)
        self.assertIn("35 module archives and both combined archive names", self.release_job)
        self.assertIn("gh release upload", self.release_job)
        self.assertIn("--clobber", self.release_job)
        self.assertIn("Verify release assets", self.release_job)
        self.assertIn('test "${#actual[@]}" -eq 37', self.release_job)

    def test_combined_archive_contains_nested_modules_archive(self):
        package_job = self.workflow.split("  package-release:", 1)[1].split("  build-summary:", 1)[0]
        self.assertIn(
            'tar -czf "$GITHUB_WORKSPACE/release/Modules.tar.gz" VIP_*.tar.gz',
            package_job,
        )
        self.assertIn("cp release/Modules.tar.gz combined-root/Modules.tar.gz", package_job)
        self.assertIn(
            "tar -czf release/VIP_All_Modules.tar.gz -C combined-root addons Modules.tar.gz",
            package_job,
        )
        self.assertIn("expected_module_archives", package_job)
        self.assertIn(
            'validate_members(modules_archive, expected_module_archives, set(), "Modules.tar.gz")',
            package_job,
        )
        self.assertNotIn("path: release/Modules.tar.gz", package_job)

    def test_nested_modules_archive_is_excluded_from_release_checksums(self):
        package_job = self.workflow.split("  package-release:", 1)[1].split("  build-summary:", 1)[0]
        self.assertIn("-name 'VIP_*.tar.gz'", package_job)
        self.assertIn('printf "%s\\n" VIP_*.tar.gz', package_job)
        self.assertIn('release.glob("VIP_*.tar.gz")', package_job)
        self.assertIn('VIP_Modules.tar.gz', package_job)
        self.assertIn('VIP_All_Modules.tar.gz', package_job)
        self.assertIn('cmp --silent release/VIP_All_Modules.tar.gz release/VIP_Modules.tar.gz', package_job)
        self.assertNotIn("find release -maxdepth 1 -type f -name '*.tar.gz'", package_job)
        self.assertNotIn('release.glob("*.tar.gz")', package_job)

    def test_build_info_is_never_published(self):
        self.assertIn("Modules_Build_Info.zip", self.release_job)
        self.assertNotIn(
            'gh release upload "$RELEASE_TAG" "release-assets/Modules_Build_Info.zip"',
            self.release_job,
        )
        self.assertNotIn("Source code", self.release_job)

    def test_legacy_combined_archive_is_uploaded(self):
        self.assertIn("path: release/VIP_All_Modules.tar.gz", self.workflow)
        self.assertIn("path: release/VIP_Modules.tar.gz", self.workflow)


if __name__ == "__main__":
    unittest.main()
