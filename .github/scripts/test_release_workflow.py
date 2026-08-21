"""Static contract tests for the Core release workflow."""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "build.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        marker = "  publish-release:\n"
        if marker not in cls.workflow:
            raise AssertionError("publish-release job is missing")
        cls.release_job = cls.workflow.split(marker, 1)[1]

    def test_push_and_pull_request_branches(self):
        self.assertIn(
            "push:\n    branches:\n      - Core\n      - dev",
            self.workflow,
        )
        self.assertIn(
            "pull_request:\n    branches:\n      - Core",
            self.workflow,
        )
        self.assertNotIn("      - main", self.workflow)
        self.assertNotIn("      - dev-core\n", self.workflow)
        self.assertNotIn("\n  release:\n", self.workflow)

    def test_release_runs_only_after_successful_pair_branch_push(self):
        self.assertIn("github.event_name == 'push'", self.release_job)
        self.assertIn("github.ref_name == 'Core'", self.release_job)
        self.assertIn("github.ref_name == 'dev'", self.release_job)
        self.assertIn("vars.RUNTIME_VALIDATION_SHA == github.sha", self.release_job)
        self.assertIn("vars.RUNTIME_VALIDATION_REPORT_URL != ''", self.release_job)
        self.assertIn("needs.build.result == 'success'", self.release_job)
        self.assertNotIn("github.event_name == 'release'", self.workflow)
        self.assertNotIn("workflow_dispatch", self.release_job)

    def test_dynamic_tag_and_branch_tip_guard(self):
        self.assertIn("RELEASE_TAG:", self.release_job)
        self.assertIn("RELEASE_TITLE:", self.release_job)
        self.assertIn("git/ref/heads/$GITHUB_REF_NAME", self.release_job)
        self.assertIn("update_release_tag.sh", self.release_job)
        self.assertNotIn('gh release delete "$RELEASE_TAG"', self.release_job)
        self.assertIn('gh release view "$RELEASE_TAG"', self.release_job)
        self.assertIn("gh release edit", self.release_job)
        self.assertIn('--target "$GITHUB_SHA"', self.release_job)
        self.assertNotIn("--cleanup-tag", self.release_job)
        self.assertIn("IS_PRERELEASE:", self.release_job)
        self.assertIn("github.ref_name == 'dev'", self.release_job)
        self.assertIn("--prerelease", self.release_job)

    def test_release_permissions_and_asset_validation(self):
        self.assertEqual(self.workflow.count("contents: write"), 1)
        self.assertEqual(self.workflow.count("id-token: write"), 1)
        self.assertEqual(self.workflow.count("attestations: write"), 1)
        self.assertIn("GH_TOKEN:", self.release_job)
        self.assertIn("github.token", self.release_job)
        self.assertIn("group: release-", self.release_job)
        self.assertIn("cancel-in-progress: false", self.release_job)
        self.assertIn("zip -T release-files/*.zip", self.release_job)
        self.assertIn("sha256sum release-files/*.zip", self.release_job)
        self.assertIn("gh release upload", self.release_job)
        self.assertIn("--clobber", self.release_job)
        self.assertIn("actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d", self.release_job)
        self.assertIn("sbom-path: release-files/vip.spdx.json", self.release_job)
        self.assertIn("gh attestation verify", self.release_job)
        self.assertIn("verify_spdx_subject.py", self.release_job)
        self.assertIn("release-files/vip.spdx.json", self.release_job)
        self.assertIn("Verify release assets", self.release_job)
        self.assertIn('actual="$(gh release view "$RELEASE_TAG"', self.release_job)
        self.assertIn("expected=$'vip.spdx.json\\nvip.zip'", self.release_job)
        self.assertIn("test_update_release_tag.py", self.workflow)

    def test_no_legacy_release_configuration(self):
        self.assertNotIn("1.0-bywinsty", self.workflow)
        self.assertNotIn("github.event.release", self.workflow)


if __name__ == "__main__":
    unittest.main()
