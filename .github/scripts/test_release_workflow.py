"""Static contracts for candidate attestation and release promotion workflows."""

from pathlib import Path
import unittest


WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = (WORKFLOWS / "build.yml").read_text(encoding="utf-8")
        cls.preflight = (WORKFLOWS / "runtime-release-preflight.yml").read_text(encoding="utf-8")
        cls.promotion = (WORKFLOWS / "promote-core-release.yml").read_text(encoding="utf-8")
        cls.cshost = (WORKFLOWS / "cshost-runtime-validation.yml").read_text(encoding="utf-8")
        cls.publish = cls.build.split("  publish-release:\n", 1)[1]
        cls.candidate = cls.build.split("  attest-candidate:\n", 1)[1].split("  publish-release:\n", 1)[0]

    def test_pr_core_and_dev_push_contract(self):
        self.assertIn("      - Core\n      - PR\n      - dev", self.build)
        self.assertIn("pull_request:\n    branches:\n      - Core\n      - PR\n      - dev", self.build)
        self.assertNotIn("pull_request_target", self.build)
        self.assertIn("github.ref_name == 'PR' || github.ref_name == 'Core'", self.candidate)
        self.assertNotIn("github.ref_name == 'dev'", self.candidate)

    def test_candidates_receive_three_attestations_with_minimal_permissions(self):
        self.assertIn("contents: read\n      id-token: write\n      attestations: write", self.candidate)
        self.assertEqual(self.candidate.count("uses: actions/attest@"), 3)
        self.assertIn("subject-path: candidate/vip.zip", self.candidate)
        self.assertIn("sbom-path: candidate/vip.spdx.json", self.candidate)
        self.assertIn("subject-path: candidate/vip.spdx.json", self.candidate)
        self.assertIn("exact candidate subjects", self.candidate.lower())

    def test_automatic_publication_is_dev_only(self):
        self.assertIn("github.ref_name == 'dev'", self.publish)
        self.assertNotIn("github.ref_name == 'Core'", self.publish)
        self.assertNotIn("RUNTIME_VALIDATION_SHA", self.publish)
        self.assertIn('IS_PRERELEASE: "true"', self.publish)
        self.assertIn("gh release upload", self.publish)
        self.assertIn("gh release download", self.publish)
        self.assertIn("cmp \"release-files/$name\"", self.publish)

    def test_every_verification_triplet_uses_explicit_spdx_predicate(self):
        for workflow in (self.build, self.preflight, self.promotion):
            with self.subTest(workflow=workflow[:40]):
                self.assertIn("--predicate-type https://spdx.dev/Document/v2.3", workflow)
                self.assertIn("vip.spdx.json", workflow)

    def test_runtime_preflight_tag_is_a_closed_choice(self):
        self.assertIn("type: choice", self.preflight)
        self.assertIn("options:\n          - dev\n          - Core", self.preflight)

    def test_stable_promotion_requires_exact_core_run_and_runtime_evidence(self):
        for text in (
            "build_run_id",
            "github.ref_name == 'Core'",
            "headBranch",
            "headSha",
            "event",
            "conclusion",
            'workflowName\' <<<"$run_json")" = "Build AMBuild Plugin"',
            "gh run download",
            "--name compile",
            "update_release_tag.sh",
            "gh release download",
            "runtime-validation/v3",
            "--signer-workflow bywinsty/cs2-vip/.github/workflows/cshost-runtime-validation.yml",
            "--source-ref refs/heads/Core",
            '--source-digest "$GITHUB_SHA"',
            '--signer-digest "$GITHUB_SHA"',
            "--format json",
            "verify_runtime_validation.py",
            "--max-age-hours 24",
        ):
            self.assertIn(text, self.promotion)
        self.assertNotIn("RUNTIME_VALIDATION_SHA", self.promotion)
        self.assertNotIn("RUNTIME_VALIDATION_REPORT_URL", self.promotion)
        self.assertNotIn("pull_request", self.promotion)
        self.assertNotIn("actions/attest@", self.promotion)

    def test_cshost_validation_and_attestation_are_separated(self):
        validation = self.cshost.split("  validation:\n", 1)[1].split("  attestation:\n", 1)[0]
        attestation = self.cshost.split("  attestation:\n", 1)[1]
        self.assertIn("environment: cshost-runtime-test", validation)
        self.assertIn("actions: read\n      contents: read", validation)
        self.assertNotIn("id-token: write", validation)
        self.assertNotIn("attestations: write", validation)
        self.assertIn("CSHOST_API_TOKEN", validation)
        self.assertIn("CSHOST_FTP_PASSWORD", validation)
        self.assertIn("id-token: write", attestation)
        self.assertIn("attestations: write", attestation)
        self.assertNotIn("CSHOST_API_TOKEN", attestation)
        self.assertNotIn("CSHOST_FTP_PASSWORD", attestation)
        self.assertIn("predicate-path: validated/runtime-validation-v3.json", attestation)
        self.assertIn("predicate-type: https://github.com/bywinsty/cs2-vip/runtime-validation/v3", attestation)

    def test_cshost_workflow_is_manual_core_only_and_supports_recovery(self):
        self.assertIn("workflow_dispatch:", self.cshost)
        self.assertNotIn("pull_request:", self.cshost)
        self.assertNotIn("push:\n", self.cshost)
        self.assertIn("github.ref_name == 'Core'", self.cshost)
        self.assertIn("restore-only", self.cshost)
        self.assertIn("cancel-in-progress: false", self.cshost)
        self.assertIn("CSHOST_SENTINEL_SHA256", self.cshost)
        self.assertIn(".can_admins_bypass", self.cshost)
        self.assertIn("required_reviewers", self.cshost)
        self.assertIn(".prevent_self_review", self.cshost)

    def test_release_assets_are_redownloaded_and_byte_compared(self):
        for workflow in (self.publish, self.promotion):
            with self.subTest(workflow=workflow[:40]):
                self.assertIn("mktemp -d", workflow)
                self.assertIn("stat -c '%s'", workflow)
                self.assertIn("sha256sum", workflow)
                self.assertIn("cmp ", workflow)
                self.assertIn("verify_spdx_subject.py", workflow)


if __name__ == "__main__":
    unittest.main()
