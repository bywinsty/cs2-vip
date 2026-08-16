#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check_vip_multitest_upgrade.py")


class MultiTestUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, root=None):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(root or self.root)],
            capture_output=True,
            text=True,
        )
        return result

    def touch(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("placeholder", encoding="utf-8")

    def test_empty_installation_passes(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0)

    def test_legacy_vip_test_requires_manual_migration(self):
        self.touch("addons/vip_modules/vip_test.so")
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("Do not delete", result.stdout)

    def test_current_vip_test_is_still_reported_as_legacy_namespace(self):
        self.touch("addons/metamod/vip_test.vdf")
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("manual migration", result.stdout)

    def test_new_multitest_passes(self):
        self.touch("addons/vip_modules/vip_multitest.so")
        self.touch("addons/metamod/vip_multitest.vdf")
        result = self.run_check()
        self.assertEqual(result.returncode, 0)

    def test_mixed_installation_is_reported_without_mutation(self):
        self.touch("addons/configs/vip/vip_test.ini")
        self.touch("addons/configs/vip/vip_multitest.ini")
        result = self.run_check()
        self.assertEqual(result.returncode, 2)
        self.assertTrue((self.root / "addons/configs/vip/vip_test.ini").exists())

    def test_missing_root_is_an_invocation_error(self):
        result = self.run_check(self.root / "missing")
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
