#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import manifest_contract


ROOT = Path(__file__).resolve().parents[2]


class ManifestContractTests(unittest.TestCase):
    def write_manifest(self, packages):
        path = Path(self.temp.name) / "manifest.json"
        path.write_text(json.dumps({"packages": packages}), encoding="utf-8")
        return path

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.package = {
            "files": ["addons/test.so", "addons/test.vdf"],
            "binary": "addons/test.so",
            "vdf": "addons/test.vdf",
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_contract_counts_are_derived(self):
        path = self.write_manifest({"VIP_Test": self.package, "VIP_Other": self.package | {
            "files": ["addons/other.so", "addons/other.vdf"],
            "binary": "addons/other.so",
            "vdf": "addons/other.vdf",
        }})
        contract = manifest_contract.load_contract(path)
        self.assertEqual(contract["module_count"], 2)
        self.assertEqual(contract["package_file_count"], 4)
        self.assertEqual(contract["release_archive_count"], 4)
        self.assertEqual(contract["report_count"], 2)
        self.assertEqual(contract["combined_archive"], "VIP_All_Modules.tar.gz")
        self.assertEqual(contract["legacy_combined_archive"], "VIP_Modules.tar.gz")

    def test_duplicate_paths_fail(self):
        package = self.package | {"files": ["addons/test.so", "addons/test.so"]}
        with self.assertRaises(ValueError):
            manifest_contract.load_contract(self.write_manifest({"test": package}))

    def test_missing_binary_or_vdf_fails(self):
        package = self.package | {"binary": "addons/missing.so"}
        with self.assertRaises(ValueError):
            manifest_contract.load_contract(self.write_manifest({"test": package}))

    def test_buy_team_weapon_config_is_declared_and_packaged(self):
        manifest_path = ROOT / ".github" / "package-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        package = manifest["packages"]["VIP_BuyTeamWeapon"]
        config_path = "addons/configs/vip/vip_btw.ini"
        package_script = (
            ROOT / "VIP_BuyTeamWeapon" / "source" / "PackageScript"
        ).read_text(encoding="utf-8")
        source_config = (
            ROOT / "VIP_BuyTeamWeapon" / "source" / "configs" / "vip" / "vip_btw.ini"
        )

        self.assertIn(config_path, package["files"])
        self.assertTrue(source_config.is_file())
        self.assertIn("addons', 'configs', 'vip", package_script)
        self.assertIn("configs', 'vip', 'vip_btw.ini", package_script)


if __name__ == "__main__":
    unittest.main()
