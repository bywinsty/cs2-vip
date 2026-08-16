#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import manifest_contract


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
        self.assertEqual(contract["release_archive_count"], 3)
        self.assertEqual(contract["report_count"], 2)

    def test_duplicate_paths_fail(self):
        package = self.package | {"files": ["addons/test.so", "addons/test.so"]}
        with self.assertRaises(ValueError):
            manifest_contract.load_contract(self.write_manifest({"test": package}))

    def test_missing_binary_or_vdf_fails(self):
        package = self.package | {"binary": "addons/missing.so"}
        with self.assertRaises(ValueError):
            manifest_contract.load_contract(self.write_manifest({"test": package}))


if __name__ == "__main__":
    unittest.main()
