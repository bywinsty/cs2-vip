from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("generate_spdx_sbom.py")
VERIFY = Path(__file__).with_name("verify_spdx_subject.py")


class GenerateSpdxSbomTests(unittest.TestCase):
    def test_deterministic_document_describes_archive_and_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "plugin.so").write_bytes(b"ELF-test")
            (package / "config.ini").write_text("enabled=1\n", encoding="utf-8")
            archive = root / "release.zip"
            archive.write_bytes(b"deterministic-archive")
            requirements = root / "requirements.txt"
            requirements.write_text(
                "example-package==1.2.3 \\\n+    --hash=sha256:" + "0" * 64 + "\n",
                encoding="utf-8",
            )
            first = root / "first.spdx.json"
            second = root / "second.spdx.json"
            command = [
                sys.executable,
                str(SCRIPT),
                "--name",
                "test-release",
                "--version",
                "a" * 40,
                "--repository",
                "owner/repository",
                "--archive",
                str(archive),
                "--root",
                str(package),
                "--requirements",
                str(requirements),
                "--git-dependency",
                f"sdk=https://github.com/example/sdk#{'b' * 40}",
            ]
            environment = os.environ.copy()
            environment["SOURCE_DATE_EPOCH"] = "1700000000"
            subprocess.run(command + ["--output", str(first)], check=True, env=environment)
            subprocess.run(command + ["--output", str(second)], check=True, env=environment)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            document = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(document["spdxVersion"], "SPDX-2.3")
            release = next(
                package
                for package in document["packages"]
                if package["SPDXID"] == "SPDXRef-ReleaseArchive"
            )
            expected = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertIn(
                {"algorithm": "SHA256", "checksumValue": expected},
                release["checksums"],
            )
            self.assertEqual(len(document["files"]), 2)
            self.assertEqual(
                {package["name"] for package in document["packages"]},
                {"test-release", "sdk", "example-package"},
            )
            subprocess.run(
                [
                    sys.executable,
                    str(VERIFY),
                    "--archive",
                    str(archive),
                    "--sbom",
                    str(first),
                ],
                check=True,
            )


if __name__ == "__main__":
    unittest.main()
