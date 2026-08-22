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

    def test_verifier_rejects_malformed_or_ambiguous_release_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "release.zip"
            archive.write_bytes(b"release")
            cases = (
                "not-json",
                json.dumps({"spdxVersion": "SPDX-2.3", "documentDescribes": [], "packages": []}),
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "documentDescribes": ["SPDXRef-ReleaseArchive"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-ReleaseArchive",
                                "packageFileName": "release.zip",
                                "checksums": [{"algorithm": "SHA256", "checksumValue": "bad"}],
                            }
                        ],
                    }
                ),
            )
            for index, content in enumerate(cases):
                sbom = root / f"invalid-{index}.json"
                sbom.write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(VERIFY), "--archive", str(archive), "--sbom", str(sbom)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SPDX subject verification failed", result.stdout)

    def test_sbom_generation_rejects_symlinked_package_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            package = base / "package"
            package.mkdir()
            outside = base / "outside.bin"
            outside.write_bytes(b"secret")
            try:
                (package / "leak.bin").symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            archive = base / "release.zip"
            archive.write_bytes(b"archive")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--name",
                    "test",
                    "--version",
                    "a" * 40,
                    "--repository",
                    "owner/repo",
                    "--archive",
                    str(archive),
                    "--root",
                    str(package),
                    "--output",
                    str(base / "out.json"),
                ],
                env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("links and junctions are forbidden", result.stdout)

    def test_sbom_output_inside_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            package = base / "package"
            package.mkdir()
            (package / "plugin.so").write_bytes(b"plugin")
            archive = base / "release.zip"
            archive.write_bytes(b"archive")
            output = package / "new" / "release.spdx.json"
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "--name", "test", "--version", "a" * 40,
                    "--repository", "owner/repo", "--archive", str(archive), "--root", str(package),
                    "--output", str(output),
                ],
                env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.parent.exists())


if __name__ == "__main__":
    unittest.main()
