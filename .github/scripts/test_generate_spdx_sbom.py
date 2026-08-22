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
VERIFY_DEPENDENCIES = Path(__file__).with_name("verify_spdx_dependencies.py")
MANIFEST = SCRIPT.parents[1] / "dependency-manifest.json"


class GenerateSpdxSbomTests(unittest.TestCase):
    def generate(self, package: Path, archive: Path, output: Path) -> None:
        subprocess.run(
            [
                sys.executable, str(SCRIPT), "--name", "test-release",
                "--version", "a" * 40, "--repository", "owner/repository",
                "--archive", str(archive), "--root", str(package),
                "--dependency-manifest", str(MANIFEST), "--output", str(output),
            ],
            check=True,
            env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
        )

    def test_deterministic_document_describes_archive_and_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "plugin.so").write_bytes(b"ELF-test")
            (package / "config.ini").write_text("enabled=1\n", encoding="utf-8")
            archive = root / "release.zip"
            archive.write_bytes(b"deterministic-archive")
            first = root / "first.spdx.json"
            second = root / "second.spdx.json"
            self.generate(package, archive, first)
            self.generate(package, archive, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            document = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(document["spdxVersion"], "SPDX-2.3")
            release = next(
                item for item in document["packages"]
                if item["SPDXID"] == "SPDXRef-ReleaseArchive"
            )
            expected_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertIn(
                {"algorithm": "SHA256", "checksumValue": expected_digest},
                release["checksums"],
            )
            self.assertEqual(len(document["files"]), 2)
            manifest_names = {
                item["name"]
                for item in json.loads(MANIFEST.read_text(encoding="utf-8"))["dependencies"]
            }
            self.assertEqual(
                {item["name"] for item in document["packages"]},
                {"test-release", *manifest_names},
            )
            dependency_relationships = [
                item for item in document["relationships"]
                if item["relationshipType"].endswith("_OF")
            ]
            self.assertTrue(dependency_relationships)
            self.assertTrue(all(
                item["relatedSpdxElement"] == "SPDXRef-ReleaseArchive"
                and item["spdxElementId"] != "SPDXRef-ReleaseArchive"
                for item in dependency_relationships
            ))
            subprocess.run(
                [sys.executable, str(VERIFY), "--archive", str(archive), "--sbom", str(first)],
                check=True,
            )
            subprocess.run(
                [sys.executable, str(VERIFY_DEPENDENCIES), "--sbom", str(first),
                 "--manifest", str(MANIFEST)],
                check=True,
            )

    def test_dependency_verifier_rejects_unknown_missing_duplicate_and_misclassified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "plugin.so").write_bytes(b"ELF-test")
            archive = root / "release.zip"
            archive.write_bytes(b"archive")
            valid = root / "valid.spdx.json"
            self.generate(package, archive, valid)
            base = json.loads(valid.read_text(encoding="utf-8"))

            cases: dict[str, dict] = {}
            unknown = json.loads(json.dumps(base))
            extra = json.loads(json.dumps(unknown["packages"][1]))
            extra["SPDXID"] = "SPDXRef-Dependency-unknown"
            extra["name"] = "unknown"
            extra["comment"] = "canonical-capability=unknown; required=true; purpose=test"
            unknown["packages"].append(extra)
            cases["unknown"] = unknown

            missing = json.loads(json.dumps(base))
            removed = missing["packages"].pop(1)
            missing["relationships"] = [
                item for item in missing["relationships"]
                if item.get("spdxElementId") != removed["SPDXID"]
            ]
            cases["missing"] = missing

            duplicate = json.loads(json.dumps(base))
            duplicate["packages"].append(json.loads(json.dumps(duplicate["packages"][1])))
            cases["duplicate"] = duplicate

            misclassified = json.loads(json.dumps(base))
            relation = next(
                item for item in misclassified["relationships"]
                if item.get("relationshipType") == "BUILD_TOOL_OF"
            )
            relation["relationshipType"] = "RUNTIME_DEPENDENCY_OF"
            cases["misclassified"] = misclassified

            for name, document in cases.items():
                sbom = root / f"{name}.spdx.json"
                sbom.write_text(json.dumps(document), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(VERIFY_DEPENDENCIES), "--sbom", str(sbom),
                     "--manifest", str(MANIFEST)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("SPDX dependency verification failed", result.stdout)

    def test_manifest_rejects_unknown_missing_duplicate_and_misclassified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "plugin.so").write_bytes(b"plugin")
            archive = root / "release.zip"
            archive.write_bytes(b"archive")
            base = json.loads(MANIFEST.read_text(encoding="utf-8"))
            cases: dict[str, dict] = {}
            unknown = json.loads(json.dumps(base))
            unknown["dependencies"].append({**unknown["dependencies"][0], "capability": "unknown"})
            cases["unknown"] = unknown
            missing = json.loads(json.dumps(base))
            missing["dependencies"].pop()
            cases["missing"] = missing
            duplicate = json.loads(json.dumps(base))
            duplicate["dependencies"].append(json.loads(json.dumps(duplicate["dependencies"][0])))
            cases["duplicate"] = duplicate
            misclassified = json.loads(json.dumps(base))
            misclassified["dependencies"][0]["relationships"] = ["RUNTIME_DEPENDENCY_OF"]
            cases["misclassified"] = misclassified

            for name, manifest in cases.items():
                manifest_path = root / f"{name}.json"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--name", "test", "--version", "a" * 40,
                     "--repository", "owner/repo", "--archive", str(archive),
                     "--root", str(package), "--dependency-manifest", str(manifest_path),
                     "--output", str(root / f"{name}.spdx.json")],
                    env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                self.assertNotEqual(result.returncode, 0, name)
                self.assertIn("SBOM generation failed", result.stdout)

    def test_verifier_rejects_malformed_or_ambiguous_release_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "release.zip"
            archive.write_bytes(b"release")
            cases = (
                "not-json",
                json.dumps({"spdxVersion": "SPDX-2.3", "documentDescribes": [], "packages": []}),
                json.dumps({
                    "spdxVersion": "SPDX-2.3",
                    "documentDescribes": ["SPDXRef-ReleaseArchive"],
                    "packages": [{
                        "SPDXID": "SPDXRef-ReleaseArchive",
                        "packageFileName": "release.zip",
                        "checksums": [{"algorithm": "SHA256", "checksumValue": "bad"}],
                    }],
                }),
            )
            for index, content in enumerate(cases):
                sbom = root / f"invalid-{index}.json"
                sbom.write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(VERIFY), "--archive", str(archive), "--sbom", str(sbom)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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
                [sys.executable, str(SCRIPT), "--name", "test", "--version", "a" * 40,
                 "--repository", "owner/repo", "--archive", str(archive), "--root", str(package),
                 "--dependency-manifest", str(MANIFEST), "--output", str(base / "out.json")],
                env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
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
                [sys.executable, str(SCRIPT), "--name", "test", "--version", "a" * 40,
                 "--repository", "owner/repo", "--archive", str(archive), "--root", str(package),
                 "--dependency-manifest", str(MANIFEST), "--output", str(output)],
                env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.parent.exists())


if __name__ == "__main__":
    unittest.main()
