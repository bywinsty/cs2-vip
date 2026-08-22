#!/usr/bin/env python3
"""Tests for deterministic archive metadata and ordering."""

from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).with_name("create_reproducible_archive.py")


class ReproducibleArchiveTests(unittest.TestCase):
    def run_archive(self, root, output, kind="zip", prefix="addons", *, check=True):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--root",
                str(root),
                "--output",
                str(output),
                "--format",
                kind,
                "--prefix",
                prefix,
            ],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"},
        )

    def test_zip_and_tar_are_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            (root / "z.txt").write_text("z\n", encoding="utf-8", newline="\n")
            (root / "a.txt").write_text("a\n", encoding="utf-8", newline="\n")
            env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}
            for kind, suffix in (("zip", ".zip"), ("tar.gz", ".tar.gz")):
                outputs = [Path(directory) / f"{index}{suffix}" for index in range(2)]
                for output in outputs:
                    self.run_archive(root, output, kind)
                digests = [hashlib.sha256(path.read_bytes()).digest() for path in outputs]
                self.assertEqual(digests[0], digests[1])

    def test_symlink_to_external_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            outside = base / "secret.txt"
            outside.write_text("outside-secret", encoding="utf-8")
            try:
                (root / "leak.txt").symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            result = self.run_archive(root, base / "release.zip", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("links and junctions are forbidden", result.stdout)

    def test_symlink_directory_and_broken_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside"
            outside.mkdir()
            for link_target, name in ((outside, "dir-link"), (base / "missing", "broken-link")):
                root = base / f"root-{name}"
                root.mkdir()
                try:
                    (root / name).symlink_to(link_target, target_is_directory=link_target.is_dir())
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlinks unavailable: {exc}")
                result = self.run_archive(root, base / f"{name}.zip", check=False)
                self.assertNotEqual(result.returncode, 0)

    def test_output_inside_root_is_rejected_without_clobbering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            nested_parent = root / "new-directory"
            output = nested_parent / "release.zip"
            result = self.run_archive(root, output, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse(nested_parent.exists())

    def test_unsafe_prefixes_are_rejected_for_both_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            for kind, suffix in (("zip", ".zip"), ("tar.gz", ".tar.gz")):
                for index, prefix in enumerate(
                    ("/absolute", "//server/share", "../escape", ".", "a/./b", "a/../b", "a//b", "a\\b", "C:/drive")
                ):
                    result = self.run_archive(
                        root,
                        base / f"unsafe-{kind}-{index}{suffix}",
                        kind,
                        prefix,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, (kind, prefix))

    def test_output_symlink_is_rejected_for_both_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            for kind, suffix in (("zip", ".zip"), ("tar.gz", ".tar.gz")):
                target = base / f"target{suffix}"
                target.write_bytes(b"do-not-clobber")
                output = base / f"release{suffix}"
                try:
                    output.symlink_to(target)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlinks unavailable: {exc}")
                result = self.run_archive(root, output, kind, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_bytes(), b"do-not-clobber")

    def test_output_is_replaced_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "root"
            root.mkdir()
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            output = base / "release.zip"
            output.write_bytes(b"old")
            self.run_archive(root, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read("addons/payload.txt"), b"payload")


if __name__ == "__main__":
    unittest.main()
