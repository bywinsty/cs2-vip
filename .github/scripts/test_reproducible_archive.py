#!/usr/bin/env python3
"""Tests for deterministic archive metadata and ordering."""

from pathlib import Path
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("create_reproducible_archive.py")


class ReproducibleArchiveTests(unittest.TestCase):
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
                    subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), "--output", str(output), "--format", kind, "--prefix", "addons"], check=True, env=env)
                digests = [hashlib.sha256(path.read_bytes()).digest() for path in outputs]
                self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
