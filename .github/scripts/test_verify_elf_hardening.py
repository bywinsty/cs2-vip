#!/usr/bin/env python3
"""Unit tests for the ELF GLIBC compatibility gate."""

from __future__ import annotations

import unittest

import verify_elf_hardening as verifier


class ElfCompatibilityTests(unittest.TestCase):
    def test_extracts_glibc_versions_without_matching_glibcxx(self) -> None:
        version_info = """
          Name: GLIBC_2.2.5  Flags: none
          Name: GLIBC_2.28   Flags: none
          Name: GLIBCXX_3.4.32 Flags: none
          Name: GLIBC_PRIVATE Flags: none
        """
        self.assertEqual(
            verifier.required_glibc_versions(version_info),
            {(2, 2, 5), (2, 28)},
        )

    def test_accepts_exact_baseline(self) -> None:
        actual = verifier.validate_glibc_baseline("Name: GLIBC_2.28", (2, 28))
        self.assertEqual(actual, (2, 28))

    def test_rejects_newer_requirement(self) -> None:
        with self.assertRaisesRegex(ValueError, r"GLIBC_2\.38 exceeds supported baseline GLIBC_2\.28"):
            verifier.validate_glibc_baseline("Name: GLIBC_2.38", (2, 28))

    def test_rejects_missing_version_contract(self) -> None:
        with self.assertRaisesRegex(ValueError, "no versioned GLIBC requirements"):
            verifier.validate_glibc_baseline("Name: GLIBC_PRIVATE", (2, 28))

    def test_rejects_malformed_maximum(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid version"):
            verifier.parse_version("2.x")


if __name__ == "__main__":
    unittest.main()
