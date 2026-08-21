#!/usr/bin/env python3
"""Verify that an SPDX document describes the exact release archive bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    args = parser.parse_args()
    document = json.loads(args.sbom.read_text(encoding="utf-8"))
    described = set(document.get("documentDescribes", []))
    packages = {
        package.get("SPDXID"): package for package in document.get("packages", [])
    }
    matches = [
        package
        for identifier, package in packages.items()
        if identifier in described and package.get("packageFileName") == args.archive.name
    ]
    if len(matches) != 1:
        raise SystemExit("SBOM must describe exactly one matching release archive")
    expected = next(
        (
            item.get("checksumValue", "").lower()
            for item in matches[0].get("checksums", [])
            if item.get("algorithm") == "SHA256"
        ),
        "",
    )
    actual = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if expected != actual:
        raise SystemExit(f"SBOM subject digest mismatch: expected={expected}, actual={actual}")
    print(f"SPDX subject verified: {args.archive.name} sha256={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
