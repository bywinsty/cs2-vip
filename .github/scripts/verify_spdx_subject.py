#!/usr/bin/env python3
"""Verify that an SPDX document describes the exact release archive bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


def load_release_package(sbom: Path, archive_name: str) -> dict:
    try:
        document = json.loads(sbom.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid SPDX JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("SBOM must be an SPDX-2.3 JSON object")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT" or document.get("dataLicense") != "CC0-1.0":
        raise ValueError("SBOM document identity or data license is invalid")
    if not isinstance(document.get("name"), str) or not document["name"]:
        raise ValueError("SBOM document name is required")
    if not isinstance(document.get("documentNamespace"), str) or not document["documentNamespace"]:
        raise ValueError("SBOM document namespace is required")
    if not isinstance(document.get("creationInfo"), dict):
        raise ValueError("SBOM creationInfo object is required")
    described = document.get("documentDescribes")
    packages = document.get("packages")
    if not isinstance(described, list) or not all(isinstance(item, str) for item in described):
        raise ValueError("SBOM documentDescribes must be a string array")
    if not isinstance(packages, list) or not all(isinstance(item, dict) for item in packages):
        raise ValueError("SBOM packages must be an object array")
    matches = [
        package
        for package in packages
        if package.get("SPDXID") == "SPDXRef-ReleaseArchive"
    ]
    if len(matches) != 1 or described.count("SPDXRef-ReleaseArchive") != 1:
        raise ValueError("SBOM must describe exactly one SPDXRef-ReleaseArchive")
    if matches[0].get("packageFileName") != archive_name:
        raise ValueError("SPDX release subject name does not match the archive name")
    if not isinstance(matches[0].get("name"), str) or not matches[0]["name"]:
        raise ValueError("SPDX release subject package name is required")
    if not re.fullmatch(r"[0-9a-f]{40}", str(matches[0].get("versionInfo", ""))):
        raise ValueError("SPDX release subject versionInfo must be a full lowercase commit SHA")
    return matches[0]


def release_sha256(package: dict) -> str:
    checksums = package.get("checksums")
    if not isinstance(checksums, list):
        raise ValueError("release package checksums must be an object array")
    values = [
        item.get("checksumValue", "").lower()
        for item in checksums
        if isinstance(item, dict) and item.get("algorithm") == "SHA256"
    ]
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
        raise ValueError("release package must contain exactly one valid SHA256 checksum")
    return values[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    args = parser.parse_args()
    try:
        package = load_release_package(args.sbom, args.archive.name)
        expected = release_sha256(package)
    except ValueError as exc:
        raise SystemExit(f"SPDX subject verification failed: {exc}") from exc
    try:
        actual = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    except OSError as exc:
        raise SystemExit(f"SPDX subject verification failed: cannot read archive: {exc}") from exc
    if expected != actual:
        raise SystemExit(f"SBOM subject digest mismatch: expected={expected}, actual={actual}")
    print(f"SPDX subject verified: {args.archive.name} sha256={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
