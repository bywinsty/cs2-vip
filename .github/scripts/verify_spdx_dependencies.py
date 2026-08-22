#!/usr/bin/env python3
"""Verify that an SPDX SBOM exactly matches the canonical dependency policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from dependency_manifest import ALLOWED_RELATIONSHIPS, load_dependency_manifest


CAPABILITY = re.compile(r"(?:^|; )canonical-capability=([^;]+)")


def load_sbom(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read SPDX document: {exc}") from exc
    if not isinstance(value, dict) or value.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("SBOM must be an SPDX-2.3 JSON object")
    return value


def package_capability(package: dict) -> str:
    comment = package.get("comment")
    match = CAPABILITY.search(comment) if isinstance(comment, str) else None
    if not match:
        raise ValueError(f"dependency package lacks canonical capability: {package.get('name')!r}")
    return match.group(1)


def verify(sbom_path: Path, manifest_path: Path) -> None:
    expected = {item["capability"]: item for item in load_dependency_manifest(manifest_path)}
    document = load_sbom(sbom_path)
    packages = document.get("packages")
    relationships = document.get("relationships")
    if not isinstance(packages, list) or not all(isinstance(item, dict) for item in packages):
        raise ValueError("SBOM packages must be an object array")
    if not isinstance(relationships, list) or not all(isinstance(item, dict) for item in relationships):
        raise ValueError("SBOM relationships must be an object array")

    release = [item for item in packages if item.get("SPDXID") == "SPDXRef-ReleaseArchive"]
    if len(release) != 1:
        raise ValueError("SBOM must contain exactly one release package")
    dependencies = [item for item in packages if item.get("SPDXID") != "SPDXRef-ReleaseArchive"]
    ids = [item.get("SPDXID") for item in dependencies]
    names = [item.get("name") for item in dependencies]
    if not all(isinstance(item, str) and item for item in ids):
        raise ValueError("SBOM dependency IDs must be non-empty strings")
    if not all(isinstance(item, str) and item for item in names):
        raise ValueError("SBOM dependency names must be non-empty strings")
    if len(ids) != len(set(ids)) or len(names) != len(set(names)):
        raise ValueError("SBOM contains duplicate dependency IDs or names")

    actual: dict[str, dict] = {}
    for package in dependencies:
        capability = package_capability(package)
        if capability in actual:
            raise ValueError(f"SBOM contains duplicate dependency capability: {capability}")
        if capability not in expected:
            raise ValueError(f"SBOM contains unknown dependency capability: {capability}")
        actual[capability] = package
    missing = set(expected) - set(actual)
    if missing:
        raise ValueError(f"SBOM is missing dependency capabilities: {sorted(missing)}")

    for capability, manifest in expected.items():
        package = actual[capability]
        if package.get("name") != manifest["name"]:
            raise ValueError(f"dependency {capability} name mismatch")
        if package.get("versionInfo") != manifest["version"]:
            raise ValueError(f"dependency {capability} version mismatch")
        if package.get("downloadLocation") != manifest["download_location"]:
            raise ValueError(f"dependency {capability} download location mismatch")
        expected_checksum = manifest.get("artifact_sha256")
        checksums = package.get("checksums", [])
        actual_sha256 = {
            item.get("checksumValue") for item in checksums
            if isinstance(item, dict) and item.get("algorithm") == "SHA256"
        }
        if expected_checksum and actual_sha256 != {expected_checksum}:
            raise ValueError(f"dependency {capability} artifact checksum mismatch")
        if not expected_checksum and actual_sha256:
            raise ValueError(f"dependency {capability} has an unexpected artifact checksum")

    id_to_capability = {package["SPDXID"]: capability for capability, package in actual.items()}
    actual_relationships = {capability: set() for capability in expected}
    for relationship in relationships:
        kind = relationship.get("relationshipType")
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        if kind in ALLOWED_RELATIONSHIPS:
            if target != "SPDXRef-ReleaseArchive" or source not in id_to_capability:
                raise ValueError("dependency relationship direction or endpoint is invalid")
            actual_relationships[id_to_capability[source]].add(kind)
        elif (source == "SPDXRef-ReleaseArchive" and target in id_to_capability) or source in id_to_capability:
            if kind not in {"CONTAINS"}:
                raise ValueError(f"unsupported dependency relationship type: {kind}")

    for capability, manifest in expected.items():
        if actual_relationships[capability] != set(manifest["relationships"]):
            raise ValueError(f"dependency {capability} relationship classification mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify(args.sbom, args.manifest)
    except ValueError as exc:
        raise SystemExit(f"SPDX dependency verification failed: {exc}") from exc
    print("SPDX dependency manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
