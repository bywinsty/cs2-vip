#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 JSON SBOM for a release archive."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re

from dependency_manifest import load_dependency_manifest
from safe_file_tree import UnsafeTreeError, collect_regular_files, is_link_like, validate_archive_output


def checksum(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spdx_id(prefix: str, value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-.") or "item"
    suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{prefix}-{safe[:48]}-{suffix}"


def created_timestamp() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None or not raw.isdigit():
        raise ValueError("SOURCE_DATE_EPOCH must be set to a non-negative integer")
    return dt.datetime.fromtimestamp(int(raw), tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dependency_package(dependency: dict) -> dict:
    package = {
        "SPDXID": spdx_id("Dependency", dependency["capability"]),
        "name": dependency["name"],
        "versionInfo": dependency["version"],
        "downloadLocation": dependency["download_location"],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "comment": (
            f"canonical-capability={dependency['capability']}; "
            f"required={str(dependency['required']).lower()}; purpose={dependency['purpose']}"
        ),
    }
    if dependency.get("artifact_sha256"):
        package["checksums"] = [{
            "algorithm": "SHA256",
            "checksumValue": dependency["artifact_sha256"],
        }]
    if dependency.get("version_evidence"):
        package["attributionTexts"] = [
            f"Exact deployed version evidence: {dependency['version_evidence']}"
        ]
    return package


def build_document(args: argparse.Namespace) -> dict:
    archive = args.archive.resolve()
    if not archive.is_file() or is_link_like(archive):
        raise ValueError("archive and package root must exist")
    root, files = collect_regular_files(args.root)
    if not files:
        raise ValueError("package root contains no files")
    spdx_files: list[dict] = []
    sha1_values: list[str] = []
    relationships: list[dict] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-ReleaseArchive",
        }
    ]
    for path in files:
        relative = path.relative_to(root).as_posix()
        sha1 = checksum(path, "sha1")
        sha256 = checksum(path, "sha256")
        sha1_values.append(sha1)
        file_id = spdx_id("File", relative)
        spdx_files.append(
            {
                "fileName": f"./{relative}",
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1},
                    {"algorithm": "SHA256", "checksumValue": sha256},
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "fileTypes": ["BINARY" if path.suffix == ".so" else "OTHER"],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-ReleaseArchive",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    verification_input = "".join(sorted(sha1_values)).encode("ascii")
    archive_sha256 = checksum(archive, "sha256")
    release_package = {
        "name": args.name,
        "SPDXID": "SPDXRef-ReleaseArchive",
        "versionInfo": args.version,
        "packageFileName": archive.name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "packageVerificationCode": {
            "packageVerificationCodeValue": hashlib.sha1(verification_input).hexdigest()
        },
        "checksums": [
            {"algorithm": "SHA1", "checksumValue": checksum(archive, "sha1")},
            {"algorithm": "SHA256", "checksumValue": archive_sha256},
        ],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "hasFiles": [entry["SPDXID"] for entry in spdx_files],
    }

    manifest_dependencies = load_dependency_manifest(args.dependency_manifest)
    dependencies = [dependency_package(item) for item in manifest_dependencies]
    packages_by_capability = {
        item["capability"]: package
        for item, package in zip(manifest_dependencies, dependencies, strict=True)
    }
    for dependency in manifest_dependencies:
        for relationship in dependency["relationships"]:
            relationships.append({
                "spdxElementId": packages_by_capability[dependency["capability"]]["SPDXID"],
                "relationshipType": relationship,
                "relatedSpdxElement": "SPDXRef-ReleaseArchive",
            })

    namespace_repository = args.repository.strip("/")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{args.name}-{args.version}",
        "documentNamespace": (
            f"https://github.com/{namespace_repository}/spdx/{args.version}/{archive_sha256}"
        ),
        "creationInfo": {
            "created": created_timestamp(),
            "creators": ["Tool: cs2-vip-generate-spdx-sbom"],
        },
        "documentDescribes": ["SPDXRef-ReleaseArchive"],
        "packages": [release_package, *dependencies],
        "files": spdx_files,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--dependency-manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        args.output = validate_archive_output(args.root.resolve(strict=True), args.output)
        document = build_document(args)
        args.output.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, ValueError, UnsafeTreeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"SBOM generation failed: {exc}")
    print(f"SPDX SBOM written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
