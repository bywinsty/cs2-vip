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


def requirement_entries(path: Path | None) -> list[tuple[str, str]]:
    if path is None:
        return []
    logical: list[str] = []
    pending = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        pending += (" " if pending else "") + line.removesuffix("\\").strip()
        if line.endswith("\\"):
            continue
        logical.append(pending)
        pending = ""
    if pending:
        logical.append(pending)
    entries: list[tuple[str, str]] = []
    for line in logical:
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", line)
        if match:
            entries.append((match.group(1), match.group(2)))
    return sorted(set(entries), key=lambda item: item[0].lower())


def dependency_package(name: str, version: str, location: str) -> dict:
    return {
        "SPDXID": spdx_id("Dependency", f"{name}-{version}-{location}"),
        "name": name,
        "versionInfo": version,
        "downloadLocation": location,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }


def parse_git_dependency(value: str) -> tuple[str, str, str]:
    try:
        name, reference = value.split("=", 1)
        repository, commit = reference.rsplit("#", 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected NAME=REPOSITORY#COMMIT") from exc
    if not name or not repository or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise argparse.ArgumentTypeError("git dependency must use a full 40-character commit SHA")
    return name, repository.rstrip("/"), commit.lower()


def build_document(args: argparse.Namespace) -> dict:
    archive = args.archive.resolve()
    root = args.root.resolve()
    if not archive.is_file() or not root.is_dir():
        raise ValueError("archive and package root must exist")

    files = sorted(path for path in root.rglob("*") if path.is_file())
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

    dependencies: list[dict] = []
    for name, repository, commit in args.git_dependency:
        dependencies.append(dependency_package(name, commit, f"{repository}/tree/{commit}"))
    for name, version in requirement_entries(args.requirements):
        normalized = name.replace("_", "-").lower()
        dependencies.append(
            dependency_package(
                name,
                version,
                f"https://pypi.org/project/{normalized}/{version}/",
            )
        )
    dependencies.sort(key=lambda item: (item["name"].lower(), item["versionInfo"]))
    for dependency in dependencies:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-ReleaseArchive",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dependency["SPDXID"],
            }
        )

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
    parser.add_argument("--requirements", type=Path)
    parser.add_argument(
        "--git-dependency",
        action="append",
        default=[],
        type=parse_git_dependency,
        metavar="NAME=REPOSITORY#COMMIT",
    )
    args = parser.parse_args()
    try:
        document = build_document(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"SBOM generation failed: {exc}")
    print(f"SPDX SBOM written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
